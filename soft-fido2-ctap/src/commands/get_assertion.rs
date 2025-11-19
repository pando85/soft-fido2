//! authenticatorGetAssertion command
//!
//! Authenticates a user with an existing credential.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetAssertion>

use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::cbor::{MapBuilder, MapParser};
use crate::extensions::GetAssertionExtensions;
use crate::status::{Result, StatusCode};
use crate::types::PublicKeyCredentialDescriptor;
use crate::{UpResult, UvResult};

use soft_fido2_crypto::ecdsa;

use sha2::{Digest, Sha256};

/// GetAssertion request parameter keys
mod req_keys {
    pub const RP_ID: i32 = 0x01;
    pub const CLIENT_DATA_HASH: i32 = 0x02;
    pub const ALLOW_LIST: i32 = 0x03;
    pub const EXTENSIONS: i32 = 0x04;
    pub const OPTIONS: i32 = 0x05;
    pub const PIN_UV_AUTH_PARAM: i32 = 0x06;
    pub const PIN_UV_AUTH_PROTOCOL: i32 = 0x07;
}

/// GetAssertion response keys
#[allow(dead_code)]
mod resp_keys {
    pub const CREDENTIAL: i32 = 0x01;
    pub const AUTH_DATA: i32 = 0x02;
    pub const SIGNATURE: i32 = 0x03;
    pub const USER: i32 = 0x04;
    pub const NUMBER_OF_CREDENTIALS: i32 = 0x05;
    pub const USER_SELECTED: i32 = 0x06;
    pub const LARGE_BLOB_KEY: i32 = 0x07;
}

/// Options in the request
#[derive(Debug, Default)]
struct GetAssertionOptions {
    up: bool,
    uv: bool,
}

/// Handle authenticatorGetAssertion command
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;

    // Parse required parameters
    let rp_id: String = parser.get(req_keys::RP_ID)?;
    let client_data_hash: Vec<u8> = parser.get_bytes(req_keys::CLIENT_DATA_HASH)?;
    if client_data_hash.len() != 32 {
        return Err(StatusCode::InvalidParameter);
    }

    // Parse allowList - manual parsing required to handle CBOR byte strings correctly
    // (automatic serde deserialization fails on CBOR Bytes type for credential IDs)
    let allow_list: Option<Vec<PublicKeyCredentialDescriptor>> = if let Some(raw_allow_list) =
        parser.get_raw(req_keys::ALLOW_LIST)
    {
        match raw_allow_list {
            crate::cbor::Value::Array(arr) => {
                let mut descriptors = Vec::new();
                for elem in arr.iter() {
                    if let crate::cbor::Value::Map(map) = elem {
                        let mut cred_type = None;
                        let mut id = None;
                        let mut transports = None;

                        for (key, value) in map {
                            if let crate::cbor::Value::Text(key_str) = key {
                                match key_str.as_str() {
                                    "type" => {
                                        if let crate::cbor::Value::Text(t) = value {
                                            cred_type = Some(t.clone());
                                        }
                                    }
                                    "id" => {
                                        // Handle CBOR byte string (correct) or array (legacy fallback)
                                        match value {
                                            crate::cbor::Value::Bytes(bytes) => {
                                                id = Some(bytes.clone());
                                            }
                                            crate::cbor::Value::Array(arr) => {
                                                let bytes: Vec<u8> = arr
                                                    .iter()
                                                    .filter_map(|v| {
                                                        if let crate::cbor::Value::Integer(i) = v {
                                                            let i128_val: i128 = *i;
                                                            if (0..=255).contains(&i128_val) {
                                                                Some(i128_val as u8)
                                                            } else {
                                                                None
                                                            }
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                    .collect();
                                                id = Some(bytes);
                                            }
                                            _ => return Err(StatusCode::InvalidCbor),
                                        }
                                    }
                                    "transports" => {
                                        if let crate::cbor::Value::Array(trans_arr) = value {
                                            let trans: Vec<String> = trans_arr
                                                .iter()
                                                .filter_map(|v| {
                                                    if let crate::cbor::Value::Text(s) = v {
                                                        Some(s.clone())
                                                    } else {
                                                        None
                                                    }
                                                })
                                                .collect();
                                            transports = Some(trans);
                                        }
                                    }
                                    _ => {} // Ignore unknown keys
                                }
                            }
                        }

                        if let (Some(cred_type), Some(id)) = (cred_type, id) {
                            descriptors.push(PublicKeyCredentialDescriptor {
                                cred_type,
                                id,
                                transports,
                            });
                        } else {
                            return Err(StatusCode::InvalidCbor);
                        }
                    } else {
                        return Err(StatusCode::InvalidCbor);
                    }
                }
                Some(descriptors)
            }
            _ => return Err(StatusCode::InvalidCbor),
        }
    } else {
        None
    };

    let pin_uv_auth_param: Option<Vec<u8>> =
        if parser.get_raw(req_keys::PIN_UV_AUTH_PARAM).is_some() {
            Some(parser.get_bytes(req_keys::PIN_UV_AUTH_PARAM)?)
        } else {
            None
        };
    let pin_uv_auth_protocol: Option<u8> = parser.get_opt(req_keys::PIN_UV_AUTH_PROTOCOL)?;

    // Parse options
    let options = parse_options(&parser)?;

    // Parse extensions
    let extensions =
        if let Some(ext_value) = parser.get_opt::<crate::cbor::Value>(req_keys::EXTENSIONS)? {
            GetAssertionExtensions::from_cbor(&ext_value)?
        } else {
            GetAssertionExtensions::new()
        };

    // 3. Verify PIN/UV auth if present
    if let Some(_pin_auth) = &pin_uv_auth_param {
        let _protocol = pin_uv_auth_protocol.ok_or(StatusCode::MissingParameter)?;
        // TODO: Implement PIN token verification
        if !auth.is_pin_set() {
            return Err(StatusCode::PinNotSet);
        }
    }

    // 4. Find matching credentials
    let mut credentials = if let Some(ref allow_list) = allow_list {
        // If allow_list is provided, filter by it
        let mut creds = Vec::new();
        for desc in allow_list {
            // First try to find in storage
            if let Ok(cred) = auth.callbacks().get_credential(&desc.id)
                && cred.rp_id == rp_id
            {
                creds.push(cred);
                continue;
            }

            // If not found, try unwrapping (for non-resident credentials)
            if let Ok((private_key, cred_rp_id, algorithm)) = auth.unwrap_credential(&desc.id)
                && cred_rp_id == rp_id
            {
                // Create a temporary credential from unwrapped data
                let cred = crate::types::Credential {
                    id: desc.id.clone(),
                    rp_id: cred_rp_id,
                    rp_name: None,
                    user_id: Vec::new(),     // Not stored in wrapped cred
                    user_name: None,         // Not stored in wrapped cred
                    user_display_name: None, // Not stored in wrapped cred
                    private_key,
                    algorithm,
                    sign_count: 0,       // Wrapped creds don't track sign count
                    created: 0,          // Not tracked
                    discoverable: false, // Non-resident
                    cred_protect: 0,     // Not tracked
                };
                creds.push(cred);
            }
        }
        creds
    } else {
        // No allow_list, search all credentials for this RP
        auth.callbacks().read_credentials(&rp_id, None)?
    };

    if credentials.is_empty() {
        return Err(StatusCode::NoCredentials);
    }

    // 5. If multiple credentials, let user select
    let selected_cred = if credentials.len() > 1 {
        let user_names: Vec<String> = credentials
            .iter()
            .map(|c| c.user_name.clone().unwrap_or_else(|| "Unknown".to_string()))
            .collect();

        let index = auth.callbacks().select_credential(&rp_id, &user_names)?;

        if index >= credentials.len() {
            return Err(StatusCode::InvalidParameter);
        }

        credentials.swap_remove(index)
    } else {
        credentials.pop().unwrap()
    };

    // 6. Request user presence if required
    let mut up_performed = false;
    if options.up {
        let info = format!("Authenticate with {}", rp_id);
        match auth
            .callbacks()
            .request_up(&info, selected_cred.user_name.as_deref(), &rp_id)?
        {
            UpResult::Accepted => up_performed = true,
            UpResult::Denied => return Err(StatusCode::OperationDenied),
            UpResult::Timeout => return Err(StatusCode::UserActionTimeout),
        }
    }

    // 7. Request user verification if required
    let mut uv_performed = false;
    if options.uv {
        let info = format!("Verify for {}", rp_id);
        match auth
            .callbacks()
            .request_uv(&info, selected_cred.user_name.as_deref(), &rp_id)?
        {
            UvResult::Accepted => uv_performed = true,
            UvResult::AcceptedWithUp => {
                uv_performed = true;
                up_performed = true;
            }
            UvResult::Denied => return Err(StatusCode::OperationDenied),
            UvResult::Timeout => return Err(StatusCode::UserActionTimeout),
        }
    }

    // 8. Increment sign count
    let new_sign_count = selected_cred.sign_count + 1;

    // Only update stored credentials (not wrapped ones)
    if selected_cred.discoverable {
        let mut updated_cred = selected_cred.clone();
        updated_cred.sign_count = new_sign_count;
        auth.callbacks().update_credential(&updated_cred)?;
    }
    // Note: Wrapped credentials (non-resident) don't persist sign count

    // 9. Build extension outputs
    let extension_outputs = extensions.build_outputs();

    // 10. Build authenticator data
    let auth_data = build_authenticator_data(
        &rp_id,
        up_performed,
        uv_performed,
        new_sign_count,
        extension_outputs.as_ref(),
    )?;

    // 11. Generate signature
    let sig_data = [&auth_data[..], &client_data_hash[..]].concat();

    // Convert private key Vec to array
    if selected_cred.private_key.len() != 32 {
        return Err(StatusCode::InvalidCredential);
    }
    let mut priv_key_array = [0u8; 32];
    priv_key_array.copy_from_slice(&selected_cred.private_key);

    let signature = ecdsa::sign(&priv_key_array, &sig_data)?;

    // 12. Build credential descriptor
    let credential_desc = PublicKeyCredentialDescriptor {
        cred_type: "public-key".to_string(),
        id: selected_cred.id.clone(),
        transports: None,
    };

    // 13. Build response
    let mut builder = MapBuilder::new()
        .insert(resp_keys::CREDENTIAL, credential_desc)?
        .insert_bytes(resp_keys::AUTH_DATA, &auth_data)? // Must be CBOR bytes, not array!
        .insert_bytes(resp_keys::SIGNATURE, &signature)?; // Must be CBOR bytes, not array!

    // Add user info if credential was discoverable
    if selected_cred.discoverable {
        let user = crate::types::User {
            id: selected_cred.user_id.clone(),
            name: selected_cred.user_name.clone(),
            display_name: selected_cred.user_display_name.clone(),
        };
        builder = builder.insert(resp_keys::USER, user)?;
    }

    builder.build()
}

/// Parse options from the request
fn parse_options(parser: &MapParser) -> Result<GetAssertionOptions> {
    let opts_map: Option<crate::cbor::Value> = parser.get_opt(req_keys::OPTIONS)?;

    let mut options = GetAssertionOptions {
        up: true, // Default to true
        uv: false,
    };

    if let Some(crate::cbor::Value::Map(opts)) = opts_map {
        for (k, v) in opts {
            if let (crate::cbor::Value::Text(key), crate::cbor::Value::Bool(val)) = (k, v) {
                match key.as_str() {
                    "up" => options.up = val,
                    "uv" => options.uv = val,
                    _ => {} // Ignore unknown options
                }
            }
        }
    }

    Ok(options)
}

/// Build authenticator data for assertion
///
/// Format: rpIdHash (32) || flags (1) || signCount (4) || extensions (optional)
fn build_authenticator_data(
    rp_id: &str,
    up: bool,
    uv: bool,
    sign_count: u32,
    extensions: Option<&crate::cbor::Value>,
) -> Result<Vec<u8>> {
    let mut auth_data = Vec::new();

    // RP ID hash (32 bytes)
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    auth_data.extend_from_slice(&hasher.finalize());

    // Flags (1 byte)
    let mut flags = 0u8;
    if up {
        flags |= 0x01; // UP
    }
    if uv {
        flags |= 0x04; // UV
    }
    if extensions.is_some() {
        flags |= 0x80; // ED (extension data present)
    }
    auth_data.push(flags);

    // Sign count (4 bytes)
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    // Extensions (CBOR-encoded)
    if let Some(ext_value) = extensions {
        let mut ext_bytes = Vec::new();
        crate::cbor::into_writer(ext_value, &mut ext_bytes).map_err(|_| StatusCode::InvalidCbor)?;
        auth_data.extend_from_slice(&ext_bytes);
    }

    Ok(auth_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_authenticator_data() {
        let auth_data = build_authenticator_data("example.com", true, false, 42, None).unwrap();

        // Should be: 32 (hash) + 1 (flags) + 4 (counter) = 37 bytes
        assert_eq!(auth_data.len(), 37);

        // Check flags (UP=1, UV=0)
        assert_eq!(auth_data[32], 0x01);

        // Check sign count
        let count =
            u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
        assert_eq!(count, 42);
    }

    #[test]
    fn test_build_authenticator_data_with_uv() {
        let auth_data = build_authenticator_data("example.com", true, true, 1, None).unwrap();

        // Check flags (UP=1, UV=1)
        assert_eq!(auth_data[32], 0x05); // 0x01 | 0x04
    }
}
