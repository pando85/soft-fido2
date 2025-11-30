//! authenticatorMakeCredential command
//!
//! Creates a new credential for a relying party.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorMakeCredential>

use crate::{
    CredProtect, SecBytes, UpResult, UvResult,
    authenticator::Authenticator,
    callbacks::AuthenticatorCallbacks,
    cbor::{MapBuilder, MapParser},
    extensions::MakeCredentialExtensions,
    status::{Result, StatusCode},
    types::{PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, User},
};

use soft_fido2_crypto::ecdsa;

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// MakeCredential request parameter keys
#[allow(dead_code)]
mod req_keys {
    pub const CLIENT_DATA_HASH: i32 = 0x01;
    pub const RP: i32 = 0x02;
    pub const USER: i32 = 0x03;
    pub const PUB_KEY_CRED_PARAMS: i32 = 0x04;
    pub const EXCLUDE_LIST: i32 = 0x05;
    pub const EXTENSIONS: i32 = 0x06;
    pub const OPTIONS: i32 = 0x07;
    pub const PIN_UV_AUTH_PARAM: i32 = 0x08;
    pub const PIN_UV_AUTH_PROTOCOL: i32 = 0x09;
    pub const ENTERPRISE_ATTESTATION: i32 = 0x0A;
}

/// MakeCredential response keys
#[allow(dead_code)]
mod resp_keys {
    pub const FMT: i32 = 0x01;
    pub const AUTH_DATA: i32 = 0x02;
    pub const ATT_STMT: i32 = 0x03;
    pub const EP_ATT: i32 = 0x04;
    pub const LARGE_BLOB_KEY: i32 = 0x05;
}

/// Options in the request
#[derive(Debug, Default)]
struct MakeCredentialOptions {
    rk: bool,
    up: bool,
    uv: bool,
}

/// Handle authenticatorMakeCredential command
///
/// Implements FIDO 2.2 spec section 6.1.2 authenticatorMakeCredential algorithm
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;

    // ===== Parse all parameters first =====

    // Required parameters
    let client_data_hash: Vec<u8> = parser.get_bytes(req_keys::CLIENT_DATA_HASH)?;
    if client_data_hash.len() != 32 {
        return Err(StatusCode::InvalidParameter);
    }

    let rp: RelyingParty = parser.get(req_keys::RP)?;
    let user = parse_user(&parser, req_keys::USER)?;

    let params_value: crate::cbor::Value = parser.get(req_keys::PUB_KEY_CRED_PARAMS)?;
    let pub_key_cred_params: Vec<PublicKeyCredentialParameters> =
        crate::cbor::from_value(&params_value)?;

    // Optional parameters
    let exclude_list: Option<Vec<PublicKeyCredentialDescriptor>> =
        parser.get_opt(req_keys::EXCLUDE_LIST)?;

    let pin_uv_auth_param: Option<Vec<u8>> =
        if parser.get_raw(req_keys::PIN_UV_AUTH_PARAM).is_some() {
            Some(parser.get_bytes(req_keys::PIN_UV_AUTH_PARAM)?)
        } else {
            None
        };
    let pin_uv_auth_protocol: Option<u8> = parser.get_opt(req_keys::PIN_UV_AUTH_PROTOCOL)?;

    let options = parse_options(&parser)?;

    let extensions =
        if let Some(ext_value) = parser.get_opt::<crate::cbor::Value>(req_keys::EXTENSIONS)? {
            MakeCredentialExtensions::from_cbor(&ext_value)?
        } else {
            MakeCredentialExtensions::new()
        };

    let enterprise_attestation: Option<u8> = parser.get_opt(req_keys::ENTERPRISE_ATTESTATION)?;

    // ===== Begin FIDO 2.2 Spec Algorithm =====

    // Step 1: Check for zero-length pinUvAuthParam
    if let Some(ref param) = pin_uv_auth_param
        && param.is_empty()
    {
        // Zero-length pinUvAuthParam
        if !auth.is_pin_set() {
            return Err(StatusCode::PinNotSet);
        } else {
            return Err(StatusCode::PinAuthInvalid);
        }
    }

    let mut user_authenticated = false;
    let mut user_verified_flag_value = false;

    // Step 2: If pinUvAuthParam is present, verify it
    if let Some(ref pin_auth) = pin_uv_auth_param {
        let protocol = pin_uv_auth_protocol.ok_or(StatusCode::MissingParameter)?;

        auth.verify_pin_uv_auth_param(protocol, pin_auth, &client_data_hash)?;
        auth.verify_pin_uv_auth_token(crate::pin_token::Permission::MakeCredential, Some(&rp.id))?;
        user_authenticated = true;
        user_verified_flag_value = get_user_verified_flag_value(auth);
    }

    if pin_uv_auth_param.is_none() && options.uv {
        // Perform built-in user verification
        let info = format!("Verify for {}", rp.id);
        match auth
            .callbacks()
            .request_uv(&info, user.name.as_deref(), &rp.id)?
        {
            UvResult::Accepted | UvResult::AcceptedWithUp => {
                user_verified_flag_value = true;
                user_authenticated = true;
            }
            UvResult::Denied => return Err(StatusCode::OperationDenied),
            UvResult::Timeout => return Err(StatusCode::UserActionTimeout),
        }
    }

    // Step 3: Check if all requested algorithms are supported
    let alg = pub_key_cred_params
        .iter()
        .find(|p| auth.config().algorithms.contains(&p.alg))
        .ok_or(StatusCode::UnsupportedAlgorithm)?;

    // Step 9: Process enterprise attestation
    let _use_enterprise_attestation = if let Some(ep_att) = enterprise_attestation {
        // Check if enterprise attestation is supported
        if !auth.config().options.ep.unwrap_or(false) {
            return Err(StatusCode::InvalidParameter);
        }
        // For now, we don't actually implement enterprise attestation
        // Just validate the parameter
        ep_att == 1 || ep_att == 2
    } else {
        false
    };

    // Step 10: Process extensions (if not already done)
    // Extensions are already parsed above

    // Step 11: Process excludeList
    if let Some(ref exclude) = exclude_list {
        // Step 11.1: Check if any excluded credential exists with appropriate credProtect level
        for cred_desc in exclude {
            if let Ok(true) = auth.callbacks().credential_exists(&cred_desc.id) {
                // Credential exists - need to check credProtect level
                // Try to get the credential to check its credProtect level
                if let Ok(cred) = auth.callbacks().get_credential(&cred_desc.id) {
                    use crate::CredProtect;
                    let cred_protect = cred.cred_protect;

                    // credProtect level 1 (userVerificationOptional): always exclude
                    if cred_protect == CredProtect::UserVerificationOptional as u8 {
                        return Err(StatusCode::CredentialExcluded);
                    }

                    // credProtect level 2 (userVerificationOptionalWithCredentialIDList):
                    // exclude if in excludeList
                    if cred_protect
                        == CredProtect::UserVerificationOptionalWithCredentialIdList as u8
                    {
                        return Err(StatusCode::CredentialExcluded);
                    }

                    // credProtect level 3 (userVerificationRequired):
                    // only exclude if user is authenticated
                    if cred_protect == CredProtect::UserVerificationRequired as u8
                        && user_authenticated
                    {
                        return Err(StatusCode::CredentialExcluded);
                    }
                }
            }
        }
    }

    // Step 12: Process extensions that haven't been processed yet
    // (Already done above in step 10)

    // Step 13: Collect user presence if required
    let mut user_present_flag_value = false;

    // Determine if we need to collect UP
    let need_user_presence = if options.up {
        // UP was explicitly requested
        true
    } else if !user_authenticated {
        // No authentication performed yet, need UP
        true
    } else {
        false
    };

    if need_user_presence {
        let info = format!("Register with {}", rp.id);
        match auth
            .callbacks()
            .request_up(&info, user.name.as_deref(), &rp.id)?
        {
            UpResult::Accepted => user_present_flag_value = true,
            UpResult::Denied => return Err(StatusCode::OperationDenied),
            UpResult::Timeout => return Err(StatusCode::UserActionTimeout),
        }
    } else {
        // If UV was performed, UP is implicitly true
        if user_verified_flag_value {
            user_present_flag_value = true;
        }
    }

    // Step 14: Generate credential and prepare response
    // Step 14.1-14.2: Generate key pair and credential
    let (private_key, public_key_bytes) = ecdsa::generate_keypair();

    let credential_id = if options.rk || auth.config().force_resident_keys {
        // Resident key: generate random ID and store credential
        let id = generate_credential_id();

        // Determine credProtect level:
        // 1. Use explicitly requested credProtect from extensions
        // 2. If UV was required during registration, enforce UV for future use (level 0x03)
        // 3. Otherwise default to userVerificationOptional (level 0x01)
        let cred_protect_value = extensions
            .cred_protect
            .map(|p| p.to_u8())
            .unwrap_or_else(|| {
                if user_verified_flag_value {
                    // UV was performed - enforce UV for future authentications
                    CredProtect::UserVerificationRequired as u8
                } else {
                    CredProtect::UserVerificationOptional as u8
                }
            });

        let credential = crate::types::Credential {
            id: id.clone(),
            rp_id: rp.id.clone(),
            rp_name: rp.name.clone(),
            user_id: user.id.clone(),
            user_name: user.name.clone(),
            user_display_name: user.display_name.clone(),
            private_key: SecBytes::from_array(private_key),
            algorithm: alg.alg,
            sign_count: 0,
            created: current_timestamp(),
            discoverable: true,
            cred_protect: cred_protect_value,
        };

        auth.callbacks().write_credential(&credential)?;

        id
    } else {
        // Non-resident key: wrap private key into credential ID
        auth.wrap_credential(&private_key, &rp.id, alg.alg)?
    };

    // Step 14.3: Call clearUserPresentFlag(), clearUserVerifiedFlag(),
    // and clearPinUvAuthTokenPermissionsExceptLbw()
    // Note: We don't have explicit user present/verified flags to clear since they're local variables
    // But we do need to clear the PIN token permissions
    auth.clear_pin_uv_auth_token_permissions_except_lbw();

    // Step 15: Build extension outputs
    let extension_outputs = extensions.build_outputs(auth.config().min_pin_length);

    // Step 16: Build authenticator data
    let cred_data = AttestationCredential {
        id: credential_id,
        public_key: public_key_bytes,
        algorithm: alg.alg,
    };
    let auth_data = build_authenticator_data(
        &rp.id,
        user_present_flag_value,
        user_verified_flag_value,
        auth.config().aaguid,
        &cred_data,
        extension_outputs.as_ref(),
    )?;

    // Step 17: Build attestation statement (self-attestation for now)
    let sig_data = [&auth_data[..], &client_data_hash[..]].concat();
    let signature = ecdsa::sign(&private_key, &sig_data)?;

    let att_stmt = build_attestation_statement(&signature, alg.alg)?;

    // Step 18: Build and return response
    MapBuilder::new()
        .insert(resp_keys::FMT, "packed")?
        .insert_bytes(resp_keys::AUTH_DATA, &auth_data)? // Must be CBOR bytes, not array!
        .insert(resp_keys::ATT_STMT, att_stmt)?
        .build()
}

/// Get user verified flag value from authenticator state
///
/// This helper checks if the current PIN/UV auth token was obtained with UV.
/// Per FIDO2 spec, if a token exists and was obtained via UV, the UV flag should be set.
pub fn get_user_verified_flag_value<C: AuthenticatorCallbacks>(_auth: &Authenticator<C>) -> bool {
    // For now, we assume that if a valid PIN token exists, it was obtained with some form of verification
    // In a full implementation, we would track whether the token was obtained via PIN or UV
    // and set the flag accordingly. For simplicity, we return true if a token exists.
    // This could be enhanced by adding a field to PinToken to track the verification method.
    true
}

/// Parse user object from the request
///
/// User object is a CBOR map with text keys containing:
/// - "id" (required): CBOR Bytes
/// - "name" (optional): CBOR Text
/// - "displayName" (optional): CBOR Text
fn parse_user(parser: &MapParser, key: i32) -> Result<User> {
    let user_value: crate::cbor::Value = parser.get(key)?;

    let user_map = match user_value {
        crate::cbor::Value::Map(map) => map,
        _ => return Err(StatusCode::InvalidCbor),
    };

    let mut user_id: Option<Vec<u8>> = None;
    let mut user_name: Option<String> = None;
    let mut user_display_name: Option<String> = None;

    for (k, v) in user_map {
        if let crate::cbor::Value::Text(key_str) = k {
            match key_str.as_str() {
                "id" => {
                    if let crate::cbor::Value::Bytes(bytes) = v {
                        user_id = Some(bytes);
                    }
                }
                "name" => {
                    if let crate::cbor::Value::Text(text) = v {
                        user_name = Some(text);
                    }
                }
                "displayName" => {
                    if let crate::cbor::Value::Text(text) = v {
                        user_display_name = Some(text);
                    }
                }
                _ => {} // Ignore unknown fields
            }
        }
    }

    let id = user_id.ok_or(StatusCode::MissingParameter)?;

    Ok(User {
        id,
        name: user_name,
        display_name: user_display_name,
    })
}

/// Parse options from the request
fn parse_options(parser: &MapParser) -> Result<MakeCredentialOptions> {
    let opts_map: Option<crate::cbor::Value> = parser.get_opt(req_keys::OPTIONS)?;

    let mut options = MakeCredentialOptions {
        rk: false,
        up: true, // Default to true
        uv: false,
    };

    if let Some(crate::cbor::Value::Map(opts)) = opts_map {
        for (k, v) in opts {
            if let (crate::cbor::Value::Text(key), crate::cbor::Value::Bool(val)) = (k, v) {
                match key.as_str() {
                    "rk" => options.rk = val,
                    "up" => options.up = val,
                    "uv" => options.uv = val,
                    _ => {} // Ignore unknown options
                }
            }
        }
    }

    Ok(options)
}

/// Attestation credential data
struct AttestationCredential {
    id: Vec<u8>,
    public_key: Vec<u8>,
    algorithm: i32,
}

/// Generate a random credential ID
fn generate_credential_id() -> Vec<u8> {
    let mut id = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Get current timestamp in seconds
#[cfg(feature = "std")]
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Get current timestamp in seconds (no_std fallback)
#[cfg(not(feature = "std"))]
fn current_timestamp() -> i64 {
    // In no_std, return 0. Applications can override this by providing
    // their own time source through the authenticator config.
    0
}

/// Build authenticator data
///
/// Format: rpIdHash (32) || flags (1) || signCount (4) || attestedCredData || extensions
fn build_authenticator_data(
    rp_id: &str,
    up: bool,
    uv: bool,
    aaguid: [u8; 16],
    cred: &AttestationCredential,
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
    flags |= 0x40; // AT (attested credential data present)
    if extensions.is_some() {
        flags |= 0x80; // ED (extension data present)
    }
    auth_data.push(flags);

    // Sign count (4 bytes) - always 0 for new credentials
    auth_data.extend_from_slice(&0u32.to_be_bytes());

    // Attested credential data
    // AAGUID (16 bytes)
    auth_data.extend_from_slice(&aaguid);

    // Credential ID length (2 bytes)
    auth_data.extend_from_slice(&(cred.id.len() as u16).to_be_bytes());

    // Credential ID
    auth_data.extend_from_slice(&cred.id);

    // Credential public key (COSE format)
    let cose_key = build_cose_public_key(&cred.public_key, cred.algorithm)?;
    auth_data.extend_from_slice(&cose_key);

    // Extensions (CBOR-encoded)
    if let Some(ext_value) = extensions {
        let mut ext_bytes = Vec::new();
        crate::cbor::into_writer(ext_value, &mut ext_bytes).map_err(|_| StatusCode::InvalidCbor)?;
        auth_data.extend_from_slice(&ext_bytes);
    }

    Ok(auth_data)
}

/// Build COSE public key
///
/// For ES256 (P-256):
/// { 1: 2, 3: -7, -1: 1, -2: x, -3: y }
fn build_cose_public_key(public_key: &[u8], algorithm: i32) -> Result<Vec<u8>> {
    // Public key is in uncompressed SEC1 format: 0x04 || x || y
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Err(StatusCode::InvalidParameter);
    }

    let x = &public_key[1..33];
    let y = &public_key[33..65];

    MapBuilder::new()
        .insert(1, 2)? // kty: EC2
        .insert(3, algorithm)? // alg
        .insert(-1, 1)? // crv: P-256
        .insert_bytes(-2, x)? // x coordinate
        .insert_bytes(-3, y)? // y coordinate
        .build()
}

/// Build attestation statement
fn build_attestation_statement(signature: &[u8], alg: i32) -> Result<crate::cbor::Value> {
    let map = vec![
        (
            crate::cbor::Value::Text("alg".to_string()),
            crate::cbor::Value::Integer(alg.into()),
        ),
        (
            crate::cbor::Value::Text("sig".to_string()),
            crate::cbor::Value::Bytes(signature.to_vec()),
        ),
    ];

    Ok(crate::cbor::Value::Map(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_credential_id() {
        let id1 = generate_credential_id();
        let id2 = generate_credential_id();

        assert_eq!(id1.len(), 32);
        assert_eq!(id2.len(), 32);
        assert_ne!(id1, id2); // Should be random
    }

    #[test]
    fn test_build_cose_public_key() {
        // Valid uncompressed P-256 public key
        let mut public_key = vec![0x04];
        public_key.extend_from_slice(&[0x42u8; 32]); // x
        public_key.extend_from_slice(&[0x43u8; 32]); // y

        let cose_key = build_cose_public_key(&public_key, -7).unwrap();
        assert!(!cose_key.is_empty());
    }

    #[test]
    fn test_build_cose_public_key_invalid() {
        let public_key = vec![0x01, 0x02, 0x03]; // Invalid format
        let result = build_cose_public_key(&public_key, -7);
        assert!(result.is_err());
    }
}
