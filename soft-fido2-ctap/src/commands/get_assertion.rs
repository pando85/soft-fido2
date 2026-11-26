//! authenticatorGetAssertion command
//!
//! Authenticates a user with an existing credential.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetAssertion>

use crate::{
    UpResult, UvResult,
    authenticator::Authenticator,
    callbacks::AuthenticatorCallbacks,
    cbor::{MapBuilder, MapParser},
    commands::make_credential::{
        MAX_CREDENTIAL_ID_LENGTH, get_user_present_flag_value, get_user_verified_flag_value,
    },
    extensions::{GetAssertionExtensions, compute_hmac_secret, select_cred_random},
    key_provider::CredentialKeyProvider,
    status::{Result, StatusCode},
    types::{CredentialBackupState, PublicKeyCredentialDescriptor, auth_data_flags},
};

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use core::cmp::Reverse;

use sha2::{Digest, Sha256};

/// Maximum RP ID length (typical domain name limit)
const MAX_RP_ID_LENGTH: usize = 256;

/// Maximum number of credentials in allow list
const MAX_ALLOW_LIST_SIZE: usize = 128;

/// GetAssertion request parameter keys
mod req_keys {
    pub const RP_ID: i32 = 0x01;
    pub const CLIENT_DATA_HASH: i32 = 0x02;
    pub const ALLOW_LIST: i32 = 0x03;
    pub const EXTENSIONS: i32 = 0x04;
    pub const OPTIONS: i32 = 0x05;
    pub const PIN_UV_AUTH_PARAM: i32 = 0x06;
    pub const PIN_UV_AUTH_PROTOCOL: i32 = 0x07;
    pub const ENTERPRISE_ATTESTATION: i32 = 0x08;
    pub const ATTESTATION_FORMATS_PREFERENCE: i32 = 0x09;
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
    pub const UNSIGNED_EXTENSION_OUTPUTS: i32 = 0x08;
    pub const EP_ATT: i32 = 0x09;
    pub const ATT_STMT: i32 = 0x0A;
}

/// Options in the request
#[derive(Debug, Default)]
struct GetAssertionOptions {
    up: bool,
    uv: bool,
}

/// Response state tracking UP and UV bits
#[derive(Debug, Default)]
struct ResponseState {
    up: bool,
    uv: bool,
}

/// Handle authenticatorGetAssertion command
///
/// Implements FIDO 2.2 spec section 6.2.2 authenticatorGetAssertion algorithm
pub fn handle<C: AuthenticatorCallbacks, K: CredentialKeyProvider>(
    auth: &mut Authenticator<C, K>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;
    auth.clear_assertion_state();

    // ===== Parse all parameters first =====

    // Required parameters
    let rp_id: String = parser.get(req_keys::RP_ID)?;

    // Validate RP ID
    if rp_id.is_empty() {
        return Err(StatusCode::InvalidParameter);
    }
    if rp_id.len() > MAX_RP_ID_LENGTH {
        return Err(StatusCode::InvalidLength);
    }

    let client_data_hash: Vec<u8> = parser.get_bytes(req_keys::CLIENT_DATA_HASH)?;
    if client_data_hash.len() != 32 {
        return Err(StatusCode::InvalidParameter);
    }

    // Optional parameters - allowList
    let allow_list: Option<Vec<PublicKeyCredentialDescriptor>> = if let Some(raw_allow_list) =
        parser.get_raw(req_keys::ALLOW_LIST)
    {
        match raw_allow_list {
            crate::cbor::Value::Array(arr) => {
                // Validate allow list size
                if arr.len() > MAX_ALLOW_LIST_SIZE {
                    return Err(StatusCode::LimitExceeded);
                }
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
                            // Validate credential ID size (per CTAP spec max is 1023 bytes)
                            if id.len() > MAX_CREDENTIAL_ID_LENGTH {
                                return Err(StatusCode::InvalidLength);
                            }
                            descriptors.push(PublicKeyCredentialDescriptor {
                                r#type: cred_type,
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

    let enterprise_attestation: Option<u8> = parser.get_opt(req_keys::ENTERPRISE_ATTESTATION)?;
    let _attestation_formats_preference: Option<Vec<String>> =
        parser.get_opt(req_keys::ATTESTATION_FORMATS_PREFERENCE)?;

    // Parse extensions
    let extensions =
        if let Some(ext_value) = parser.get_opt::<crate::cbor::Value>(req_keys::EXTENSIONS)? {
            GetAssertionExtensions::from_cbor(&ext_value)?
        } else {
            GetAssertionExtensions::new()
        };

    // ===== FIDO 2.2 Algorithm Steps =====

    // Step 1: Check for zero-length pinUvAuthParam
    if let Some(ref param) = pin_uv_auth_param
        && param.is_empty()
    {
        // Zero-length pinUvAuthParam - request evidence of user interaction
        let info = format!("Select authenticator for {}", rp_id);
        match auth.callbacks().request_up(&info, None, &rp_id)? {
            UpResult::Accepted => {
                // User interaction provided
                // Check if authenticator is protected by UV (PIN or biometrics)
                if !auth.is_protected_by_uv() {
                    return Err(StatusCode::PinNotSet);
                } else {
                    return Err(StatusCode::PinAuthInvalid);
                }
            }
            UpResult::Denied => return Err(StatusCode::OperationDenied),
            UpResult::Timeout => return Err(StatusCode::UserActionTimeout),
        }
    }

    // Step 2: Validate pinUvAuthProtocol if pinUvAuthParam is present
    if pin_uv_auth_param.is_some() {
        if let Some(protocol) = pin_uv_auth_protocol {
            // Check if protocol is supported
            if !auth.config().pin_uv_auth_protocols.contains(&protocol) {
                return Err(StatusCode::InvalidParameter);
            }
        } else {
            // pinUvAuthParam present but pinUvAuthProtocol absent
            return Err(StatusCode::MissingParameter);
        }
    }

    // Step 3: Initialize response state - both up and uv bits start as false
    let mut response_state = ResponseState {
        up: false,
        uv: false,
    };

    // Step 4: Process options
    let mut options = parse_options(&parser)?;

    // hmac-secret requires user presence, even for a non-UV assertion.
    if extensions.has_hmac_secret() && !options.up {
        return Err(StatusCode::UnsupportedOption);
    }

    // Step 4.1: If "uv" option is absent, treat as false (default)
    // This is already handled by parse_options() which defaults uv to false

    // Step 4.2: If pinUvAuthParam is present, treat "uv" option as false
    if pin_uv_auth_param.is_some() {
        options.uv = false;
    }

    // Step 4.3: If "uv" is true, built-in UV must be configured now.
    if options.uv && !auth.built_in_uv_state().is_configured() {
        return Err(StatusCode::InvalidOption);
    }

    // Step 4.4: If "rk" option is present, return error
    // This is handled in parse_options()

    // Step 4.5: If "up" option is not present, treat as true (default)
    // This is already handled by parse_options() which defaults up to true

    // Step 5: alwaysUv option processing
    if auth.config().options.always_uv && options.up {
        // Step 5.1: Check if authenticator is protected by user verification
        // (either PIN is set OR built-in UV is enabled)
        if !auth.is_protected_by_uv() {
            // Authenticator is NOT protected by some form of user verification
            // Check if clientPin is supported for ga permission
            if auth.config().options.client_pin.unwrap_or(false)
                && !auth.config().options.pin_uv_auth_token
            // noMcGaPermissionsWithClientPin absent or false
            {
                return Err(StatusCode::PuatRequired);
            } else {
                // clientPin is not supported
                return Err(StatusCode::OperationDenied);
            }
        }

        // Authenticator IS protected by UV
        // Step 5.2: If pinUvAuthParam is present, continue to step 7
        if pin_uv_auth_param.is_some() {
            // Continue to step 7
        }
        // Step 5.3: If "uv" option is true, continue to step 7
        else if options.uv {
            // Continue to step 7 (built-in UV will be performed)
        }
        // Step 5.4: If "uv" is false but authenticator supports enabled built-in UV
        else if auth.has_built_in_uv_enabled() {
            // Treat "uv" as true
            options.uv = true;
            // Continue to step 7
        }
        // Step 5.5: Otherwise, require PUAT or deny
        else if auth.config().options.client_pin.unwrap_or(false)
            && !auth.config().options.pin_uv_auth_token
        {
            // clientPin is supported, return PUAT required
            return Err(StatusCode::PuatRequired);
        } else {
            // clientPin is not supported
            return Err(StatusCode::OperationDenied);
        }
    }

    // Step 6: Enterprise attestation handling
    let ep_att = false;
    if let Some(ea_value) = enterprise_attestation {
        // Check if authenticator is enterprise attestation capable
        // For this implementation, we assume the authenticator doesn't support enterprise attestation
        // A full implementation would check auth.config().options.ep and process accordingly

        // Simplified: If EA is requested but not supported, return error
        // In a real implementation, you would:
        // 1. Check if EA is enabled
        // 2. Validate EA value (1 or 2)
        // 3. Check RP ID against pre-configured list
        // 4. Display warning to user if needed
        // 5. Set ep_att = true if conditions are met

        if ea_value != 1 && ea_value != 2 {
            return Err(StatusCode::InvalidOption);
        }

        // For now, we don't support enterprise attestation, so treat as absent
        // ep_att remains false
    }

    // Step 7: User verification handling
    if auth.is_protected_by_uv() {
        if let Some(ref pin_auth) = pin_uv_auth_param {
            // Step 7.1: pinUvAuthParam is present (and "uv" option is treated as false per step 4.2)
            let protocol = pin_uv_auth_protocol.unwrap(); // Already validated in step 2

            // Step 7.1.1: Verify pinUvAuthParam
            auth.verify_pin_uv_auth_param(protocol, pin_auth, &client_data_hash)?;

            // Step 7.1.2: Get user verified flag value from PIN token
            let user_verified_flag_value = get_user_verified_flag_value(auth);

            // Step 7.1.3: If userVerifiedFlagValue is false, return error
            if !user_verified_flag_value {
                return Err(StatusCode::PinAuthInvalid);
            }

            // Step 7.1.4: Verify PIN token has ga (GetAssertion) permission
            auth.verify_pin_uv_auth_token(
                crate::pin_token::Permission::GetAssertion,
                Some(&rp_id),
            )?;

            // Step 7.1.5: Set "uv" bit in response
            response_state.uv = true;

            // Also check if user presence was confirmed during token acquisition
            let user_present_flag_value = get_user_present_flag_value(auth);
            if user_present_flag_value {
                response_state.up = true;
            }

            // Continue to Step 8
        } else if options.uv {
            // Step 7.2: "uv" option is present and true (pinUvAuthParam is not present)
            // This provides backward compatibility for CTAP2.0
            // Perform built-in user verification with internal retry

            let info = format!("Verify for {}", rp_id);
            match auth.callbacks().request_uv(&info, None, &rp_id)? {
                UvResult::Accepted => {
                    // UV succeeded - reset retry counter
                    auth.reset_uv_retries();
                    response_state.uv = true;
                }
                UvResult::AcceptedWithUp => {
                    // UV succeeded - reset retry counter
                    auth.reset_uv_retries();
                    response_state.uv = true;
                    response_state.up = true;
                }
                UvResult::Timeout => {
                    // User action timeout
                    return Err(StatusCode::UserActionTimeout);
                }
                UvResult::Denied => {
                    auth.decrement_uv_retries();

                    if auth.is_uv_blocked() {
                        return Err(StatusCode::UvBlocked);
                    }

                    if auth.is_pin_set() {
                        return Err(StatusCode::PuatRequired);
                    }

                    return Err(StatusCode::OperationDenied);
                }
                UvResult::Unavailable => {
                    // Not a failed attempt: no retry is consumed, and a PIN, which is what the
                    // platform needs, is asked for even when the UV retries are exhausted.
                    if auth.is_pin_set() {
                        return Err(StatusCode::PuatRequired);
                    }

                    if auth.is_uv_blocked() {
                        return Err(StatusCode::UvBlocked);
                    }

                    return Err(StatusCode::OperationDenied);
                }
            }
            // Continue to Step 8
        }
    }

    // Step 8: Locate all credentials that are eligible for retrieval
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
            if let Ok((key, cred_rp_id, algorithm)) = auth.unwrap_credential(&desc.id)
                && cred_rp_id == rp_id
            {
                let cred = crate::types::Credential {
                    id: desc.id.clone(),
                    rp_id: cred_rp_id,
                    rp_name: None,
                    user_id: Vec::new(),
                    user_name: None,
                    user_display_name: None,
                    key,
                    algorithm,
                    sign_count: 0,
                    created: 0,
                    discoverable: false,
                    backup_state: CredentialBackupState::NotEligible,
                    cred_protect: 0,
                    // Not stored: derived from the wrapping key and the ID.
                    cred_random: Some(auth.wrapped_cred_random(&desc.id)),
                };
                creds.push(cred);
            }
        }
        creds
    } else {
        // No allow_list, search all discoverable credentials for this RP
        auth.callbacks().read_credentials(&rp_id, None)?
    };

    // Step 8.1: Filter credentials by credential protection policy
    credentials.retain(|cred| {
        // credProtect level 3 (userVerificationRequired): Remove if UV not performed
        if cred.cred_protect == 0x03 && !response_state.uv {
            return false;
        }
        // credProtect level 2 (userVerificationOptionalWithCredentialIDList):
        // Remove if no allowList and UV not performed
        if cred.cred_protect == 0x02 && allow_list.is_none() && !response_state.uv {
            return false;
        }
        true
    });

    if credentials.is_empty() {
        return Err(StatusCode::NoCredentials);
    }

    let number_of_credentials = credentials.len();

    // Step 9: Check if evidence of user interaction was provided in Step 7
    // If UV was performed with AcceptedWithUp, UP bit is already set
    // This step is already handled above

    // Step 10: User presence handling
    if options.up {
        if pin_uv_auth_param.is_some() {
            // Step 10.1: pinUvAuthParam is present
            // TODO: Check getUserPresentFlagValue()
            // For simplicity, we always request UP unless already set
            if !response_state.up {
                let info = format!("Authenticate with {}", rp_id);
                match auth.callbacks().request_up(&info, None, &rp_id)? {
                    UpResult::Accepted => response_state.up = true,
                    UpResult::Denied => return Err(StatusCode::OperationDenied),
                    UpResult::Timeout => return Err(StatusCode::UserActionTimeout),
                }
            }
        } else {
            // Step 10.2: pinUvAuthParam is not present
            if !response_state.up {
                let info = format!("Authenticate with {}", rp_id);
                match auth.callbacks().request_up(&info, None, &rp_id)? {
                    UpResult::Accepted => response_state.up = true,
                    UpResult::Denied => return Err(StatusCode::OperationDenied),
                    UpResult::Timeout => return Err(StatusCode::UserActionTimeout),
                }
            }
        }

        // Set UP bit in response
        response_state.up = true;

        // Clear flags
        // TODO: Implement clearUserPresentFlag(), clearUserVerifiedFlag()
        auth.clear_pin_uv_auth_token_permissions_except_lbw();
    }

    // Step 11: Process extensions
    // Extensions are processed; outputs will be added to authenticator data
    let mut extension_outputs = extensions.build_outputs();
    // Note: hmac-secret output is computed after credential selection

    // Step 12: Credential selection
    let (selected_cred, user_selected) = if allow_list.is_some() {
        // Step 12.1: allowList is present - select any credential
        (credentials.pop().unwrap(), false)
    } else {
        // Step 12.2: allowList is not present
        if number_of_credentials == 1 {
            // Only one credential - select it
            (credentials.pop().unwrap(), false)
        } else {
            // Multiple credentials
            // Check if authenticator has a display
            // For this implementation, we assume no display or simplified behavior

            // Order credentials by creation time (reverse order - most recent first)
            credentials.sort_by_key(|b| Reverse(b.created));

            // If no display or (UV and UP are false), use account selection
            let user_names: Vec<String> = credentials
                .iter()
                .map(|c| c.user_name.clone().unwrap_or_else(|| "Unknown".to_string()))
                .collect();

            let index = auth.callbacks().select_credential(&rp_id, &user_names)?;

            if index >= credentials.len() {
                return Err(StatusCode::InvalidParameter);
            }

            let selected = credentials.swap_remove(index);

            // Note: In a full implementation with display and UV/UP true,
            // we would set user_selected = true here
            (selected, false)
        }
    };

    // Compute hmac-secret output if requested and credential supports it
    if extensions.has_hmac_secret()
        && let Some(hmac_input) = extensions.get_hmac_secret()
    {
        // Get the stored keypair for the PIN protocol version
        // This keypair was established via getKeyAgreement clientPIN subcommand
        let keypair = auth.get_pin_protocol_keypair(hmac_input.pin_uv_auth_protocol);

        if let Some(auth_keypair) = keypair
            && let Some(cred_random) = &selected_cred.cred_random
        {
            // Compute hmac-secret output using the stored keypair
            if let Some(encrypted_output) = compute_hmac_secret(
                hmac_input,
                select_cred_random(cred_random.as_slice(), response_state.uv).as_slice(),
                auth_keypair,
            ) {
                // Add hmac-secret to extension outputs
                // Per spec, the output is just the encrypted bytes
                let ext_name = crate::extensions::ext_ids::HMAC_SECRET;
                if let Some(crate::cbor::Value::Map(ref mut map)) = extension_outputs {
                    map.push((
                        crate::cbor::Value::Text(ext_name.to_string()),
                        crate::cbor::Value::Bytes(encrypted_output),
                    ));
                } else {
                    use alloc::vec;
                    extension_outputs = Some(crate::cbor::Value::Map(vec![(
                        crate::cbor::Value::Text(ext_name.to_string()),
                        crate::cbor::Value::Bytes(encrypted_output),
                    )]));
                }
            }
        }
    }

    // Step 13: Attestation statement generation
    // Simplified: Only generate attestation if attestationFormatsPreference is present and not ["none"]
    // For now, we skip attestation generation (most common case)
    // TODO: Implement full attestation statement generation

    // Step 14: Sign clientDataHash with authData
    // Wrapped credentials do not have durable mutable state, so they must
    // consistently report zero rather than repeat a misleading positive value.
    let new_sign_count = if auth.config().constant_sign_count || !selected_cred.discoverable {
        0
    } else {
        selected_cred.sign_count.saturating_add(1)
    };

    // Only update stored credentials (not wrapped ones)
    let write_back = !auth.config().constant_sign_count && selected_cred.discoverable;
    if write_back {
        let mut updated_cred = selected_cred.clone();
        updated_cred.sign_count = new_sign_count;
        auth.callbacks().update_credential(&updated_cred)?;
    }

    // Build authenticator data
    let auth_data = build_authenticator_data(
        &rp_id,
        response_state.up,
        response_state.uv,
        selected_cred.backup_state,
        new_sign_count,
        extension_outputs.as_ref(),
    )?;

    // Generate signature via provider
    let sig_data = [&auth_data[..], &client_data_hash[..]].concat();

    let signature = auth
        .key_provider()
        .sign(&selected_cred.key, selected_cred.algorithm, &sig_data)
        .map_err(StatusCode::from)?;

    // Build credential descriptor
    let credential_desc = PublicKeyCredentialDescriptor {
        id: selected_cred.id.clone(),
        r#type: "public-key".to_string(),
        transports: None,
    };

    // Build response
    let mut builder = MapBuilder::new()
        .insert(resp_keys::CREDENTIAL, credential_desc)?
        .insert_bytes(resp_keys::AUTH_DATA, &auth_data)?
        .insert_bytes(resp_keys::SIGNATURE, &signature)?;

    // Add user info if credential was discoverable
    // User identifiable information must NOT be returned if UV is not performed
    if selected_cred.discoverable {
        if response_state.uv {
            // UV performed - include full user info
            let user = crate::types::User {
                id: selected_cred.user_id.clone(),
                name: selected_cred.user_name.clone(),
                display_name: selected_cred.user_display_name.clone(),
            };
            builder = builder.insert(resp_keys::USER, user)?;
        } else {
            // UV not performed - only include user ID
            let user = crate::types::User {
                id: selected_cred.user_id.clone(),
                name: None,
                display_name: None,
            };
            builder = builder.insert(resp_keys::USER, user)?;
        }
    }

    // Add numberOfCredentials if multiple credentials and no allowList
    if allow_list.is_none() && number_of_credentials > 1 {
        builder = builder.insert(resp_keys::NUMBER_OF_CREDENTIALS, number_of_credentials)?;
        auth.start_assertion(
            credentials,
            client_data_hash.clone(),
            rp_id.clone(),
            response_state.up,
            response_state.uv,
            extensions.clone(),
        );
    }

    // Add userSelected if credential was selected by user via authenticator interaction
    if user_selected {
        builder = builder.insert(resp_keys::USER_SELECTED, true)?;
    }

    // Add epAtt if enterprise attestation was returned
    if ep_att {
        builder = builder.insert(resp_keys::EP_ATT, true)?;
    }

    // TODO: Add attStmt if attestation statement was generated

    builder.build()
}

/// Parse options from the request
fn parse_options(parser: &MapParser) -> Result<GetAssertionOptions> {
    let opts_map: Option<crate::cbor::Value> = parser.get_opt(req_keys::OPTIONS)?;

    let mut options = GetAssertionOptions {
        up: true,
        uv: false,
    };

    if let Some(crate::cbor::Value::Map(opts)) = opts_map {
        for (k, v) in opts {
            if let (crate::cbor::Value::Text(key), crate::cbor::Value::Bool(val)) = (k, v) {
                match key.as_str() {
                    "up" => options.up = val,
                    "uv" => options.uv = val,
                    "rk" => {
                        // Per spec step 4.4: If "rk" option is present, return error
                        return Err(StatusCode::UnsupportedOption);
                    }
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
    backup_state: CredentialBackupState,
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
        flags |= auth_data_flags::UP;
    }
    if uv {
        flags |= auth_data_flags::UV;
    }
    flags |= backup_state.flags();
    if extensions.is_some() {
        flags |= auth_data_flags::ED;
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

    use crate::{
        authenticator::{Authenticator, AuthenticatorConfig, AuthenticatorOptions, BuiltInUvState},
        cbor::Value,
        test_utils::MockCallbacks,
    };

    #[test]
    fn test_get_assertion_uses_runtime_built_in_uv_state() {
        let config = AuthenticatorConfig::new().with_options(AuthenticatorOptions {
            uv: Some(false),
            pin_uv_auth_token: true,
            ..AuthenticatorOptions::new()
        });
        let mut auth = Authenticator::new(config, MockCallbacks);
        auth.set_built_in_uv_state(BuiltInUvState::Configured)
            .unwrap();

        let options = Value::Map(vec![(Value::Text("uv".into()), Value::Bool(true))]);
        let request = MapBuilder::new()
            .insert(req_keys::RP_ID, "example.com")
            .unwrap()
            .insert_bytes(req_keys::CLIENT_DATA_HASH, &[0x42; 32])
            .unwrap()
            .insert(req_keys::OPTIONS, options)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(handle(&mut auth, &request), Err(StatusCode::NoCredentials));

        auth.set_built_in_uv_state(BuiltInUvState::SupportedNotConfigured)
            .unwrap();
        assert_eq!(handle(&mut auth, &request), Err(StatusCode::InvalidOption));
    }

    /// Platform side of hmac-secret with PIN/UV auth protocol 2: installs a key
    /// agreement key on the authenticator and returns the extensions map for
    /// `salt` plus the key that decrypts the output.
    fn hmac_secret_extensions(
        auth: &mut Authenticator<MockCallbacks>,
        salt: &[u8; 32],
    ) -> (Value, zeroize::Zeroizing<[u8; 32]>) {
        use soft_fido2_crypto::{ecdh::KeyPair, pin_protocol::v2};

        let auth_keypair = KeyPair::generate().unwrap();
        let auth_public = auth_keypair.public_key_bytes();
        auth.set_pin_protocol_keypair(2, auth_keypair);

        let platform = KeyPair::generate().unwrap();
        let shared = platform.shared_secret(&auth_public).unwrap();
        let enc_key = v2::derive_encryption_key(&shared);
        let hmac_key = v2::derive_hmac_key(&shared);
        let salt_enc = v2::encrypt(&enc_key, salt).unwrap();
        let salt_auth = v2::authenticate(&hmac_key, &salt_enc);
        let (x, y) = platform.public_key_cose();
        let cose_key = Value::Map(vec![
            (Value::Integer(1), Value::Integer(2)),
            (Value::Integer(3), Value::Integer(-25)),
            (Value::Integer(-1), Value::Integer(1)),
            (Value::Integer(-2), Value::Bytes(x.to_vec())),
            (Value::Integer(-3), Value::Bytes(y.to_vec())),
        ]);
        let input = Value::Map(vec![
            (Value::Integer(1), cose_key),
            (Value::Integer(2), Value::Bytes(salt_enc)),
            (Value::Integer(3), Value::Bytes(salt_auth.to_vec())),
            (Value::Integer(4), Value::Integer(2)),
        ]);
        let extensions = Value::Map(vec![(Value::Text("hmac-secret".into()), input)]);
        (extensions, enc_key)
    }

    /// getAssertion for `credential_id` with hmac-secret; returns the decrypted output.
    fn hmac_secret_assertion(
        auth: &mut Authenticator<MockCallbacks>,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let (extensions, enc_key) = hmac_secret_extensions(auth, salt);
        let allow_list = Value::Array(vec![Value::Map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("id".into()),
                Value::Bytes(credential_id.to_vec()),
            ),
        ])]);
        let request = MapBuilder::new()
            .insert(req_keys::RP_ID, "example.com")
            .unwrap()
            .insert_bytes(req_keys::CLIENT_DATA_HASH, &[0x42; 32])
            .unwrap()
            .insert(req_keys::ALLOW_LIST, allow_list)
            .unwrap()
            .insert(req_keys::EXTENSIONS, extensions)
            .unwrap()
            .build()
            .unwrap();

        let response = handle(auth, &request).unwrap();
        let auth_data = MapParser::from_bytes(&response)
            .unwrap()
            .get_bytes(resp_keys::AUTH_DATA)
            .unwrap();
        // rpIdHash (32) || flags (1) || signCount (4) || extensions
        let outputs: Value = crate::cbor::decode(auth_data.get(37..)?).ok()?;
        let Value::Map(outputs) = outputs else {
            return None;
        };
        outputs.into_iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(name), Value::Bytes(enc)) if name == "hmac-secret" => {
                soft_fido2_crypto::pin_protocol::v2::decrypt(&enc_key, &enc).ok()
            }
            _ => None,
        })
    }

    fn wrapped_credential(auth: &Authenticator<MockCallbacks>) -> Vec<u8> {
        let (private_key, _) = soft_fido2_crypto::ecdsa::generate_keypair();
        let key = crate::key_provider::CredentialKey::software(crate::SecBytes::from_slice(
            private_key.as_slice(),
        ));
        auth.wrap_credential(&key, "example.com", crate::CoseAlgorithm::ES256.to_i32())
            .unwrap()
    }

    #[test]
    fn test_hmac_secret_rejects_silent_assertion() {
        let mut auth = Authenticator::new(AuthenticatorConfig::new(), MockCallbacks);
        let id = wrapped_credential(&auth);
        let (extensions, _) = hmac_secret_extensions(&mut auth, &[7u8; 32]);
        let allow_list = Value::Array(vec![Value::Map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (Value::Text("id".into()), Value::Bytes(id)),
        ])]);
        let options = Value::Map(vec![(Value::Text("up".into()), Value::Bool(false))]);
        let request = MapBuilder::new()
            .insert(req_keys::RP_ID, "example.com")
            .unwrap()
            .insert_bytes(req_keys::CLIENT_DATA_HASH, &[0x42; 32])
            .unwrap()
            .insert(req_keys::ALLOW_LIST, allow_list)
            .unwrap()
            .insert(req_keys::EXTENSIONS, extensions)
            .unwrap()
            .insert(req_keys::OPTIONS, options)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            handle(&mut auth, &request),
            Err(StatusCode::UnsupportedOption)
        );
    }

    #[test]
    fn test_hmac_secret_for_wrapped_credential() {
        let mut auth = Authenticator::new(AuthenticatorConfig::new(), MockCallbacks);
        let id = wrapped_credential(&auth);
        let salt = [7u8; 32];

        let output = hmac_secret_assertion(&mut auth, &id, &salt)
            .expect("wrapped credential must answer hmac-secret");
        assert_eq!(output.len(), 32);

        // Stable across assertions (and key agreements) for the same credential and salt.
        assert_eq!(
            hmac_secret_assertion(&mut auth, &id, &salt),
            Some(output.clone())
        );

        // A different credential gives a different secret.
        let other = wrapped_credential(&auth);
        assert_ne!(
            hmac_secret_assertion(&mut auth, &other, &salt),
            Some(output)
        );
    }

    #[test]
    fn test_wrapped_cred_random_is_per_credential_and_deterministic() {
        let auth = Authenticator::new(AuthenticatorConfig::new(), MockCallbacks);
        let a = wrapped_credential(&auth);
        let b = wrapped_credential(&auth);
        assert_eq!(
            auth.wrapped_cred_random(&a).as_slice(),
            auth.wrapped_cred_random(&a).as_slice()
        );
        assert_ne!(
            auth.wrapped_cred_random(&a).as_slice(),
            auth.wrapped_cred_random(&b).as_slice()
        );
        assert_eq!(auth.wrapped_cred_random(&a).as_slice().len(), 32);
    }

    #[test]
    fn test_build_authenticator_data() {
        let auth_data = build_authenticator_data(
            "example.com",
            true,
            false,
            CredentialBackupState::NotEligible,
            42,
            None,
        )
        .unwrap();

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
        let auth_data = build_authenticator_data(
            "example.com",
            true,
            true,
            CredentialBackupState::NotEligible,
            1,
            None,
        )
        .unwrap();

        // Check flags (UP=1, UV=1)
        assert_eq!(auth_data[32], 0x05); // 0x01 | 0x04
    }

    /// Callbacks holding one stored credential (everything else as `MockCallbacks`).
    struct OneCredential(crate::types::Credential);

    impl crate::callbacks::PlatformCallbacks for OneCredential {
        fn get_timestamp_ms(&self) -> u64 {
            MockCallbacks.get_timestamp_ms()
        }
    }

    impl crate::callbacks::UserInteractionCallbacks for OneCredential {
        fn request_up(
            &self,
            info: &str,
            user_name: Option<&str>,
            rp_id: &str,
        ) -> Result<crate::callbacks::UpResult> {
            MockCallbacks.request_up(info, user_name, rp_id)
        }

        fn request_uv(
            &self,
            info: &str,
            user_name: Option<&str>,
            rp_id: &str,
        ) -> Result<crate::callbacks::UvResult> {
            MockCallbacks.request_uv(info, user_name, rp_id)
        }

        fn select_credential(&self, rp_id: &str, user_names: &[String]) -> Result<usize> {
            MockCallbacks.select_credential(rp_id, user_names)
        }
    }

    impl crate::callbacks::CredentialStorageCallbacks for OneCredential {
        fn write_credential(&self, _credential: &crate::types::Credential) -> Result<()> {
            Ok(())
        }

        fn delete_credential(&self, _credential_id: &[u8]) -> Result<()> {
            Ok(())
        }

        fn read_credentials(
            &self,
            rp_id: &str,
            _user_id: Option<&[u8]>,
        ) -> Result<Vec<crate::types::Credential>> {
            Ok(if rp_id == self.0.rp_id {
                vec![self.0.clone()]
            } else {
                Vec::new()
            })
        }

        fn credential_exists(&self, credential_id: &[u8]) -> Result<bool> {
            Ok(credential_id == self.0.id.as_slice())
        }

        fn get_credential(&self, credential_id: &[u8]) -> Result<crate::types::Credential> {
            if credential_id == self.0.id.as_slice() {
                Ok(self.0.clone())
            } else {
                Err(StatusCode::NoCredentials)
            }
        }

        fn update_credential(&self, _credential: &crate::types::Credential) -> Result<()> {
            Ok(())
        }

        fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
            Ok(Vec::new())
        }

        fn credential_count(&self) -> Result<usize> {
            Ok(1)
        }
    }

    impl crate::callbacks::PinStorageCallbacks for OneCredential {
        fn load_pin_state(&self) -> Result<crate::types::PinState> {
            MockCallbacks.load_pin_state()
        }

        fn save_pin_state(&self, state: &crate::types::PinState) -> Result<()> {
            MockCallbacks.save_pin_state(state)
        }
    }

    /// getAssertion with hmac-secret (PIN/UV auth protocol 2) for `salt`; with a
    /// PIN token when `pin_token` is given. Returns the decrypted output and
    /// whether the UV flag was set.
    fn hmac_secret_assertion_with_optional_pin(
        auth: &mut Authenticator<OneCredential>,
        salt: &[u8; 32],
        pin_token: Option<&[u8; 32]>,
    ) -> (Vec<u8>, bool) {
        use soft_fido2_crypto::{ecdh::KeyPair, pin_protocol::v2};

        let auth_keypair = KeyPair::generate().unwrap();
        let auth_public = auth_keypair.public_key_bytes();
        auth.set_pin_protocol_keypair(2, auth_keypair);
        let platform = KeyPair::generate().unwrap();
        let shared = platform.shared_secret(&auth_public).unwrap();
        let enc_key = v2::derive_encryption_key(&shared);
        let salt_enc = v2::encrypt(&enc_key, salt).unwrap();
        let salt_auth = v2::authenticate(&v2::derive_hmac_key(&shared), &salt_enc);
        let (x, y) = platform.public_key_cose();
        let cose_key = Value::Map(vec![
            (Value::Integer(1), Value::Integer(2)),
            (Value::Integer(3), Value::Integer(-25)),
            (Value::Integer(-1), Value::Integer(1)),
            (Value::Integer(-2), Value::Bytes(x.to_vec())),
            (Value::Integer(-3), Value::Bytes(y.to_vec())),
        ]);
        let extensions = Value::Map(vec![(
            Value::Text("hmac-secret".into()),
            Value::Map(vec![
                (Value::Integer(1), cose_key),
                (Value::Integer(2), Value::Bytes(salt_enc)),
                (Value::Integer(3), Value::Bytes(salt_auth.to_vec())),
                (Value::Integer(4), Value::Integer(2)),
            ]),
        )]);
        let client_data_hash = [0x42u8; 32];
        let allow_list = Value::Array(vec![Value::Map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3])),
        ])]);
        let mut request = MapBuilder::new()
            .insert(req_keys::RP_ID, "example.com")
            .unwrap()
            .insert_bytes(req_keys::CLIENT_DATA_HASH, &client_data_hash)
            .unwrap()
            .insert(req_keys::ALLOW_LIST, allow_list)
            .unwrap()
            .insert(req_keys::EXTENSIONS, extensions)
            .unwrap();
        if let Some(token) = pin_token {
            request = request
                .insert_bytes(
                    req_keys::PIN_UV_AUTH_PARAM,
                    &v2::authenticate(token, &client_data_hash),
                )
                .unwrap()
                .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 2)
                .unwrap();
        }

        let response = handle(auth, &request.build().unwrap()).unwrap();
        let auth_data = MapParser::from_bytes(&response)
            .unwrap()
            .get_bytes(resp_keys::AUTH_DATA)
            .unwrap();
        let uv = auth_data[32] & crate::types::auth_data_flags::UV != 0;
        // rpIdHash (32) || flags (1) || signCount (4) || extensions
        let Value::Map(outputs) = crate::cbor::decode::<Value>(&auth_data[37..]).unwrap() else {
            panic!("no extension outputs");
        };
        let output = outputs
            .into_iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Text(name), Value::Bytes(enc)) if name == "hmac-secret" => {
                    v2::decrypt(&enc_key, &enc).ok()
                }
                _ => None,
            })
            .expect("hmac-secret output");
        (output, uv)
    }

    #[test]
    fn test_hmac_secret_differs_with_and_without_uv() {
        let cred_random = [9u8; 32];
        let (private_key, _) = soft_fido2_crypto::ecdsa::generate_keypair();
        let credential = crate::types::Credential {
            id: vec![1, 2, 3],
            rp_id: "example.com".to_string(),
            rp_name: None,
            user_id: vec![7],
            user_name: None,
            user_display_name: None,
            key: crate::key_provider::CredentialKey::software(crate::SecBytes::from_slice(
                private_key.as_slice(),
            )),
            algorithm: crate::CoseAlgorithm::ES256.to_i32(),
            sign_count: 0,
            created: 0,
            discoverable: true,
            backup_state: CredentialBackupState::NotEligible,
            cred_protect: 1,
            cred_random: Some(crate::SecBytes::from_array(cred_random)),
        };
        let mut auth = Authenticator::new(AuthenticatorConfig::new(), OneCredential(credential));
        auth.set_pin("1234").unwrap();
        let salt = [5u8; 32];

        // User presence only: CredRandomWithoutUV.
        let (without_uv, uv) = hmac_secret_assertion_with_optional_pin(&mut auth, &salt, None);
        assert!(!uv);
        let expected = soft_fido2_crypto::hmac_sha256(
            crate::extensions::select_cred_random(&cred_random, false).as_slice(),
            &salt,
        );
        assert_eq!(without_uv, expected.to_vec());

        // With the PIN: CredRandomWithUV (the stored value).
        let token = auth
            .get_pin_token(
                "1234",
                crate::pin_token::Permission::GetAssertion.to_u8(),
                Some("example.com".to_string()),
            )
            .unwrap();
        let (with_uv, uv) = hmac_secret_assertion_with_optional_pin(&mut auth, &salt, Some(&token));
        assert!(uv);
        assert_eq!(
            with_uv,
            soft_fido2_crypto::hmac_sha256(&cred_random, &salt).to_vec()
        );

        assert_ne!(with_uv, without_uv);
    }
}
