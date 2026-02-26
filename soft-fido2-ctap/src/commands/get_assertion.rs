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
    commands::make_credential::get_user_verified_flag_value,
    extensions::{GetAssertionExtensions, compute_hmac_secret},
    status::{Result, StatusCode},
    types::PublicKeyCredentialDescriptor,
};

use soft_fido2_crypto::ecdsa;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;

    // ===== Parse all parameters first =====

    // Required parameters
    let rp_id: String = parser.get(req_keys::RP_ID)?;

    // Validate RP ID is not empty (empty RP ID could match unintended credentials)
    if rp_id.is_empty() {
        return Err(StatusCode::InvalidParameter);
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

    // Step 4.1: If "uv" option is absent, treat as false (default)
    // This is already handled by parse_options() which defaults uv to false

    // Step 4.2: If pinUvAuthParam is present, treat "uv" option as false
    if pin_uv_auth_param.is_some() {
        options.uv = false;
    }

    // Step 4.3: If "uv" option is present and true
    if options.uv {
        // Check if authenticator supports built-in user verification
        if !auth.config().options.uv.unwrap_or(false) {
            return Err(StatusCode::InvalidOption);
        }
        // Check if built-in user verification method is enabled
        // Built-in UV refers to biometric methods (fingerprint, face recognition, etc.)
        if !auth.has_built_in_uv_enabled() {
            return Err(StatusCode::InvalidOption);
        }
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
                    // UV failed - decrement retry counter
                    auth.decrement_uv_retries();

                    // Check if UV is now blocked
                    if auth.is_uv_blocked() {
                        return Err(StatusCode::UvBlocked);
                    }

                    // Check if clientPin is supported and noMcGaPermissionsWithClientPin is absent/false
                    if auth.config().options.client_pin.unwrap_or(false)
                        && !auth.config().options.pin_uv_auth_token
                    {
                        return Err(StatusCode::PuatRequired);
                    }

                    // Otherwise return operation denied
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
            if let Ok((private_key, cred_rp_id, algorithm)) = auth.unwrap_credential(&desc.id)
                && cred_rp_id == rp_id
            {
                // Create a temporary credential from unwrapped data
                // Note: Non-discoverable credentials don't support hmac-secret
                // because cred_random isn't stored in the wrapped credential
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
                    cred_random: None,   // Not supported for non-resident creds
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
            credentials.sort_by(|a, b| b.created.cmp(&a.created));

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
    if extensions.has_hmac_secret() {
        #[cfg(feature = "std")]
        eprintln!("  [DEBUG] hmac-secret extension requested");
        if let Some(hmac_input) = extensions.get_hmac_secret() {
            #[cfg(feature = "std")]
            eprintln!(
                "  [DEBUG] hmac-secret input parsed: keyAgreement={} bytes, saltEnc={} bytes, protocol={}",
                hmac_input.key_agreement.len(),
                hmac_input.salt_enc.len(),
                hmac_input.pin_uv_auth_protocol
            );

            // Get the stored keypair for the PIN protocol version
            // This keypair was established via getKeyAgreement clientPIN subcommand
            let keypair = auth.get_pin_protocol_keypair(hmac_input.pin_uv_auth_protocol);

            if let Some(auth_keypair) = keypair {
                #[cfg(feature = "std")]
                eprintln!(
                    "  [DEBUG] ✓ Found stored keypair for protocol {}",
                    hmac_input.pin_uv_auth_protocol
                );

                if let Some(cred_random) = &selected_cred.cred_random {
                    #[cfg(feature = "std")]
                    eprintln!("  [DEBUG] cred_random present, computing hmac-secret...");

                    // Compute hmac-secret output using the stored keypair
                    if let Some(encrypted_output) =
                        compute_hmac_secret(hmac_input, cred_random.as_slice(), auth_keypair)
                    {
                        #[cfg(feature = "std")]
                        eprintln!(
                            "  [DEBUG] ✓ hmac-secret computed successfully, output={} bytes",
                            encrypted_output.len()
                        );

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
                    } else {
                        #[cfg(feature = "std")]
                        eprintln!("  [DEBUG] ✗ hmac-secret computation FAILED");
                    }
                } else {
                    #[cfg(feature = "std")]
                    eprintln!("  [DEBUG] ✗ cred_random is None");
                }
            } else {
                #[cfg(feature = "std")]
                eprintln!(
                    "  [DEBUG] ✗ No stored keypair for protocol {} - getKeyAgreement not called?",
                    hmac_input.pin_uv_auth_protocol
                );
            }
        } else {
            #[cfg(feature = "std")]
            eprintln!("  [DEBUG] ✗ hmac-secret input parsing failed or missing");
        }
    } else {
        #[cfg(feature = "std")]
        eprintln!("  [DEBUG] hmac-secret extension NOT requested");
    }

    // Step 13: Attestation statement generation
    // Simplified: Only generate attestation if attestationFormatsPreference is present and not ["none"]
    // For now, we skip attestation generation (most common case)
    // TODO: Implement full attestation statement generation

    // Step 14: Sign clientDataHash with authData
    // Increment sign count (unless constant_sign_count is enabled)
    let new_sign_count = if auth.config().constant_sign_count {
        selected_cred.sign_count // Keep counter constant for privacy
    } else {
        selected_cred.sign_count + 1 // Normal incrementing behavior
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
        new_sign_count,
        extension_outputs.as_ref(),
    )?;

    // Generate signature
    let sig_data = [&auth_data[..], &client_data_hash[..]].concat();

    let key_bytes = selected_cred.private_key.as_slice();
    if key_bytes.len() != 32 {
        return Err(StatusCode::InvalidCredential);
    }

    // Copy private key to Zeroizing wrapper (zeroed on drop)
    let priv_key_array = Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key_bytes);
        arr
    });

    let signature = ecdsa::sign(&priv_key_array, &sig_data)?;

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
        // Note: For authenticatorGetNextAssertion support, we would need to:
        // - Store the remaining credentials
        // - Start a timer
        // - Track credential counter
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
