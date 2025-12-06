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

/// Response state tracker
#[derive(Debug, Default)]
struct ResponseState {
    up: bool,
    uv: bool,
    ep_att: bool,
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

    let extensions =
        if let Some(ext_value) = parser.get_opt::<crate::cbor::Value>(req_keys::EXTENSIONS)? {
            MakeCredentialExtensions::from_cbor(&ext_value)?
        } else {
            MakeCredentialExtensions::new()
        };

    let enterprise_attestation: Option<u8> = parser.get_opt(req_keys::ENTERPRISE_ATTESTATION)?;

    // Parse options (will process in step 5)
    let mut options = parse_options(&parser)?;

    // ===== Begin FIDO 2.2 Spec Algorithm =====

    // Step 1: Zero-length pinUvAuthParam backward compatibility check
    if (auth.config().options.pin_uv_auth_token
        || auth.config().options.client_pin.unwrap_or(false))
        && let Some(ref param) = pin_uv_auth_param
        && param.is_empty()
    {
        // Request evidence of user interaction
        let info = format!("Select authenticator for {}", rp.id);
        match auth
            .callbacks()
            .request_up(&info, user.name.as_deref(), &rp.id)?
        {
            UpResult::Denied => return Err(StatusCode::OperationDenied),
            UpResult::Timeout => return Err(StatusCode::OperationDenied),
            UpResult::Accepted => {
                // User interaction provided
                // Check if authenticator is protected by UV (PIN or biometrics)
                if !auth.is_protected_by_uv() {
                    return Err(StatusCode::PinNotSet);
                } else {
                    return Err(StatusCode::PinInvalid);
                }
            }
        }
    }

    // Step 2: If pinUvAuthParam is present, validate protocol
    if pin_uv_auth_param.is_some() {
        if let Some(protocol) = pin_uv_auth_protocol {
            if !auth.config().pin_uv_auth_protocols.contains(&protocol) {
                return Err(StatusCode::InvalidParameter);
            }
        } else {
            return Err(StatusCode::MissingParameter);
        }
    }

    // Step 3: Validate pubKeyCredParams and choose algorithm
    let alg = validate_and_choose_algorithm(auth, &pub_key_cred_params)?;

    // Step 4: Create response structure with "uv" and "up" bits initialized as false
    let mut response_state = ResponseState::default();

    // Step 5: Process options parameter
    // 5.1: If "uv" option is absent, treat as false (default)
    // (Already done by default)

    // 5.2: If pinUvAuthParam is present, treat "uv" option as false
    if pin_uv_auth_param.is_some() {
        options.uv = false;
    }

    // 5.3: If "uv" option is true, validate built-in UV support
    if options.uv {
        // Check if authenticator supports a built-in user verification method
        if auth.config().options.uv != Some(true) {
            return Err(StatusCode::InvalidOption);
        }
    }

    // 5.4: Process "rk" option
    if options.rk && !auth.config().options.rk {
        return Err(StatusCode::UnsupportedOption);
    }
    // Else: treat "rk" as false (already default)

    // 5.5: Process "up" option
    if !options.up {
        // "up" option false is invalid
        return Err(StatusCode::InvalidOption);
    }
    // Else: "up" is true (default)

    // Step 6: Handle alwaysUv option
    if auth.config().options.always_uv {
        // 6.1: Treat makeCredUvNotRqd as false
        // 6.2: Check if authenticator is protected by user verification
        // Protected by UV means either PIN is set OR built-in UV (biometrics) is enabled
        if auth.is_protected_by_uv() {
            // Protected by UV

            // 6.3: If pinUvAuthParam not present and uv is true, keep uv as true
            // (Already handled by options parsing)

            // 6.4: If pinUvAuthParam not present and uv is false/absent, require PUAT
            if pin_uv_auth_param.is_none() && !options.uv {
                if auth.config().options.client_pin.unwrap_or(false)
                    && !auth.config().options.pin_uv_auth_token
                // noMcGaPermissionsWithClientPin absent or false
                {
                    return Err(StatusCode::PuatRequired);
                } else {
                    return Err(StatusCode::OperationDenied);
                }
            }
        } else {
            // Not protected by UV
            if auth.config().options.client_pin.unwrap_or(false)
                && !auth.config().options.pin_uv_auth_token
            {
                return Err(StatusCode::PuatRequired);
            } else {
                return Err(StatusCode::OperationDenied);
            }
        }
    }

    // Step 7: Handle makeCredUvNotRqd option
    let authenticator_protected = auth.is_protected_by_uv();

    if auth.config().options.make_cred_uv_not_rqd {
        // makeCredUvNotRqd is true
        if authenticator_protected && !options.uv && pin_uv_auth_param.is_none() && options.rk {
            // Trying to create discoverable credential without UV
            if auth.config().options.client_pin.unwrap_or(false)
                && !auth.config().options.pin_uv_auth_token
            {
                return Err(StatusCode::PuatRequired);
            } else {
                return Err(StatusCode::OperationDenied);
            }
        }
    } else {
        // makeCredUvNotRqd is false or absent
        if authenticator_protected && !options.uv && pin_uv_auth_param.is_none() {
            // Creating any credential without UV when authenticator is protected
            if auth.config().options.client_pin.unwrap_or(false)
                && !auth.config().options.pin_uv_auth_token
            {
                return Err(StatusCode::PuatRequired);
            } else {
                return Err(StatusCode::OperationDenied);
            }
        }
    }

    // Step 9: Process enterpriseAttestation parameter
    if let Some(ep_att_value) = enterprise_attestation {
        if !auth.config().options.ep.unwrap_or(false) {
            return Err(StatusCode::InvalidParameter);
        }

        if ep_att_value != 1 && ep_att_value != 2 {
            return Err(StatusCode::InvalidOption);
        }

        // For now, we don't implement full enterprise attestation logic
        // Just validate the parameter
        response_state.ep_att = false; // Would be true if we returned enterprise attestation
    }

    // Step 10: Check if we can skip UV requirement
    let skip_uv = !options.rk
        && !options.uv
        && auth.config().options.make_cred_uv_not_rqd
        && pin_uv_auth_param.is_none();

    if skip_uv {
        // Go to Step 12 (generate credential)
        // UV bit already false from Step 4
    } else {
        // Step 11: Perform user verification if required
        perform_user_verification(
            auth,
            &mut response_state,
            &mut options,
            &pin_uv_auth_param,
            pin_uv_auth_protocol,
            &client_data_hash,
            &rp,
            &user,
        )?;
    }

    // Track if evidence of user interaction was provided in Step 11
    let evidence_from_step_11 = options.uv && pin_uv_auth_param.is_none() && response_state.uv;

    // Step 12: Check excludeList for excluded credentials
    check_exclude_list(
        auth,
        &exclude_list,
        &response_state,
        &pin_uv_auth_param,
        evidence_from_step_11,
    )?;

    // Step 13: If evidence provided in Step 11 via built-in UV
    if evidence_from_step_11 {
        response_state.up = true;
        // Go to Step 15
    } else {
        // Step 14: Collect user presence if "up" option is true
        if options.up {
            collect_user_presence(auth, &mut response_state, &pin_uv_auth_param, &rp, &user)?;
        }
    }

    // Step 14 (last): Clear flags and permissions
    auth.clear_pin_uv_auth_token_permissions_except_lbw();

    // Step 15: Process extensions
    let extension_outputs = extensions.build_outputs(auth.config().min_pin_length);

    // Step 16: Generate credential key pair
    let (private_key, public_key_bytes) = ecdsa::generate_keypair();

    // Step 17: Create credential (resident or non-resident)
    let credential_id = create_credential(
        auth,
        &options,
        &extensions,
        &response_state,
        private_key,
        &rp,
        &user,
        alg,
    )?;

    // Step 18: Generate attestation
    let cred_data = AttestationCredential {
        id: credential_id,
        public_key: public_key_bytes,
        algorithm: alg,
    };

    let auth_data = build_authenticator_data(
        &rp.id,
        response_state.up,
        response_state.uv,
        auth.config().aaguid,
        &cred_data,
        extension_outputs.as_ref(),
    )?;

    // Build attestation statement (self-attestation)
    let sig_data = [&auth_data[..], &client_data_hash[..]].concat();
    let signature = ecdsa::sign(&private_key, &sig_data)?;
    let att_stmt = build_attestation_statement(&signature, alg)?;

    // Build response
    let mut builder = MapBuilder::new()
        .insert(resp_keys::FMT, "packed")?
        .insert_bytes(resp_keys::AUTH_DATA, &auth_data)?
        .insert(resp_keys::ATT_STMT, att_stmt)?;

    if response_state.ep_att {
        builder = builder.insert(resp_keys::EP_ATT, true)?;
    }

    builder.build()
}

/// Step 3: Validate pubKeyCredParams and choose algorithm
fn validate_and_choose_algorithm<C: AuthenticatorCallbacks>(
    auth: &Authenticator<C>,
    params: &[PublicKeyCredentialParameters],
) -> Result<i32> {
    let mut chosen_alg: Option<i32> = None;

    for param in params {
        // Validate that type is present and correct
        if param.cred_type != "public-key" {
            return Err(StatusCode::InvalidCbor);
        }

        // If this algorithm is supported and we haven't chosen one yet
        if chosen_alg.is_none() && auth.config().algorithms.contains(&param.alg) {
            chosen_alg = Some(param.alg);
        }
    }

    chosen_alg.ok_or(StatusCode::UnsupportedAlgorithm)
}

/// Step 11: Perform user verification
#[allow(clippy::too_many_arguments)]
fn perform_user_verification<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    response_state: &mut ResponseState,
    options: &mut MakeCredentialOptions,
    pin_uv_auth_param: &Option<Vec<u8>>,
    pin_uv_auth_protocol: Option<u8>,
    client_data_hash: &[u8],
    rp: &RelyingParty,
    user: &User,
) -> Result<()> {
    let authenticator_protected = auth.is_protected_by_uv();

    if authenticator_protected {
        if let Some(pin_auth) = pin_uv_auth_param {
            // Step 11.1: Verify pinUvAuthParam
            let protocol = pin_uv_auth_protocol.ok_or(StatusCode::MissingParameter)?;
            auth.verify_pin_uv_auth_param(protocol, pin_auth, client_data_hash)?;

            // Verify mc permission
            auth.verify_pin_uv_auth_token(
                crate::pin_token::Permission::MakeCredential,
                Some(&rp.id),
            )?;

            // Get userVerifiedFlagValue
            let user_verified = get_user_verified_flag_value(auth);

            if !user_verified {
                return Err(StatusCode::PinAuthInvalid);
            }

            if user_verified {
                response_state.uv = true;
            }

            // Associate RP ID with token if not already associated
            // (This is handled internally by verify_pin_uv_auth_token)

            return Ok(());
        }

        if options.uv {
            // Step 11.2: Perform built-in user verification
            let internal_retry = true;
            let uv_state = perform_built_in_uv(auth, internal_retry, rp, user)?;

            if uv_state {
                response_state.uv = true;
            }

            return Ok(());
        }
    }

    // Note: If we reach here, authenticator is not protected or UV not requested
    // UV bit remains false from Step 4
    Ok(())
}

/// Step 11.2: Perform built-in user verification
fn perform_built_in_uv<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    _internal_retry: bool,
    rp: &RelyingParty,
    user: &User,
) -> Result<bool> {
    let info = format!("Verify for {}", rp.id);
    match auth
        .callbacks()
        .request_uv(&info, user.name.as_deref(), &rp.id)?
    {
        UvResult::Accepted | UvResult::AcceptedWithUp => Ok(true),
        UvResult::Timeout => Err(StatusCode::UserActionTimeout),
        UvResult::Denied => {
            // Check retry counter
            if auth.uv_retries() == 0 {
                return Err(StatusCode::PinBlocked);
            }

            if auth.config().options.client_pin.unwrap_or(false)
                && !auth.config().options.pin_uv_auth_token
            {
                return Err(StatusCode::PuatRequired);
            }

            Err(StatusCode::OperationDenied)
        }
    }
}

/// Get user verified flag value from PIN token state
pub(crate) fn get_user_verified_flag_value<C: AuthenticatorCallbacks>(
    _auth: &Authenticator<C>,
) -> bool {
    // Per spec, if PIN token was obtained via getPinToken/getPinUvAuthTokenUsingPinWithPermissions,
    // then UV flag should be true
    // For simplicity, we return true when a valid PIN token exists
    true
}

/// Get user present flag value
pub(crate) fn get_user_present_flag_value<C: AuthenticatorCallbacks>(
    auth: &Authenticator<C>,
) -> bool {
    // Check if there's a valid PIN token with recent usage
    // For simplicity, return true if token exists
    auth.pin_retries() > 0
}

/// Step 12: Check excludeList for credential exclusion
fn check_exclude_list<C: AuthenticatorCallbacks>(
    auth: &Authenticator<C>,
    exclude_list: &Option<Vec<PublicKeyCredentialDescriptor>>,
    response_state: &ResponseState,
    pin_uv_auth_param: &Option<Vec<u8>>,
    evidence_from_step_11: bool,
) -> Result<()> {
    if let Some(exclude) = exclude_list {
        for cred_desc in exclude {
            if let Ok(true) = auth.callbacks().credential_exists(&cred_desc.id)
                && let Ok(cred) = auth.callbacks().get_credential(&cred_desc.id)
            {
                // Check credProtect level
                if cred.cred_protect != CredProtect::UserVerificationRequired as u8 {
                    // Not UV required - need UP before returning error
                    let mut user_present = false;

                    if pin_uv_auth_param.is_some() {
                        user_present = get_user_present_flag_value(auth);
                    } else if evidence_from_step_11 {
                        user_present = true;
                    }

                    if !user_present {
                        // Wait for user presence - but we can't actually wait here
                        // Return error regardless
                        return Err(StatusCode::CredentialExcluded);
                    }

                    return Err(StatusCode::CredentialExcluded);
                } else {
                    // UV required credential
                    if response_state.uv {
                        let mut user_present = false;

                        if pin_uv_auth_param.is_some() {
                            user_present = get_user_present_flag_value(auth);
                        } else if evidence_from_step_11 {
                            user_present = true;
                        }

                        if !user_present {
                            return Err(StatusCode::CredentialExcluded);
                        }

                        return Err(StatusCode::CredentialExcluded);
                    }
                    // Else: UV not collected, remove from list and continue
                    // (We just continue to next credential)
                }
            }
        }
    }

    Ok(())
}

/// Step 14: Collect user presence
fn collect_user_presence<C: AuthenticatorCallbacks>(
    auth: &Authenticator<C>,
    response_state: &mut ResponseState,
    pin_uv_auth_param: &Option<Vec<u8>>,
    rp: &RelyingParty,
    user: &User,
) -> Result<()> {
    if pin_uv_auth_param.is_some() {
        let user_present = get_user_present_flag_value(auth);

        if !user_present {
            // Request user interaction
            let info = format!("Register with {}", rp.id);
            match auth
                .callbacks()
                .request_up(&info, user.name.as_deref(), &rp.id)?
            {
                UpResult::Accepted => {}
                UpResult::Denied => return Err(StatusCode::OperationDenied),
                UpResult::Timeout => return Err(StatusCode::OperationDenied),
            }
        }
    } else {
        // pinUvAuthParam not present
        if !response_state.up {
            // Request user interaction
            let info = format!("Register with {}", rp.id);
            match auth
                .callbacks()
                .request_up(&info, user.name.as_deref(), &rp.id)?
            {
                UpResult::Accepted => {}
                UpResult::Denied => return Err(StatusCode::OperationDenied),
                UpResult::Timeout => return Err(StatusCode::OperationDenied),
            }
        }
    }

    response_state.up = true;
    Ok(())
}

/// Step 17: Create credential (resident or non-resident)
#[allow(clippy::too_many_arguments)]
fn create_credential<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    options: &MakeCredentialOptions,
    extensions: &MakeCredentialExtensions,
    response_state: &ResponseState,
    private_key: [u8; 32],
    rp: &RelyingParty,
    user: &User,
    algorithm: i32,
) -> Result<Vec<u8>> {
    if options.rk || auth.config().force_resident_keys {
        // Create discoverable credential
        let id = generate_credential_id();

        // Determine credProtect level
        let cred_protect_value = extensions
            .cred_protect
            .map(|p| p.to_u8())
            .unwrap_or_else(|| {
                if response_state.uv {
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
            algorithm,
            sign_count: 0,
            created: current_timestamp(),
            discoverable: true,
            cred_protect: cred_protect_value,
        };

        auth.callbacks().write_credential(&credential)?;

        Ok(id)
    } else {
        // Create non-discoverable credential
        auth.wrap_credential(&private_key, &rp.id, algorithm)
    }
}

/// Parse user object from the request
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
        up: true,
        uv: false,
    };

    if let Some(crate::cbor::Value::Map(opts)) = opts_map {
        for (k, v) in opts {
            if let (crate::cbor::Value::Text(key), crate::cbor::Value::Bool(val)) = (k, v) {
                match key.as_str() {
                    "rk" => options.rk = val,
                    "up" => options.up = val,
                    "uv" => options.uv = val,
                    _ => {} // Ignore unknown options per spec
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

    #[test]
    fn test_validate_algorithm_selection() {
        use crate::authenticator::{Authenticator, AuthenticatorConfig, AuthenticatorOptions};

        // Mock callbacks for testing
        struct MockCallbacks;

        impl crate::callbacks::UserInteractionCallbacks for MockCallbacks {
            fn request_up(
                &self,
                _info: &str,
                _user_name: Option<&str>,
                _rp_id: &str,
            ) -> Result<crate::callbacks::UpResult> {
                Ok(crate::callbacks::UpResult::Accepted)
            }

            fn request_uv(
                &self,
                _info: &str,
                _user_name: Option<&str>,
                _rp_id: &str,
            ) -> Result<crate::callbacks::UvResult> {
                Ok(crate::callbacks::UvResult::Accepted)
            }

            fn select_credential(&self, _rp_id: &str, _user_names: &[String]) -> Result<usize> {
                Ok(0)
            }
        }

        impl crate::callbacks::CredentialStorageCallbacks for MockCallbacks {
            fn write_credential(&self, _credential: &crate::types::Credential) -> Result<()> {
                Ok(())
            }

            fn delete_credential(&self, _credential_id: &[u8]) -> Result<()> {
                Ok(())
            }

            fn read_credentials(
                &self,
                _rp_id: &str,
                _user_id: Option<&[u8]>,
            ) -> Result<Vec<crate::types::Credential>> {
                Ok(vec![])
            }

            fn credential_exists(&self, _credential_id: &[u8]) -> Result<bool> {
                Ok(false)
            }

            fn get_credential(&self, _credential_id: &[u8]) -> Result<crate::types::Credential> {
                Err(StatusCode::NoCredentials)
            }

            fn update_credential(&self, _credential: &crate::types::Credential) -> Result<()> {
                Ok(())
            }

            fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
                Ok(vec![])
            }

            fn credential_count(&self) -> Result<usize> {
                Ok(0)
            }
        }

        let config = AuthenticatorConfig::new()
            .with_algorithms(vec![-7, -8]) // ES256, EdDSA
            .with_options(AuthenticatorOptions::new());
        let auth = Authenticator::new(config, MockCallbacks);

        let params = vec![
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -257, // RS256 (not supported)
            },
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -8, // EdDSA (supported)
            },
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256 (supported)
            },
        ];

        // Should choose the first supported algorithm (EdDSA in this case)
        let result = validate_and_choose_algorithm(&auth, &params);
        assert_eq!(result.unwrap(), -8);
    }

    #[test]
    fn test_validate_algorithm_none_supported() {
        use crate::authenticator::{Authenticator, AuthenticatorConfig, AuthenticatorOptions};

        // Mock callbacks for testing
        struct MockCallbacks;

        impl crate::callbacks::UserInteractionCallbacks for MockCallbacks {
            fn request_up(
                &self,
                _info: &str,
                _user_name: Option<&str>,
                _rp_id: &str,
            ) -> Result<crate::callbacks::UpResult> {
                Ok(crate::callbacks::UpResult::Accepted)
            }

            fn request_uv(
                &self,
                _info: &str,
                _user_name: Option<&str>,
                _rp_id: &str,
            ) -> Result<crate::callbacks::UvResult> {
                Ok(crate::callbacks::UvResult::Accepted)
            }

            fn select_credential(&self, _rp_id: &str, _user_names: &[String]) -> Result<usize> {
                Ok(0)
            }
        }

        impl crate::callbacks::CredentialStorageCallbacks for MockCallbacks {
            fn write_credential(&self, _credential: &crate::types::Credential) -> Result<()> {
                Ok(())
            }

            fn delete_credential(&self, _credential_id: &[u8]) -> Result<()> {
                Ok(())
            }

            fn read_credentials(
                &self,
                _rp_id: &str,
                _user_id: Option<&[u8]>,
            ) -> Result<Vec<crate::types::Credential>> {
                Ok(vec![])
            }

            fn credential_exists(&self, _credential_id: &[u8]) -> Result<bool> {
                Ok(false)
            }

            fn get_credential(&self, _credential_id: &[u8]) -> Result<crate::types::Credential> {
                Err(StatusCode::NoCredentials)
            }

            fn update_credential(&self, _credential: &crate::types::Credential) -> Result<()> {
                Ok(())
            }

            fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
                Ok(vec![])
            }

            fn credential_count(&self) -> Result<usize> {
                Ok(0)
            }
        }

        let config = AuthenticatorConfig::new()
            .with_algorithms(vec![-7]) // Only ES256
            .with_options(AuthenticatorOptions::new());
        let auth = Authenticator::new(config, MockCallbacks);

        let params = vec![
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -257, // RS256 (not supported)
            },
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -8, // EdDSA (not supported)
            },
        ];

        let result = validate_and_choose_algorithm(&auth, &params);
        assert_eq!(result, Err(StatusCode::UnsupportedAlgorithm));
    }
}
