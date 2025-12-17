//! authenticatorClientPIN command
//!
//! Handles PIN management operations including:
//! - Getting PIN retry counter
//! - Getting key agreement
//! - Setting PIN
//! - Changing PIN
//! - Getting PIN token
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorClientPIN>

use crate::{
    authenticator::Authenticator,
    callbacks::AuthenticatorCallbacks,
    cbor::{MapBuilder, MapParser},
    status::{Result, StatusCode},
};

use alloc::{string::String, vec::Vec};
use zeroize::Zeroizing;

/// ClientPIN subcommand codes
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum SubCommand {
    GetPinRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUvRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

/// Request keys
#[allow(dead_code)]
mod req_keys {
    pub const PIN_UV_AUTH_PROTOCOL: i32 = 0x01;
    pub const SUBCOMMAND: i32 = 0x02;
    pub const KEY_AGREEMENT: i32 = 0x03;
    pub const PIN_UV_AUTH_PARAM: i32 = 0x04;
    pub const NEW_PIN_ENC: i32 = 0x05;
    pub const PIN_HASH_ENC: i32 = 0x06;
    pub const PERMISSIONS: i32 = 0x09;
    pub const RP_ID: i32 = 0x0A;
}

/// Response keys
#[allow(dead_code)]
mod resp_keys {
    pub const KEY_AGREEMENT: i32 = 0x01;
    pub const PIN_UV_AUTH_TOKEN: i32 = 0x02;
    pub const PIN_RETRIES: i32 = 0x03;
    pub const POWER_CYCLE_STATE: i32 = 0x04;
    pub const UV_RETRIES: i32 = 0x05;
}

/// Handle authenticatorClientPIN command
///
/// Implements the CTAP PIN protocol for secure PIN management.
/// Supports both PIN protocol V1 (AES-256-CBC) and V2 (HMAC-only).
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;

    let subcommand: u8 = parser.get(req_keys::SUBCOMMAND)?;

    match subcommand {
        0x01 => handle_get_pin_retries(auth),
        0x02 => handle_get_key_agreement(auth, &parser),
        0x03 => handle_set_pin(auth, &parser),
        0x04 => handle_change_pin(auth, &parser),
        0x05 => handle_get_pin_token(auth, &parser),
        0x06 => handle_get_pin_uv_auth_token_using_uv_with_permissions(auth, &parser),
        0x07 => handle_get_uv_retries(auth),
        0x09 => handle_get_pin_uv_auth_token_using_pin_with_permissions(auth, &parser),
        _ => Err(StatusCode::InvalidSubcommand),
    }
}

/// Handle getPinRetries subcommand
fn handle_get_pin_retries<C: AuthenticatorCallbacks>(auth: &Authenticator<C>) -> Result<Vec<u8>> {
    MapBuilder::new()
        .insert(resp_keys::PIN_RETRIES, auth.pin_retries() as i32)?
        .build()
}

/// Handle getKeyAgreement subcommand
fn handle_get_key_agreement<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    let protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;

    // Validate protocol version
    if protocol != 1 && protocol != 2 {
        return Err(StatusCode::InvalidParameter);
    }

    // Generate ephemeral ECDH key pair
    let keypair = soft_fido2_crypto::ecdh::KeyPair::generate()?;
    let (x, y) = keypair.public_key_cose();

    // Store keypair for later use in PIN operations
    auth.set_pin_protocol_keypair(protocol, keypair);

    // Build COSE key
    let key_agreement = MapBuilder::new()
        .insert(1, 2)? // kty: EC2
        .insert(3, -25)? // alg: ECDH-ES + HKDF-256
        .insert(-1, 1)? // crv: P-256
        .insert_bytes(-2, &x)? // x coordinate
        .insert_bytes(-3, &y)? // y coordinate
        .build_value()?;

    MapBuilder::new()
        .insert(resp_keys::KEY_AGREEMENT, key_agreement)?
        .build()
}

/// Handle setPin subcommand
fn handle_set_pin<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    if auth.is_pin_set() {
        return Err(StatusCode::PinAuthInvalid);
    }

    let protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let new_pin_enc: Vec<u8> = parser.get_bytes(req_keys::NEW_PIN_ENC)?;
    let pin_uv_auth_param: Vec<u8> = parser.get_bytes(req_keys::PIN_UV_AUTH_PARAM)?;

    // Get platform's key agreement key (COSE_Key format)
    let key_agreement: crate::cbor::Value = parser.get(req_keys::KEY_AGREEMENT)?;
    let platform_public_key = parse_cose_key(&key_agreement)?;

    // Get stored keypair for this protocol
    let keypair = auth
        .get_pin_protocol_keypair(protocol)
        .ok_or(StatusCode::PinAuthInvalid)?;

    // Compute shared secret
    let shared_secret = keypair.shared_secret(&platform_public_key)?;

    // Derive keys based on protocol version
    let (enc_key, hmac_key) = match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret),
        2 => {
            let enc = soft_fido2_crypto::pin_protocol::v2::derive_encryption_key(&shared_secret);
            let hmac = soft_fido2_crypto::pin_protocol::v2::derive_hmac_key(&shared_secret);
            (enc, hmac)
        }
        _ => return Err(StatusCode::InvalidParameter),
    };

    // Verify pinUvAuthParam = HMAC(hmac_key, new_pin_enc)
    // Protocol v1 uses 16 bytes, v2 uses 32 bytes
    let valid = match protocol {
        1 => {
            if pin_uv_auth_param.len() != 16 {
                return Err(StatusCode::PinAuthInvalid);
            }
            let expected_mac: [u8; 16] = pin_uv_auth_param
                .as_slice()
                .try_into()
                .map_err(|_| StatusCode::PinAuthInvalid)?;
            soft_fido2_crypto::pin_protocol::v1::verify(&hmac_key, &new_pin_enc, &expected_mac)
        }
        2 => {
            if pin_uv_auth_param.len() != 32 {
                return Err(StatusCode::PinAuthInvalid);
            }
            let expected_mac: [u8; 32] = pin_uv_auth_param
                .as_slice()
                .try_into()
                .map_err(|_| StatusCode::PinAuthInvalid)?;
            soft_fido2_crypto::pin_protocol::v2::verify(&hmac_key, &new_pin_enc, &expected_mac)
        }
        _ => return Err(StatusCode::InvalidParameter),
    };

    if !valid {
        return Err(StatusCode::PinAuthInvalid);
    }

    // Decrypt new PIN
    let decrypted_pin: Zeroizing<Vec<u8>> = Zeroizing::new(match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::decrypt(&enc_key, &new_pin_enc)?,
        2 => soft_fido2_crypto::pin_protocol::v2::decrypt(&enc_key, &new_pin_enc)?,
        _ => return Err(StatusCode::InvalidParameter),
    });

    // PIN is padded to 64 bytes with trailing zeros, find actual length
    let pin_len = decrypted_pin
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(decrypted_pin.len());
    let pin_str = core::str::from_utf8(&decrypted_pin[..pin_len])
        .map_err(|_| StatusCode::PinPolicyViolation)?;

    // Set the PIN (this validates length)
    auth.set_pin(pin_str)?;

    MapBuilder::new().build()
}

/// Handle changePin subcommand
fn handle_change_pin<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    if !auth.is_pin_set() {
        return Err(StatusCode::PinNotSet);
    }

    let protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let pin_hash_enc: Vec<u8> = parser.get_bytes(req_keys::PIN_HASH_ENC)?;
    let new_pin_enc: Vec<u8> = parser.get_bytes(req_keys::NEW_PIN_ENC)?;
    let pin_uv_auth_param: Vec<u8> = parser.get_bytes(req_keys::PIN_UV_AUTH_PARAM)?;

    // Get platform's key agreement key
    let key_agreement: crate::cbor::Value = parser.get(req_keys::KEY_AGREEMENT)?;
    let platform_public_key = parse_cose_key(&key_agreement)?;

    // Get stored keypair for this protocol
    let keypair = auth
        .get_pin_protocol_keypair(protocol)
        .ok_or(StatusCode::PinAuthInvalid)?;

    // Compute shared secret
    let shared_secret = keypair.shared_secret(&platform_public_key)?;

    // Derive keys based on protocol version
    let (enc_key, hmac_key) = match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret),
        2 => {
            let enc = soft_fido2_crypto::pin_protocol::v2::derive_encryption_key(&shared_secret);
            let hmac = soft_fido2_crypto::pin_protocol::v2::derive_hmac_key(&shared_secret);
            (enc, hmac)
        }
        _ => return Err(StatusCode::InvalidParameter),
    };

    // Verify pinUvAuthParam = HMAC(hmac_key, new_pin_enc || pin_hash_enc)
    // Protocol v1 uses 16 bytes, v2 uses 32 bytes
    let mut verify_data = new_pin_enc.clone();
    verify_data.extend_from_slice(&pin_hash_enc);

    let valid = match protocol {
        1 => {
            if pin_uv_auth_param.len() != 16 {
                return Err(StatusCode::PinAuthInvalid);
            }
            let expected_mac: [u8; 16] = pin_uv_auth_param
                .as_slice()
                .try_into()
                .map_err(|_| StatusCode::PinAuthInvalid)?;
            soft_fido2_crypto::pin_protocol::v1::verify(&hmac_key, &verify_data, &expected_mac)
        }
        2 => {
            if pin_uv_auth_param.len() != 32 {
                return Err(StatusCode::PinAuthInvalid);
            }
            let expected_mac: [u8; 32] = pin_uv_auth_param
                .as_slice()
                .try_into()
                .map_err(|_| StatusCode::PinAuthInvalid)?;
            soft_fido2_crypto::pin_protocol::v2::verify(&hmac_key, &verify_data, &expected_mac)
        }
        _ => return Err(StatusCode::InvalidParameter),
    };

    if !valid {
        return Err(StatusCode::PinAuthInvalid);
    }

    // Decrypt and verify old PIN hash (first 16 bytes of SHA-256(PIN))
    let decrypted_pin_hash: Zeroizing<Vec<u8>> = Zeroizing::new(match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::decrypt(&enc_key, &pin_hash_enc)?,
        2 => soft_fido2_crypto::pin_protocol::v2::decrypt(&enc_key, &pin_hash_enc)?,
        _ => return Err(StatusCode::InvalidParameter),
    });

    // Verify old PIN hash matches (first 16 bytes per CTAP spec)
    if decrypted_pin_hash.len() < 16 {
        return Err(StatusCode::PinAuthInvalid);
    }

    // Use constant-time comparison for PIN hash verification
    if !auth.verify_pin_hash_first_16(&decrypted_pin_hash) {
        // Decrement retry counter on failed verification
        auth.decrement_pin_retries()?;
        if auth.is_pin_blocked() {
            return Err(StatusCode::PinBlocked);
        }
        return Err(StatusCode::PinInvalid);
    }

    // Decrypt new PIN
    let decrypted_new_pin: Zeroizing<Vec<u8>> = Zeroizing::new(match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::decrypt(&enc_key, &new_pin_enc)?,
        2 => soft_fido2_crypto::pin_protocol::v2::decrypt(&enc_key, &new_pin_enc)?,
        _ => return Err(StatusCode::InvalidParameter),
    });

    // PIN is padded to 64 bytes with trailing zeros, find actual length
    let pin_len = decrypted_new_pin
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(decrypted_new_pin.len());
    let new_pin_str = core::str::from_utf8(&decrypted_new_pin[..pin_len])
        .map_err(|_| StatusCode::PinPolicyViolation)?;

    // Set new PIN (old PIN was already verified above)
    auth.set_pin(new_pin_str)?;

    MapBuilder::new().build()
}

/// Handle getPinToken subcommand (CTAP 2.0)
fn handle_get_pin_token<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    if !auth.is_pin_set() {
        return Err(StatusCode::PinNotSet);
    }

    // Check if PIN is blocked
    if auth.is_pin_blocked() {
        return Err(StatusCode::PinBlocked);
    }

    let protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let pin_hash_enc: Vec<u8> = parser.get_bytes(req_keys::PIN_HASH_ENC)?;

    // Get platform's key agreement key
    let key_agreement: crate::cbor::Value = parser.get(req_keys::KEY_AGREEMENT)?;
    let platform_public_key = parse_cose_key(&key_agreement)?;

    // Get stored keypair for this protocol
    let keypair = auth
        .get_pin_protocol_keypair(protocol)
        .ok_or(StatusCode::PinAuthInvalid)?;

    // Compute shared secret
    let shared_secret = keypair.shared_secret(&platform_public_key)?;

    // Derive keys based on protocol version
    let (enc_key, _hmac_key) = match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret),
        2 => {
            let enc = soft_fido2_crypto::pin_protocol::v2::derive_encryption_key(&shared_secret);
            let hmac = soft_fido2_crypto::pin_protocol::v2::derive_hmac_key(&shared_secret);
            (enc, hmac)
        }
        _ => return Err(StatusCode::InvalidParameter),
    };

    // Decrypt PIN hash (first 16 bytes of SHA-256(PIN))
    let decrypted_pin_hash: Zeroizing<Vec<u8>> = Zeroizing::new(match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::decrypt(&enc_key, &pin_hash_enc)?,
        2 => soft_fido2_crypto::pin_protocol::v2::decrypt(&enc_key, &pin_hash_enc)?,
        _ => return Err(StatusCode::InvalidParameter),
    });

    if decrypted_pin_hash.len() < 16 {
        return Err(StatusCode::PinAuthInvalid);
    }

    // Verify PIN hash (first 16 bytes per CTAP spec)
    if !auth.verify_pin_hash_first_16(&decrypted_pin_hash) {
        auth.decrement_pin_retries()?;
        if auth.is_pin_blocked() {
            return Err(StatusCode::PinBlocked);
        }
        return Err(StatusCode::PinInvalid);
    }

    // PIN verified - reset retry counter
    auth.reset_pin_retries()?;

    // Get PIN token (CTAP 2.0 uses all permissions)
    let token = auth.get_pin_token_after_verification(0xFF, None)?;

    // Encrypt the token
    let encrypted_token = match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &token)?,
        2 => soft_fido2_crypto::pin_protocol::v2::encrypt(&enc_key, &token)?,
        _ => return Err(StatusCode::InvalidParameter),
    };

    MapBuilder::new()
        .insert_bytes(resp_keys::PIN_UV_AUTH_TOKEN, &encrypted_token)?
        .build()
}

/// Handle getPinUvAuthTokenUsingPinWithPermissions subcommand (CTAP 2.1)
///
/// This is the CTAP 2.1 version that adds permissions and rpId support.
fn handle_get_pin_uv_auth_token_using_pin_with_permissions<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    if !auth.is_pin_set() {
        return Err(StatusCode::PinNotSet);
    }

    let protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let pin_hash_enc: Vec<u8> = parser.get_bytes(req_keys::PIN_HASH_ENC)?;
    let permissions: u8 = parser.get(req_keys::PERMISSIONS)?;
    let rp_id: Option<String> = parser.get_opt(req_keys::RP_ID)?;

    // Get platform's key agreement key
    let key_agreement: crate::cbor::Value = parser.get(req_keys::KEY_AGREEMENT)?;
    let platform_public_key = parse_cose_key(&key_agreement)?;

    // Get stored keypair for this protocol
    let keypair = match auth.get_pin_protocol_keypair(protocol) {
        Some(kp) => kp,
        None => {
            // getKeyAgreement must be called first to establish the ephemeral keypair
            return Err(StatusCode::PinAuthInvalid);
        }
    };

    // Compute shared secret
    let shared_secret = keypair.shared_secret(&platform_public_key)?;

    // Derive keys based on protocol version
    let (enc_key, _hmac_key) = match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret),
        2 => {
            let enc = soft_fido2_crypto::pin_protocol::v2::derive_encryption_key(&shared_secret);
            let hmac = soft_fido2_crypto::pin_protocol::v2::derive_hmac_key(&shared_secret);
            (enc, hmac)
        }
        _ => return Err(StatusCode::InvalidParameter),
    };

    // Decrypt PIN hash (first 16 bytes of SHA-256(PIN))
    let decrypted_pin_hash: Zeroizing<Vec<u8>> = Zeroizing::new(match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::decrypt(&enc_key, &pin_hash_enc)
            .map_err(|_| StatusCode::PinAuthInvalid)?,
        2 => soft_fido2_crypto::pin_protocol::v2::decrypt(&enc_key, &pin_hash_enc)
            .map_err(|_| StatusCode::PinAuthInvalid)?,
        _ => return Err(StatusCode::InvalidParameter),
    });

    if decrypted_pin_hash.len() < 16 {
        return Err(StatusCode::PinAuthInvalid);
    }

    // Verify PIN hash (first 16 bytes per CTAP spec)
    if !auth.verify_pin_hash_first_16(&decrypted_pin_hash) {
        auth.decrement_pin_retries()?;
        if auth.is_pin_blocked() {
            return Err(StatusCode::PinBlocked);
        }
        return Err(StatusCode::PinInvalid);
    }

    // PIN verified - reset retry counter and get token
    auth.reset_pin_retries()?;
    let token = auth.get_pin_token_after_verification(permissions, rp_id)?;

    // Encrypt the token
    let encrypted_token = match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &token)?,
        2 => soft_fido2_crypto::pin_protocol::v2::encrypt(&enc_key, &token)?,
        _ => return Err(StatusCode::InvalidParameter),
    };

    MapBuilder::new()
        .insert_bytes(resp_keys::PIN_UV_AUTH_TOKEN, &encrypted_token)?
        .build()
}

/// Handle getUvRetries subcommand
/// // Gets the remaining built-in UV retries counter.
fn handle_get_uv_retries<C: AuthenticatorCallbacks>(auth: &Authenticator<C>) -> Result<Vec<u8>> {
    MapBuilder::new()
        .insert(resp_keys::UV_RETRIES, auth.uv_retries())?
        .build()
}

/// Handle getPinUvAuthTokenUsingUvWithPermissions subcommand (0x06)
///
/// Gets a PIN/UV auth token using built-in user verification.
/// Spec: https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#getPinUvAuthTokenUsingUvWithPermissions
fn handle_get_pin_uv_auth_token_using_uv_with_permissions<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    // Check mandatory parameters
    let protocol: u8 = parser
        .get(req_keys::PIN_UV_AUTH_PROTOCOL)
        .map_err(|_| StatusCode::MissingParameter)?;
    let key_agreement: crate::cbor::Value = parser
        .get(req_keys::KEY_AGREEMENT)
        .map_err(|_| StatusCode::MissingParameter)?;
    let permissions: u8 = parser
        .get(req_keys::PERMISSIONS)
        .map_err(|_| StatusCode::MissingParameter)?;
    let rp_id: Option<String> = parser.get_opt(req_keys::RP_ID)?;

    // Validate pinUvAuthProtocol
    if protocol != 1 && protocol != 2 {
        return Err(StatusCode::InvalidParameter);
    }

    // Validate permissions (must not be 0)
    if permissions == 0 {
        return Err(StatusCode::InvalidParameter);
    }

    // Check permission authorization based on authenticator options
    // Permission bits: mc=0x01, ga=0x02, cm=0x04, be=0x08, lbw=0x10, acfg=0x20
    let config = auth.config();

    // cm (0x04) requires credMgmt to be true
    if (permissions & 0x04) != 0 && !config.options.cred_mgmt {
        return Err(StatusCode::UnauthorizedPermission);
    }

    // be (0x08) requires uvBioEnroll to be true
    if (permissions & 0x08) != 0 {
        if let Some(bio_enroll) = config.options.bio_enroll {
            if !bio_enroll {
                return Err(StatusCode::UnauthorizedPermission);
            }
        } else {
            return Err(StatusCode::UnauthorizedPermission);
        }
    }

    // lbw (0x10) requires largeBlobs to be true
    if (permissions & 0x10) != 0 {
        if let Some(large_blobs) = config.options.large_blobs {
            if !large_blobs {
                return Err(StatusCode::UnauthorizedPermission);
            }
        } else {
            return Err(StatusCode::UnauthorizedPermission);
        }
    }

    // Check if built-in UV is configured
    // For our implementation, UV is always available via callbacks
    if config.options.uv.is_none() || !config.options.uv.unwrap() {
        return Err(StatusCode::NotAllowed);
    }

    // Check if UV is blocked (retries exhausted)
    if auth.is_uv_blocked() {
        return Err(StatusCode::UvBlocked);
    }

    // Parse platform key agreement key
    let platform_public_key = parse_cose_key(&key_agreement)?;

    // Get stored keypair for this protocol
    let keypair = match auth.get_pin_protocol_keypair(protocol) {
        Some(kp) => kp,
        None => {
            return Err(StatusCode::PinAuthInvalid);
        }
    };

    // Compute shared secret
    let shared_secret = keypair.shared_secret(&platform_public_key)?;

    // Derive encryption key
    let enc_key = match protocol {
        1 => {
            let (enc, _) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret);
            enc
        }
        2 => soft_fido2_crypto::pin_protocol::v2::derive_encryption_key(&shared_secret),
        _ => return Err(StatusCode::InvalidParameter),
    };

    // Request user consent for the permissions if authenticator has display
    // For virtual authenticator, we skip this step

    // Perform built-in user verification
    let uv_result = auth.callbacks().request_uv(
        "Credential Management",
        None,
        rp_id.as_deref().unwrap_or("*"),
    )?;

    match uv_result {
        crate::UvResult::AcceptedWithUp => {
            // UV succeeded - reset retry counter
            auth.reset_uv_retries();
            true
        }
        crate::UvResult::Accepted => {
            // UV succeeded - reset retry counter
            auth.reset_uv_retries();
            false
        }
        crate::UvResult::Denied => {
            // UV failed - decrement retry counter
            auth.decrement_uv_retries();
            if auth.is_uv_blocked() {
                return Err(StatusCode::UvBlocked);
            }
            return Err(StatusCode::OperationDenied);
        }
        crate::UvResult::Timeout => {
            return Err(StatusCode::UserActionTimeout);
        }
    };

    // Get PIN/UV auth token with the requested permissions
    let token = auth.get_pin_token_after_verification(permissions, rp_id)?;

    // Note: In a full implementation, we would call:
    // - resetPinUvAuthToken() to invalidate existing tokens
    // - beginUsingPinUvAuthToken(userIsPresent) to set the UP flag
    // These are handled internally by get_pin_token_after_verification

    // Encrypt the token
    let encrypted_token = match protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &token)?,
        2 => soft_fido2_crypto::pin_protocol::v2::encrypt(&enc_key, &token)?,
        _ => return Err(StatusCode::InvalidParameter),
    };

    MapBuilder::new()
        .insert_bytes(resp_keys::PIN_UV_AUTH_TOKEN, &encrypted_token)?
        .build()
}

/// Parse COSE_Key to extract public key in SEC1 format
///
/// Extracts the x and y coordinates from a COSE_Key structure and
/// converts to uncompressed SEC1 format (0x04 || x || y).
fn parse_cose_key(cose_key: &crate::cbor::Value) -> Result<Vec<u8>> {
    let map = match cose_key {
        crate::cbor::Value::Map(m) => m,
        _ => return Err(StatusCode::InvalidParameter),
    };

    // Extract x and y coordinates (keys -2 and -3)
    let mut x_coord: Option<Vec<u8>> = None;
    let mut y_coord: Option<Vec<u8>> = None;

    for (key, value) in map {
        // Match both positive and negative integer keys
        let key_int = match key {
            crate::cbor::Value::Integer(i) => {
                // Convert ciborium::value::Integer to i128
                let val: i128 = *i;
                val
            }
            _ => continue,
        };

        match key_int {
            -2 => {
                if let crate::cbor::Value::Bytes(b) = value {
                    x_coord = Some(b.clone());
                }
            }
            -3 => {
                if let crate::cbor::Value::Bytes(b) = value {
                    y_coord = Some(b.clone());
                }
            }
            _ => {}
        }
    }

    let x = x_coord.ok_or(StatusCode::InvalidParameter)?;
    let y = y_coord.ok_or(StatusCode::InvalidParameter)?;

    if x.len() != 32 || y.len() != 32 {
        return Err(StatusCode::InvalidParameter);
    }

    // Build uncompressed SEC1 format: 0x04 || x || y
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04);
    public_key.extend_from_slice(&x);
    public_key.extend_from_slice(&y);

    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        UpResult, UvResult,
        authenticator::{Authenticator, AuthenticatorConfig},
        callbacks::{CredentialStorageCallbacks, PlatformCallbacks, UserInteractionCallbacks},
        types::Credential,
    };

    // Mock callbacks for testing
    struct MockCallbacks;

    impl PlatformCallbacks for MockCallbacks {
        fn get_timestamp_ms(&self) -> u64 {
            0
        }
    }

    impl UserInteractionCallbacks for MockCallbacks {
        fn request_up(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> Result<UpResult> {
            Ok(UpResult::Accepted)
        }

        fn request_uv(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> Result<UvResult> {
            Ok(UvResult::Accepted)
        }

        fn select_credential(&self, _rp_id: &str, _user_names: &[String]) -> Result<usize> {
            Ok(0)
        }
    }

    impl CredentialStorageCallbacks for MockCallbacks {
        fn write_credential(&self, _credential: &Credential) -> Result<()> {
            Ok(())
        }

        fn delete_credential(&self, _credential_id: &[u8]) -> Result<()> {
            Ok(())
        }

        fn read_credentials(
            &self,
            _rp_id: &str,
            _user_id: Option<&[u8]>,
        ) -> Result<Vec<Credential>> {
            Ok(vec![])
        }

        fn credential_exists(&self, _credential_id: &[u8]) -> Result<bool> {
            Ok(false)
        }

        fn get_credential(&self, _credential_id: &[u8]) -> Result<Credential> {
            Err(StatusCode::NoCredentials)
        }

        fn update_credential(&self, _credential: &Credential) -> Result<()> {
            Ok(())
        }

        fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
            Ok(vec![])
        }

        fn credential_count(&self) -> Result<usize> {
            Ok(0)
        }
    }

    fn create_test_authenticator() -> Authenticator<MockCallbacks> {
        let config = AuthenticatorConfig::new();
        Authenticator::new(config, MockCallbacks)
    }

    #[test]
    fn test_get_pin_retries() {
        let auth = create_test_authenticator();
        let response = handle_get_pin_retries(&auth).unwrap();

        // Parse response to verify it contains PIN retries
        assert!(!response.is_empty());
    }

    #[test]
    fn test_get_key_agreement() {
        let mut auth = create_test_authenticator();

        // Build request for protocol V1
        let request = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x02u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .build()
            .unwrap();

        let response = handle(&mut auth, &request).unwrap();

        // Response should contain key agreement
        assert!(!response.is_empty());

        // Verify keypair was stored
        assert!(auth.get_pin_protocol_keypair(1).is_some());
    }

    #[test]
    fn test_set_pin_integration() {
        let mut auth = create_test_authenticator();

        // Step 1: Get key agreement from authenticator
        let get_key_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x02u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .build()
            .unwrap();

        let key_response = handle(&mut auth, &get_key_req).unwrap();
        let parser = MapParser::from_bytes(&key_response).unwrap();
        let auth_cose_key: crate::cbor::Value = parser.get(resp_keys::KEY_AGREEMENT).unwrap();
        let auth_public_key = parse_cose_key(&auth_cose_key).unwrap();

        // Step 2: Generate platform keypair and compute shared secret
        let platform_keypair = soft_fido2_crypto::ecdh::KeyPair::generate().unwrap();
        let shared_secret = platform_keypair.shared_secret(&auth_public_key).unwrap();

        // Step 3: Derive keys
        let (enc_key, hmac_key) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret);

        // Step 4: Prepare PIN (padded to 64 bytes)
        let pin = "1234";
        let mut padded_pin = [0u8; 64];
        padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

        // Step 5: Encrypt PIN
        let new_pin_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &padded_pin).unwrap();

        // Step 6: Compute pinUvAuthParam
        let pin_uv_auth_param =
            soft_fido2_crypto::pin_protocol::v1::authenticate(&hmac_key, &new_pin_enc);

        // Step 7: Build platform's COSE key
        let (px, py) = platform_keypair.public_key_cose();
        let platform_cose_key = MapBuilder::new()
            .insert(1, 2)
            .unwrap()
            .insert(3, -25)
            .unwrap()
            .insert(-1, 1)
            .unwrap()
            .insert_bytes(-2, &px)
            .unwrap()
            .insert_bytes(-3, &py)
            .unwrap()
            .build_value()
            .unwrap();

        // Step 8: Send setPin command
        let set_pin_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x03u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key)
            .unwrap()
            .insert_bytes(req_keys::NEW_PIN_ENC, &new_pin_enc)
            .unwrap()
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)
            .unwrap()
            .build()
            .unwrap();

        let response = handle(&mut auth, &set_pin_req).unwrap();
        assert!(!response.is_empty());

        // Verify PIN was set
        assert!(auth.is_pin_set());
        assert!(auth.verify_pin(pin).is_ok());
    }

    #[test]
    fn test_parse_cose_key() {
        // Create a COSE key structure
        let x = vec![0x42u8; 32];
        let y = vec![0x43u8; 32];

        let cose_key = MapBuilder::new()
            .insert(1, 2)
            .unwrap()
            .insert(3, -25)
            .unwrap()
            .insert(-1, 1)
            .unwrap()
            .insert_bytes(-2, &x)
            .unwrap()
            .insert_bytes(-3, &y)
            .unwrap()
            .build_value()
            .unwrap();

        let public_key = parse_cose_key(&cose_key).unwrap();

        // Verify SEC1 format: 0x04 || x || y
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);
        assert_eq!(&public_key[1..33], x.as_slice());
        assert_eq!(&public_key[33..65], y.as_slice());
    }

    #[test]
    fn test_parse_cose_key_invalid() {
        // Invalid - not a map
        let invalid = crate::cbor::Value::Integer(42.into());
        assert!(parse_cose_key(&invalid).is_err());

        // Invalid - missing coordinates
        let invalid_map = MapBuilder::new()
            .insert(1, 2)
            .unwrap()
            .build_value()
            .unwrap();
        assert!(parse_cose_key(&invalid_map).is_err());
    }

    /// Helper to set up key agreement and return shared secret components
    fn setup_key_agreement(
        auth: &mut Authenticator<MockCallbacks>,
        protocol: u8,
    ) -> (
        soft_fido2_crypto::ecdh::KeyPair,
        soft_fido2_crypto::Zeroizing<[u8; 32]>,
    ) {
        // Get key agreement from authenticator
        let get_key_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x02u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, protocol)
            .unwrap()
            .build()
            .unwrap();

        let key_response = handle(auth, &get_key_req).unwrap();
        let parser = MapParser::from_bytes(&key_response).unwrap();
        let auth_cose_key: crate::cbor::Value = parser.get(resp_keys::KEY_AGREEMENT).unwrap();
        let auth_public_key = parse_cose_key(&auth_cose_key).unwrap();

        // Generate platform keypair and compute shared secret
        let platform_keypair = soft_fido2_crypto::ecdh::KeyPair::generate().unwrap();
        let shared_secret = platform_keypair.shared_secret(&auth_public_key).unwrap();

        (platform_keypair, shared_secret)
    }

    /// Helper to build COSE key from platform keypair
    fn build_platform_cose_key(
        platform_keypair: &soft_fido2_crypto::ecdh::KeyPair,
    ) -> crate::cbor::Value {
        let (px, py) = platform_keypair.public_key_cose();
        MapBuilder::new()
            .insert(1, 2)
            .unwrap()
            .insert(3, -25)
            .unwrap()
            .insert(-1, 1)
            .unwrap()
            .insert_bytes(-2, &px)
            .unwrap()
            .insert_bytes(-3, &py)
            .unwrap()
            .build_value()
            .unwrap()
    }

    #[test]
    fn test_change_pin_integration() {
        use sha2::{Digest, Sha256};

        let mut auth = create_test_authenticator();

        // First set an initial PIN
        let (platform_keypair, shared_secret) = setup_key_agreement(&mut auth, 1);
        let (enc_key, hmac_key) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret);

        let initial_pin = "1234";
        let mut padded_pin = [0u8; 64];
        padded_pin[..initial_pin.len()].copy_from_slice(initial_pin.as_bytes());

        let new_pin_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &padded_pin).unwrap();
        let pin_uv_auth_param =
            soft_fido2_crypto::pin_protocol::v1::authenticate(&hmac_key, &new_pin_enc);

        let platform_cose_key = build_platform_cose_key(&platform_keypair);

        let set_pin_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x03u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key)
            .unwrap()
            .insert_bytes(req_keys::NEW_PIN_ENC, &new_pin_enc)
            .unwrap()
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)
            .unwrap()
            .build()
            .unwrap();

        handle(&mut auth, &set_pin_req).unwrap();
        assert!(auth.is_pin_set());

        // Now change the PIN
        let (platform_keypair2, shared_secret2) = setup_key_agreement(&mut auth, 1);
        let (enc_key2, hmac_key2) =
            soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret2);

        // Compute current PIN hash (first 16 bytes of SHA-256(PIN))
        let current_pin_hash: [u8; 32] = Sha256::digest(initial_pin.as_bytes()).into();

        // New PIN
        let new_pin = "5678";
        let mut padded_new_pin = [0u8; 64];
        padded_new_pin[..new_pin.len()].copy_from_slice(new_pin.as_bytes());

        // Encrypt current PIN hash (first 16 bytes)
        let pin_hash_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key2, &current_pin_hash[..16])
                .unwrap();

        // Encrypt new PIN
        let new_pin_enc2 =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key2, &padded_new_pin).unwrap();

        // Compute pinUvAuthParam = HMAC(hmac_key, newPinEnc || pinHashEnc)
        let mut verify_data = new_pin_enc2.clone();
        verify_data.extend_from_slice(&pin_hash_enc);
        let pin_uv_auth_param2 =
            soft_fido2_crypto::pin_protocol::v1::authenticate(&hmac_key2, &verify_data);

        let platform_cose_key2 = build_platform_cose_key(&platform_keypair2);

        let change_pin_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x04u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key2)
            .unwrap()
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param2)
            .unwrap()
            .insert_bytes(req_keys::NEW_PIN_ENC, &new_pin_enc2)
            .unwrap()
            .insert_bytes(req_keys::PIN_HASH_ENC, &pin_hash_enc)
            .unwrap()
            .build()
            .unwrap();

        let response = handle(&mut auth, &change_pin_req).unwrap();
        assert!(!response.is_empty());

        // Verify new PIN works
        assert!(auth.verify_pin(new_pin).is_ok());
        // Verify old PIN fails
        assert!(auth.verify_pin(initial_pin).is_err());
    }

    #[test]
    fn test_get_pin_token_integration() {
        use sha2::{Digest, Sha256};

        let mut auth = create_test_authenticator();

        // First set a PIN
        let (platform_keypair, shared_secret) = setup_key_agreement(&mut auth, 1);
        let (enc_key, hmac_key) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret);

        let pin = "1234";
        let mut padded_pin = [0u8; 64];
        padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

        let new_pin_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &padded_pin).unwrap();
        let pin_uv_auth_param =
            soft_fido2_crypto::pin_protocol::v1::authenticate(&hmac_key, &new_pin_enc);

        let platform_cose_key = build_platform_cose_key(&platform_keypair);

        let set_pin_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x03u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key)
            .unwrap()
            .insert_bytes(req_keys::NEW_PIN_ENC, &new_pin_enc)
            .unwrap()
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)
            .unwrap()
            .build()
            .unwrap();

        handle(&mut auth, &set_pin_req).unwrap();
        assert!(auth.is_pin_set());

        // Now get a PIN token
        let (platform_keypair2, shared_secret2) = setup_key_agreement(&mut auth, 1);
        let (enc_key2, _hmac_key2) =
            soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret2);

        // Compute PIN hash (first 16 bytes)
        let pin_hash: [u8; 32] = Sha256::digest(pin.as_bytes()).into();

        // Encrypt PIN hash (first 16 bytes)
        let pin_hash_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key2, &pin_hash[..16]).unwrap();

        let platform_cose_key2 = build_platform_cose_key(&platform_keypair2);

        let get_pin_token_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x05u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key2)
            .unwrap()
            .insert_bytes(req_keys::PIN_HASH_ENC, &pin_hash_enc)
            .unwrap()
            .build()
            .unwrap();

        let response = handle(&mut auth, &get_pin_token_req).unwrap();

        // Parse response to verify we got an encrypted PIN token
        let parser = MapParser::from_bytes(&response).unwrap();
        let encrypted_token: Vec<u8> = parser.get_bytes(resp_keys::PIN_UV_AUTH_TOKEN).unwrap();

        // Decrypt the token
        let decrypted_token =
            soft_fido2_crypto::pin_protocol::v1::decrypt(&enc_key2, &encrypted_token).unwrap();

        // Token should be 32 bytes
        assert_eq!(decrypted_token.len(), 32);
    }

    #[test]
    fn test_get_pin_token_wrong_pin() {
        use sha2::{Digest, Sha256};

        let mut auth = create_test_authenticator();

        // First set a PIN
        let (platform_keypair, shared_secret) = setup_key_agreement(&mut auth, 1);
        let (enc_key, hmac_key) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret);

        let pin = "1234";
        let mut padded_pin = [0u8; 64];
        padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

        let new_pin_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &padded_pin).unwrap();
        let pin_uv_auth_param =
            soft_fido2_crypto::pin_protocol::v1::authenticate(&hmac_key, &new_pin_enc);

        let platform_cose_key = build_platform_cose_key(&platform_keypair);

        let set_pin_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x03u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key)
            .unwrap()
            .insert_bytes(req_keys::NEW_PIN_ENC, &new_pin_enc)
            .unwrap()
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)
            .unwrap()
            .build()
            .unwrap();

        handle(&mut auth, &set_pin_req).unwrap();
        assert_eq!(auth.pin_retries(), 8);

        // Try to get PIN token with wrong PIN
        let (platform_keypair2, shared_secret2) = setup_key_agreement(&mut auth, 1);
        let (enc_key2, _hmac_key2) =
            soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret2);

        // Wrong PIN hash
        let wrong_pin_hash: [u8; 32] = Sha256::digest("wrong".as_bytes()).into();

        let pin_hash_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key2, &wrong_pin_hash[..16]).unwrap();

        let platform_cose_key2 = build_platform_cose_key(&platform_keypair2);

        let get_pin_token_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x05u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key2)
            .unwrap()
            .insert_bytes(req_keys::PIN_HASH_ENC, &pin_hash_enc)
            .unwrap()
            .build()
            .unwrap();

        let result = handle(&mut auth, &get_pin_token_req);
        assert!(result.is_err());

        // PIN retries should have decreased
        assert_eq!(auth.pin_retries(), 7);
    }

    #[test]
    fn test_pin_blocked_after_retries() {
        use sha2::{Digest, Sha256};

        let mut auth = create_test_authenticator();

        // First set a PIN
        let (platform_keypair, shared_secret) = setup_key_agreement(&mut auth, 1);
        let (enc_key, hmac_key) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret);

        let pin = "1234";
        let mut padded_pin = [0u8; 64];
        padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

        let new_pin_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &padded_pin).unwrap();
        let pin_uv_auth_param =
            soft_fido2_crypto::pin_protocol::v1::authenticate(&hmac_key, &new_pin_enc);

        let platform_cose_key = build_platform_cose_key(&platform_keypair);

        let set_pin_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x03u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key)
            .unwrap()
            .insert_bytes(req_keys::NEW_PIN_ENC, &new_pin_enc)
            .unwrap()
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)
            .unwrap()
            .build()
            .unwrap();

        handle(&mut auth, &set_pin_req).unwrap();

        // Exhaust retries with wrong PIN
        let wrong_pin_hash: [u8; 32] = Sha256::digest("wrong".as_bytes()).into();

        for i in 0..8 {
            let (platform_keypair2, shared_secret2) = setup_key_agreement(&mut auth, 1);
            let (enc_key2, _hmac_key2) =
                soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret2);

            let pin_hash_enc =
                soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key2, &wrong_pin_hash[..16])
                    .unwrap();

            let platform_cose_key2 = build_platform_cose_key(&platform_keypair2);

            let get_pin_token_req = MapBuilder::new()
                .insert(req_keys::SUBCOMMAND, 0x05u8)
                .unwrap()
                .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
                .unwrap()
                .insert(req_keys::KEY_AGREEMENT, platform_cose_key2)
                .unwrap()
                .insert_bytes(req_keys::PIN_HASH_ENC, &pin_hash_enc)
                .unwrap()
                .build()
                .unwrap();

            let result = handle(&mut auth, &get_pin_token_req);

            if i < 7 {
                // Should fail with PinInvalid
                assert!(result.is_err());
            } else {
                // Last attempt should fail with PinBlocked
                assert!(result.is_err());
            }
        }

        // Verify PIN is blocked
        assert!(auth.is_pin_blocked());
        assert_eq!(auth.pin_retries(), 0);

        // Verify even correct PIN fails now
        let (platform_keypair3, shared_secret3) = setup_key_agreement(&mut auth, 1);
        let (enc_key3, _) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret3);
        let correct_pin_hash: [u8; 32] = Sha256::digest(pin.as_bytes()).into();
        let pin_hash_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key3, &correct_pin_hash[..16])
                .unwrap();
        let platform_cose_key3 = build_platform_cose_key(&platform_keypair3);

        let get_pin_token_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x05u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key3)
            .unwrap()
            .insert_bytes(req_keys::PIN_HASH_ENC, &pin_hash_enc)
            .unwrap()
            .build()
            .unwrap();

        let result = handle(&mut auth, &get_pin_token_req);
        assert!(result.is_err());
    }

    #[test]
    fn test_pin_retries_reset_on_success() {
        use sha2::{Digest, Sha256};

        let mut auth = create_test_authenticator();

        // First set a PIN
        let (platform_keypair, shared_secret) = setup_key_agreement(&mut auth, 1);
        let (enc_key, hmac_key) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret);

        let pin = "1234";
        let mut padded_pin = [0u8; 64];
        padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

        let new_pin_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &padded_pin).unwrap();
        let pin_uv_auth_param =
            soft_fido2_crypto::pin_protocol::v1::authenticate(&hmac_key, &new_pin_enc);

        let platform_cose_key = build_platform_cose_key(&platform_keypair);

        let set_pin_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x03u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key)
            .unwrap()
            .insert_bytes(req_keys::NEW_PIN_ENC, &new_pin_enc)
            .unwrap()
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)
            .unwrap()
            .build()
            .unwrap();

        handle(&mut auth, &set_pin_req).unwrap();

        // Make some failed attempts
        let wrong_pin_hash: [u8; 32] = Sha256::digest("wrong".as_bytes()).into();

        for _ in 0..3 {
            let (platform_keypair2, shared_secret2) = setup_key_agreement(&mut auth, 1);
            let (enc_key2, _) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret2);

            let pin_hash_enc =
                soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key2, &wrong_pin_hash[..16])
                    .unwrap();

            let platform_cose_key2 = build_platform_cose_key(&platform_keypair2);

            let get_pin_token_req = MapBuilder::new()
                .insert(req_keys::SUBCOMMAND, 0x05u8)
                .unwrap()
                .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
                .unwrap()
                .insert(req_keys::KEY_AGREEMENT, platform_cose_key2)
                .unwrap()
                .insert_bytes(req_keys::PIN_HASH_ENC, &pin_hash_enc)
                .unwrap()
                .build()
                .unwrap();

            let _ = handle(&mut auth, &get_pin_token_req);
        }

        assert_eq!(auth.pin_retries(), 5);

        // Now succeed with correct PIN
        let (platform_keypair3, shared_secret3) = setup_key_agreement(&mut auth, 1);
        let (enc_key3, _) = soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret3);
        let correct_pin_hash: [u8; 32] = Sha256::digest(pin.as_bytes()).into();
        let pin_hash_enc =
            soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key3, &correct_pin_hash[..16])
                .unwrap();
        let platform_cose_key3 = build_platform_cose_key(&platform_keypair3);

        let get_pin_token_req = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x05u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
            .unwrap()
            .insert(req_keys::KEY_AGREEMENT, platform_cose_key3)
            .unwrap()
            .insert_bytes(req_keys::PIN_HASH_ENC, &pin_hash_enc)
            .unwrap()
            .build()
            .unwrap();

        let result = handle(&mut auth, &get_pin_token_req);
        assert!(result.is_ok());

        // PIN retries should be reset to max
        assert_eq!(auth.pin_retries(), 8);
    }
}
