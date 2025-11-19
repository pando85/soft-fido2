//! authenticatorMakeCredential command
//!
//! Creates a new credential for a relying party.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorMakeCredential>

use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::cbor::{MapBuilder, MapParser};
use crate::extensions::MakeCredentialExtensions;
use crate::status::{Result, StatusCode};
use crate::types::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, User,
};
use crate::{CredProtect, UpResult, UvResult};

use soft_fido2_crypto::ecdsa;

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
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;

    // Parse required parameters
    let client_data_hash: Vec<u8> = parser.get_bytes(req_keys::CLIENT_DATA_HASH)?;
    if client_data_hash.len() != 32 {
        return Err(StatusCode::InvalidParameter);
    }

    let rp: RelyingParty = parser.get(req_keys::RP)?;

    let user = parse_user(&parser, req_keys::USER)?;

    // Parse pub_key_cred_params as generic CBOR and convert
    let params_value: crate::cbor::Value = parser.get(req_keys::PUB_KEY_CRED_PARAMS)?;
    let pub_key_cred_params: Vec<PublicKeyCredentialParameters> =
        crate::cbor::from_value(&params_value)?;

    // Parse optional parameters
    let exclude_list: Option<Vec<PublicKeyCredentialDescriptor>> =
        parser.get_opt(req_keys::EXCLUDE_LIST)?;
    // Parse pinUvAuthParam as bytes (use get_bytes for CBOR Bytes type)
    let pin_uv_auth_param: Option<Vec<u8>> =
        if parser.get_raw(req_keys::PIN_UV_AUTH_PARAM).is_some() {
            Some(parser.get_bytes(req_keys::PIN_UV_AUTH_PARAM)?)
        } else {
            None
        };
    let pin_uv_auth_protocol: Option<u8> = parser.get_opt(req_keys::PIN_UV_AUTH_PROTOCOL)?;

    let options = parse_options(&parser)?;

    // Parse extensions
    let extensions =
        if let Some(ext_value) = parser.get_opt::<crate::cbor::Value>(req_keys::EXTENSIONS)? {
            MakeCredentialExtensions::from_cbor(&ext_value)?
        } else {
            MakeCredentialExtensions::new()
        };

    // 3. Check if algorithm is supported
    let alg = pub_key_cred_params
        .iter()
        .find(|p| auth.config().algorithms.contains(&p.alg))
        .ok_or(StatusCode::UnsupportedAlgorithm)?;

    // Verify PIN/UV auth if present
    if let Some(_pin_auth) = &pin_uv_auth_param {
        let _protocol = pin_uv_auth_protocol.ok_or(StatusCode::MissingParameter)?;

        // TODO: Implement PIN token verification
        // For now, just check if PIN is set when pin_auth is provided
        if !auth.is_pin_set() {
            return Err(StatusCode::PinNotSet);
        }
    }

    // 5. Check excluded credentials
    if let Some(ref exclude) = exclude_list {
        for cred_desc in exclude {
            if auth.callbacks().credential_exists(&cred_desc.id)? {
                return Err(StatusCode::CredentialExcluded);
            }
        }
    }

    // 6. Request user presence if required
    let mut up_performed = false;
    if options.up {
        let info = format!("Register with {}", rp.id);
        match auth
            .callbacks()
            .request_up(&info, user.name.as_deref(), &rp.id)?
        {
            UpResult::Accepted => up_performed = true,
            UpResult::Denied => return Err(StatusCode::OperationDenied),
            UpResult::Timeout => return Err(StatusCode::UserActionTimeout),
        }
    }

    // 7. Request user verification if required
    let mut uv_performed = false;
    if options.uv {
        let info = format!("Verify for {}", rp.id);
        match auth
            .callbacks()
            .request_uv(&info, user.name.as_deref(), &rp.id)?
        {
            UvResult::Accepted => uv_performed = true,
            UvResult::AcceptedWithUp => {
                uv_performed = true;
                up_performed = true;
            }
            UvResult::Denied => return Err(StatusCode::OperationDenied),
            UvResult::Timeout => return Err(StatusCode::UserActionTimeout),
        }

        // CRITICAL: When UV is required, it MUST be performed
        // If we reach here and UV was not performed, fail the operation
        if !uv_performed {
            return Err(StatusCode::OperationDenied);
        }
    }

    // Generate credential key pair
    let (private_key, public_key_bytes) = ecdsa::generate_keypair();

    // Generate credential ID
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
                if options.uv && uv_performed {
                    // UV was required and performed - enforce UV for future authentications
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
            private_key: private_key.to_vec(),
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

    // 11. Build extension outputs
    let extension_outputs = extensions.build_outputs(auth.config().min_pin_length);

    // 12. Build authenticator data
    let cred_data = AttestationCredential {
        id: credential_id,
        public_key: public_key_bytes,
        algorithm: alg.alg,
    };
    let auth_data = build_authenticator_data(
        &rp.id,
        up_performed,
        uv_performed,
        auth.config().aaguid,
        &cred_data,
        extension_outputs.as_ref(),
    )?;

    // 13. Build attestation statement (self-attestation for now)
    let sig_data = [&auth_data[..], &client_data_hash[..]].concat();
    let signature = ecdsa::sign(&private_key, &sig_data)?;

    let att_stmt = build_attestation_statement(&signature, alg.alg)?;

    // 14. Build response
    MapBuilder::new()
        .insert(resp_keys::FMT, "packed")?
        .insert_bytes(resp_keys::AUTH_DATA, &auth_data)? // Must be CBOR bytes, not array!
        .insert(resp_keys::ATT_STMT, att_stmt)?
        .build()
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
    use rand::RngCore;
    let mut id = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Get current timestamp in seconds
fn current_timestamp() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
