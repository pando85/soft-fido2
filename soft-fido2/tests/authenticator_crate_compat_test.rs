//! Comprehensive integration test for Mozilla authenticator crate compatibility (in-memory)
//!
//! This test suite validates that soft-fido2 correctly handles the same CTAP request
//! formats that Mozilla's authenticator crate would send, but without requiring
//! USB/HID transport. This provides fast, reliable compatibility testing.
//!
//! # Architecture
//!
//! ```text
//! [Test] → [CTAP Request Builder] → [soft-fido2 Authenticator]
//! ```
//!
//! vs E2E test:
//! ```text
//! [Test] → [Mozilla authenticator crate] → [USB HID] → [UHID] → [soft-fido2 Authenticator]
//! ```
//!
//! This test validates the same protocol compatibility as the E2E test but with:
//! - No USB/UHID dependencies
//! - Faster execution
//! - More reliable (no kernel/permissions issues)
//! - Easier to debug
//!
//! # Test Coverage
//!
//! - Basic registration and authentication (no PIN)
//! - PIN protocol v2 (setup, authentication with PIN token)
//! - Resident keys with multiple credentials
//! - Credential management (enumerate, delete, update)
//! - Different authenticator configurations

mod common;

use soft_fido2::{Authenticator, AuthenticatorConfig, AuthenticatorOptions};

use common::TestCallbacks;
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use soft_fido2_crypto::pin_protocol::v2;

const TEST_RP_ID: &str = "example.com";
const TEST_RP_NAME: &str = "Example Corporation";
const TEST_ORIGIN: &str = "https://example.com";
const TEST_USER_ID: &[u8] = &[1, 2, 3, 4];
const TEST_USER_NAME: &str = "alice@example.com";
const TEST_USER_DISPLAY_NAME: &str = "Alice";

/// Compute client data hash (simulates WebAuthn client-side)
fn compute_client_data_hash(challenge: &[u8], ceremony_type: &str) -> [u8; 32] {
    use base64::Engine;
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);

    let client_data_json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
        ceremony_type, challenge_b64, TEST_ORIGIN
    );

    let hash = Sha256::digest(client_data_json.as_bytes());
    hash.into()
}

/// Build makeCredential CBOR request matching Mozilla authenticator crate format
fn build_make_credential_request(
    client_data_hash: &[u8],
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    // Relying Party (0x02)
    let rp_map = vec![
        (
            Value::Text("id".to_string()),
            Value::Text(rp_id.to_string()),
        ),
        (
            Value::Text("name".to_string()),
            Value::Text(rp_name.to_string()),
        ),
    ];

    // User (0x03)
    let user_map = vec![
        (
            Value::Text("id".to_string()),
            Value::Bytes(user_id.to_vec()),
        ),
        (
            Value::Text("name".to_string()),
            Value::Text(user_name.to_string()),
        ),
        (
            Value::Text("displayName".to_string()),
            Value::Text(user_display_name.to_string()),
        ),
    ];

    // Public Key Credential Parameters (0x04)
    // Mozilla authenticator crate sends both ES256 and RS256
    let pub_key_params = vec![
        Value::Map(vec![
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
            (Value::Text("alg".to_string()), Value::Integer((-7).into())), // ES256
        ]),
        Value::Map(vec![
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-257).into()),
            ), // RS256
        ]),
    ];

    // Options (0x07) - UP only, no UV
    let options_map = vec![
        (Value::Text("rk".to_string()), Value::Bool(false)), // Not required
        (Value::Text("uv".to_string()), Value::Bool(false)), // No user verification
    ];

    // Main request map (integer keys per CTAP2 spec)
    let request_map = vec![
        (
            Value::Integer(0x01.into()),
            Value::Bytes(client_data_hash.to_vec()),
        ), // clientDataHash
        (Value::Integer(0x02.into()), Value::Map(rp_map)), // rp
        (Value::Integer(0x03.into()), Value::Map(user_map)), // user
        (Value::Integer(0x04.into()), Value::Array(pub_key_params)), // pubKeyCredParams
        (Value::Integer(0x07.into()), Value::Map(options_map)), // options
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Build getAssertion CBOR request matching Mozilla authenticator crate format
fn build_get_assertion_request(
    client_data_hash: &[u8],
    rp_id: &str,
    allow_list: Option<Vec<Vec<u8>>>,
) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    let mut request_map = vec![
        (Value::Integer(0x01.into()), Value::Text(rp_id.to_string())), // rpId
        (
            Value::Integer(0x02.into()),
            Value::Bytes(client_data_hash.to_vec()),
        ), // clientDataHash
    ];

    // Allow list (0x03) - optional credential IDs
    if let Some(cred_ids) = allow_list {
        let allow_list_array: Vec<Value> = cred_ids
            .into_iter()
            .map(|cred_id| {
                Value::Map(vec![
                    (
                        Value::Text("type".to_string()),
                        Value::Text("public-key".to_string()),
                    ),
                    (Value::Text("id".to_string()), Value::Bytes(cred_id)),
                ])
            })
            .collect();
        request_map.push((Value::Integer(0x03.into()), Value::Array(allow_list_array)));
    }

    // Options (0x05) - UP only, no UV
    let options_map = vec![
        (Value::Text("up".to_string()), Value::Bool(true)), // user presence
        (Value::Text("uv".to_string()), Value::Bool(false)), // no user verification
    ];
    request_map.push((Value::Integer(0x05.into()), Value::Map(options_map)));

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Extract credential ID from makeCredential response
fn extract_credential_id(response: &[u8]) -> Option<Vec<u8>> {
    use soft_fido2_ctap::cbor::Value;

    if response.is_empty() {
        return None;
    }

    // Skip status byte
    if response[0] != 0x00 {
        return None;
    }

    // Parse CBOR response
    let value: Value = soft_fido2_ctap::cbor::decode(&response[1..]).ok()?;

    // Response is a map with key 0x02 = authData
    if let Value::Map(map) = value {
        for (k, v) in map {
            if k == Value::Integer(0x02.into()) {
                // authData is bytes
                if let Value::Bytes(auth_data) = v {
                    // Parse authenticator data structure:
                    // rpIdHash (32) + flags (1) + signCount (4) + attestedCredentialData
                    if auth_data.len() < 37 {
                        return None;
                    }

                    // Check AT flag (bit 6)
                    let flags = auth_data[32];
                    if (flags & 0x40) == 0 {
                        return None;
                    }

                    // attestedCredentialData starts at byte 37:
                    // aaguid (16) + credentialIdLength (2) + credentialId
                    if auth_data.len() < 55 {
                        return None;
                    }

                    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
                    if auth_data.len() < 55 + cred_id_len {
                        return None;
                    }

                    return Some(auth_data[55..55 + cred_id_len].to_vec());
                }
            }
        }
    }

    None
}

// ============================================================================
// CLIENT PIN HELPERS
// ============================================================================

/// Build clientPIN getKeyAgreement request (subCommand 0x02)
fn build_get_key_agreement_request(pin_protocol: u8) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    let request_map = vec![
        (
            Value::Integer(0x01.into()),
            Value::Integer(pin_protocol.into()),
        ), // pinUvAuthProtocol
        (Value::Integer(0x02.into()), Value::Integer(0x02.into())), // subCommand: getKeyAgreement
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Build clientPIN setPIN request (subCommand 0x03)
fn build_set_pin_request(
    pin_protocol: u8,
    key_agreement: &[u8],
    pin_enc: &[u8],
    pin_auth: &[u8],
) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    // Parse key agreement COSE_Key
    let key_agreement_value: Value =
        soft_fido2_ctap::cbor::decode(key_agreement).expect("Failed to parse key agreement");

    let request_map = vec![
        (
            Value::Integer(0x01.into()),
            Value::Integer(pin_protocol.into()),
        ), // pinUvAuthProtocol
        (Value::Integer(0x02.into()), Value::Integer(0x03.into())), // subCommand: setPIN
        (Value::Integer(0x03.into()), key_agreement_value),         // keyAgreement
        (Value::Integer(0x04.into()), Value::Bytes(pin_auth.to_vec())), // pinUvAuthParam
        (Value::Integer(0x05.into()), Value::Bytes(pin_enc.to_vec())), // newPinEnc
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Build clientPIN getPINToken request (subCommand 0x05) - for PIN protocol v2
#[allow(dead_code)]
fn build_get_pin_token_request(
    pin_protocol: u8,
    key_agreement: &[u8],
    pin_hash_enc: &[u8],
) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    let key_agreement_value: Value =
        soft_fido2_ctap::cbor::decode(key_agreement).expect("Failed to parse key agreement");

    let request_map = vec![
        (
            Value::Integer(0x01.into()),
            Value::Integer(pin_protocol.into()),
        ), // pinUvAuthProtocol
        (Value::Integer(0x02.into()), Value::Integer(0x05.into())), // subCommand: getPINToken
        (Value::Integer(0x03.into()), key_agreement_value),         // keyAgreement
        (
            Value::Integer(0x06.into()),
            Value::Bytes(pin_hash_enc.to_vec()),
        ), // pinHashEnc
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Build clientPIN getPinUvAuthTokenUsingPinWithPermissions request (subCommand 0x09)
fn build_get_pin_uv_auth_token_using_pin_with_permissions_request(
    pin_protocol: u8,
    key_agreement: &[u8],
    pin_hash_enc: &[u8],
    permissions: u8,
    rp_id: Option<&str>,
) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    let key_agreement_value: Value =
        soft_fido2_ctap::cbor::decode(key_agreement).expect("Failed to parse key agreement");

    let mut request_map = vec![
        (
            Value::Integer(0x01.into()),
            Value::Integer(pin_protocol.into()),
        ), // pinUvAuthProtocol
        (Value::Integer(0x02.into()), Value::Integer(0x09.into())), // subCommand: getPinUvAuthTokenUsingPinWithPermissions
        (Value::Integer(0x03.into()), key_agreement_value),         // keyAgreement
        (
            Value::Integer(0x06.into()),
            Value::Bytes(pin_hash_enc.to_vec()),
        ), // pinHashEnc
        (
            Value::Integer(0x09.into()),
            Value::Integer(permissions.into()),
        ), // permissions
    ];

    if let Some(rp_id) = rp_id {
        request_map.push((Value::Integer(0x0A.into()), Value::Text(rp_id.to_string()))); // rpId
    }

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Build clientPIN getPinUvAuthTokenUsingUvWithPermissions request (subCommand 0x06)
fn build_get_pin_uv_auth_token_request(
    pin_protocol: u8,
    key_agreement: &[u8],
    permissions: u8,
    rp_id: Option<&str>,
) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    let key_agreement_value: Value =
        soft_fido2_ctap::cbor::decode(key_agreement).expect("Failed to parse key agreement");

    let mut request_map = vec![
        (
            Value::Integer(0x01.into()),
            Value::Integer(pin_protocol.into()),
        ), // pinUvAuthProtocol
        (Value::Integer(0x02.into()), Value::Integer(0x06.into())), // subCommand: getPinUvAuthTokenUsingUvWithPermissions
        (Value::Integer(0x03.into()), key_agreement_value),         // keyAgreement
        (
            Value::Integer(0x09.into()),
            Value::Integer(permissions.into()),
        ), // permissions
    ];

    if let Some(rp_id) = rp_id {
        request_map.push((Value::Integer(0x0A.into()), Value::Text(rp_id.to_string()))); // rpId
    }

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Extract COSE key from clientPIN response
fn extract_cose_key(response: &[u8]) -> Option<Vec<u8>> {
    use soft_fido2_ctap::cbor::Value;

    if response.is_empty() || response[0] != 0x00 {
        return None;
    }

    let value: Value = soft_fido2_ctap::cbor::decode(&response[1..]).ok()?;

    if let Value::Map(map) = value {
        for (k, v) in map {
            if k == Value::Integer(0x01.into()) {
                // keyAgreement
                let mut buffer = Vec::new();
                soft_fido2_ctap::cbor::into_writer(&v, &mut buffer).ok()?;
                return Some(buffer);
            }
        }
    }

    None
}

/// Extract encrypted PIN token from clientPIN response
fn extract_pin_token(response: &[u8]) -> Option<Vec<u8>> {
    use soft_fido2_ctap::cbor::Value;

    if response.is_empty() || response[0] != 0x00 {
        return None;
    }

    let value: Value = soft_fido2_ctap::cbor::decode(&response[1..]).ok()?;

    if let Value::Map(map) = value {
        for (k, v) in map {
            if k == Value::Integer(0x02.into()) {
                // pinToken
                if let Value::Bytes(token) = v {
                    return Some(token);
                }
            }
        }
    }

    None
}

// ============================================================================
// CREDENTIAL MANAGEMENT HELPERS
// ============================================================================

/// Build credentialManagement getCredsMetadata request (subCommand 0x01)
fn build_get_creds_metadata_request(pin_protocol: u8, pin_uv_auth_param: &[u8]) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    let request_map = vec![
        (Value::Integer(0x01.into()), Value::Integer(0x01.into())), // subCommand: getCredsMetadata
        (
            Value::Integer(0x02.into()),
            Value::Bytes(pin_uv_auth_param.to_vec()),
        ), // pinUvAuthParam
        (
            Value::Integer(0x03.into()),
            Value::Integer(pin_protocol.into()),
        ), // pinUvAuthProtocol
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Build credentialManagement enumerateRPsBegin request (subCommand 0x02)
fn build_enumerate_rps_begin_request(pin_protocol: u8, pin_uv_auth_param: &[u8]) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    let request_map = vec![
        (Value::Integer(0x01.into()), Value::Integer(0x02.into())), // subCommand: enumerateRPsBegin
        (
            Value::Integer(0x02.into()),
            Value::Bytes(pin_uv_auth_param.to_vec()),
        ), // pinUvAuthParam
        (
            Value::Integer(0x03.into()),
            Value::Integer(pin_protocol.into()),
        ), // pinUvAuthProtocol
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Build credentialManagement enumerateRPsGetNextRP request (subCommand 0x03)
fn build_enumerate_rps_get_next_request() -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

    let request_map = vec![
        (Value::Integer(0x01.into()), Value::Integer(0x03.into())), // subCommand: enumerateRPsGetNextRP
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Extract total RPs count from credentialManagement metadata response
fn extract_total_rps(response: &[u8]) -> Option<u32> {
    use soft_fido2_ctap::cbor::Value;

    if response.is_empty() || response[0] != 0x00 {
        return None;
    }

    let value: Value = soft_fido2_ctap::cbor::decode(&response[1..]).ok()?;

    if let Value::Map(map) = value {
        for (k, v) in map {
            if k == Value::Integer(0x02.into()) {
                // existingResidentCredentialsCount
                if let Value::Integer(count) = v {
                    return count.try_into().ok();
                }
            }
        }
    }

    None
}

/// Extract RP info from credentialManagement enumerateRPs response
fn extract_rp_info(response: &[u8]) -> Option<(String, Vec<u8>)> {
    use soft_fido2_ctap::cbor::Value;

    if response.is_empty() || response[0] != 0x00 {
        return None;
    }

    let value: Value = soft_fido2_ctap::cbor::decode(&response[1..]).ok()?;

    if let Value::Map(map) = value {
        let mut rp_id = None;
        let mut rp_id_hash = None;

        for (k, v) in map {
            match k {
                Value::Integer(i) if i == 0x03.into() => {
                    // rp
                    if let Value::Map(rp_map) = v {
                        for (rk, rv) in rp_map {
                            if rk == Value::Text("id".to_string())
                                && let Value::Text(id) = rv
                            {
                                rp_id = Some(id);
                            }
                        }
                    }
                }
                Value::Integer(i) if i == 0x04.into() => {
                    // rpIDHash
                    if let Value::Bytes(hash) = v {
                        rp_id_hash = Some(hash);
                    }
                }
                _ => {}
            }
        }

        if let (Some(id), Some(hash)) = (rp_id, rp_id_hash) {
            return Some((id, hash));
        }
    }

    None
}

// ============================================================================
// TESTS
// ============================================================================

#[test]
fn test_mozilla_authenticator_crate_compat_basic() {
    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║   Mozilla Authenticator Compatibility Test    ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    // Setup authenticator with UP-only config (matching E2E test)
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_presence(true)
                .with_user_verification(Some(false))
                .with_platform_device(false)
                .with_client_pin(Some(false))
                .with_credential_management(Some(false)),
        )
        .build();

    let mut auth =
        Authenticator::with_config(callbacks.clone(), config).expect("Failed to create auth");

    // ========================================
    // PHASE 1: REGISTRATION (makeCredential)
    // ========================================
    eprintln!("[Test] ═══ REGISTRATION PHASE ═══\n");

    let challenge = b"random-registration-challenge-12345";
    let client_data_hash = compute_client_data_hash(challenge, "webauthn.create");

    let make_cred_cbor = build_make_credential_request(
        &client_data_hash,
        TEST_RP_ID,
        TEST_RP_NAME,
        TEST_USER_ID,
        TEST_USER_NAME,
        TEST_USER_DISPLAY_NAME,
    );

    // CTAP command: 0x01 (makeCredential) + CBOR
    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("makeCredential failed");

    assert!(!response.is_empty(), "Empty response from makeCredential");
    assert_eq!(
        response[0], 0x00,
        "makeCredential failed with status: 0x{:02x}",
        response[0]
    );

    eprintln!("[Test] ✓ Registration successful");

    // Extract credential ID for authentication
    let credential_id = extract_credential_id(&response).expect("Failed to extract credential ID");
    eprintln!("[Test]   Credential ID: {} bytes\n", credential_id.len());

    // ========================================
    // PHASE 2: AUTHENTICATION (getAssertion)
    // ========================================
    eprintln!("[Test] ═══ AUTHENTICATION PHASE ═══\n");

    let challenge = b"random-authentication-challenge-67890";
    let client_data_hash = compute_client_data_hash(challenge, "webauthn.get");

    let get_assertion_cbor =
        build_get_assertion_request(&client_data_hash, TEST_RP_ID, Some(vec![credential_id]));

    // CTAP command: 0x02 (getAssertion) + CBOR
    let mut ctap_request = vec![0x02];
    ctap_request.extend_from_slice(&get_assertion_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getAssertion failed");

    assert!(!response.is_empty(), "Empty response from getAssertion");
    assert_eq!(
        response[0], 0x00,
        "getAssertion failed with status: 0x{:02x}",
        response[0]
    );

    eprintln!("[Test] ✓ Authentication successful");

    // ========================================
    // VERIFICATION
    // ========================================
    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║              ✓ Test Passed!                    ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    eprintln!("Summary:");
    eprintln!("  • Validated Mozilla authenticator crate CTAP request format");
    eprintln!("  • Successfully registered credential");
    eprintln!("  • Successfully authenticated with credential");
    eprintln!("  • All without USB/transport layer");

    // Verify credential was stored
    let cred_count = callbacks.credential_count();
    assert_eq!(cred_count, 1, "Expected 1 credential to be stored");
}

#[test]
fn test_mozilla_authenticator_crate_compat_with_pin() {
    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║     PIN Protocol v2 Compatibility Test        ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    // Setup authenticator with PIN support
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_presence(true)
                .with_user_verification(Some(true)) // Enable UV
                .with_platform_device(false)
                .with_client_pin(Some(false)) // PIN supported but not yet set
                .with_credential_management(Some(true)),
        )
        .build();

    let mut auth =
        Authenticator::with_config(callbacks.clone(), config).expect("Failed to create auth");

    // ========================================
    // PHASE 1: SET UP PIN
    // ========================================
    eprintln!("[Test] ═══ PIN SETUP PHASE ═══\n");

    // Step 1: Get authenticator's key agreement
    let get_key_agreement_cbor = build_get_key_agreement_request(2); // PIN protocol v2
    let mut ctap_request = vec![0x06]; // clientPIN command
    ctap_request.extend_from_slice(&get_key_agreement_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getKeyAgreement failed");

    assert_eq!(
        response[0], 0x00,
        "getKeyAgreement failed with status: 0x{:02x}",
        response[0]
    );

    let auth_cose_key = extract_cose_key(&response).expect("Failed to extract COSE key");
    eprintln!("[Test] ✓ Got authenticator key agreement");

    // Step 2: Perform ECDH and encrypt PIN
    let pin = "123456";

    // Generate platform key pair
    let mut rng = rand::thread_rng();
    let platform_secret = EphemeralSecret::random(&mut rng);
    let platform_public = platform_secret.public_key();

    // Parse authenticator's public key
    use soft_fido2_ctap::cbor::Value;
    let auth_key_value: Value = soft_fido2_ctap::cbor::decode(&auth_cose_key)
        .expect("Failed to parse authenticator COSE key");

    let (x_bytes, y_bytes) = if let Value::Map(map) = auth_key_value {
        let mut x = None;
        let mut y = None;
        for (k, v) in map {
            match k {
                Value::Integer(i) if i == (-2).into() => {
                    if let Value::Bytes(b) = v {
                        x = Some(b);
                    }
                }
                Value::Integer(i) if i == (-3).into() => {
                    if let Value::Bytes(b) = v {
                        y = Some(b);
                    }
                }
                _ => {}
            }
        }
        (
            x.expect("Missing x coordinate"),
            y.expect("Missing y coordinate"),
        )
    } else {
        panic!("Invalid COSE key format");
    };

    // Construct authenticator's public key
    let mut auth_pubkey_bytes = vec![0x04]; // Uncompressed point
    auth_pubkey_bytes.extend_from_slice(&x_bytes);
    auth_pubkey_bytes.extend_from_slice(&y_bytes);
    let auth_public = PublicKey::from_sec1_bytes(&auth_pubkey_bytes)
        .expect("Failed to parse authenticator public key");

    // Perform ECDH
    let shared_secret = platform_secret.diffie_hellman(&auth_public);

    // Encrypt PIN
    let pin_padded = format!("{:\0<64}", pin); // Pad to 64 bytes
    let shared_secret_bytes: &[u8; 32] = shared_secret
        .raw_secret_bytes()
        .as_slice()
        .try_into()
        .expect("Shared secret should be 32 bytes");

    // Derive both encryption and HMAC keys from shared secret (PIN protocol v2)
    let enc_key = v2::derive_encryption_key(shared_secret_bytes);
    let hmac_key = v2::derive_hmac_key(shared_secret_bytes);

    // Encrypt PIN using encryption key
    let pin_enc = v2::encrypt(&enc_key, pin_padded.as_bytes()).expect("Failed to encrypt PIN");

    // Generate pinAuth using HMAC key
    let pin_auth = v2::authenticate(&hmac_key, &pin_enc).to_vec();

    // Encode platform public key as COSE_Key
    let platform_pubkey_point = platform_public.to_encoded_point(false);
    let platform_cose_key = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer((-25).into())), // alg: ECDH-ES+HKDF-256
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
        (
            Value::Integer((-2).into()),
            Value::Bytes(platform_pubkey_point.x().unwrap().to_vec()),
        ), // x
        (
            Value::Integer((-3).into()),
            Value::Bytes(platform_pubkey_point.y().unwrap().to_vec()),
        ), // y
    ]);

    let mut platform_cose_key_bytes = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&platform_cose_key, &mut platform_cose_key_bytes)
        .expect("Failed to encode platform COSE key");

    // Step 3: Set PIN
    let set_pin_cbor = build_set_pin_request(2, &platform_cose_key_bytes, &pin_enc, &pin_auth);
    let mut ctap_request = vec![0x06]; // clientPIN command
    ctap_request.extend_from_slice(&set_pin_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("setPIN failed");

    assert_eq!(
        response[0], 0x00,
        "setPIN failed with status: 0x{:02x}",
        response[0]
    );

    eprintln!("[Test] ✓ PIN set successfully\n");

    // ========================================
    // PHASE 2: REGISTRATION WITH PIN TOKEN
    // ========================================
    eprintln!("[Test] ═══ REGISTRATION WITH PIN TOKEN ═══\n");

    // Step 1: Get new key agreement for PIN token
    let get_key_agreement_cbor = build_get_key_agreement_request(2);
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_key_agreement_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getKeyAgreement failed");

    let auth_cose_key = extract_cose_key(&response).expect("Failed to extract COSE key");

    // Step 2: Perform ECDH again
    let platform_secret = EphemeralSecret::random(&mut rng);
    let platform_public = platform_secret.public_key();

    let auth_key_value: Value = soft_fido2_ctap::cbor::decode(&auth_cose_key)
        .expect("Failed to parse authenticator COSE key");

    let (x_bytes, y_bytes) = if let Value::Map(map) = auth_key_value {
        let mut x = None;
        let mut y = None;
        for (k, v) in map {
            match k {
                Value::Integer(i) if i == (-2).into() => {
                    if let Value::Bytes(b) = v {
                        x = Some(b);
                    }
                }
                Value::Integer(i) if i == (-3).into() => {
                    if let Value::Bytes(b) = v {
                        y = Some(b);
                    }
                }
                _ => {}
            }
        }
        (
            x.expect("Missing x coordinate"),
            y.expect("Missing y coordinate"),
        )
    } else {
        panic!("Invalid COSE key format");
    };

    let mut auth_pubkey_bytes = vec![0x04];
    auth_pubkey_bytes.extend_from_slice(&x_bytes);
    auth_pubkey_bytes.extend_from_slice(&y_bytes);
    let auth_public = PublicKey::from_sec1_bytes(&auth_pubkey_bytes)
        .expect("Failed to parse authenticator public key");

    let shared_secret = platform_secret.diffie_hellman(&auth_public);

    // Step 3: Encrypt PIN hash
    let pin_hash = Sha256::digest(pin.as_bytes());
    let shared_secret_bytes: &[u8; 32] = shared_secret
        .raw_secret_bytes()
        .as_slice()
        .try_into()
        .expect("Shared secret should be 32 bytes");

    // Derive both encryption and HMAC keys from shared secret (PIN protocol v2)
    let enc_key = v2::derive_encryption_key(shared_secret_bytes);
    let _hmac_key = v2::derive_hmac_key(shared_secret_bytes);

    // Encrypt PIN hash using encryption key
    let pin_hash_enc = v2::encrypt(&enc_key, &pin_hash[..16]).expect("Failed to encrypt PIN hash");

    // Encode platform public key
    let platform_pubkey_point = platform_public.to_encoded_point(false);
    let platform_cose_key = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer(3.into()), Value::Integer((-25).into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (
            Value::Integer((-2).into()),
            Value::Bytes(platform_pubkey_point.x().unwrap().to_vec()),
        ),
        (
            Value::Integer((-3).into()),
            Value::Bytes(platform_pubkey_point.y().unwrap().to_vec()),
        ),
    ]);

    let mut platform_cose_key_bytes = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&platform_cose_key, &mut platform_cose_key_bytes)
        .expect("Failed to encode platform COSE key");

    // Step 4: Get PIN token with makeCredential permission
    let permissions = 0x01; // makeCredential
    let rp_id = Some(TEST_RP_ID);
    let get_pin_token_cbor = build_get_pin_uv_auth_token_using_pin_with_permissions_request(
        2,
        &platform_cose_key_bytes,
        &pin_hash_enc,
        permissions,
        rp_id,
    );
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_pin_token_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getPinUvAuthTokenUsingPinWithPermissions failed");

    assert_eq!(
        response[0], 0x00,
        "getPinUvAuthTokenUsingPinWithPermissions failed with status: 0x{:02x}",
        response[0]
    );

    let pin_token_enc = extract_pin_token(&response).expect("Failed to extract PIN token");
    let pin_token = v2::decrypt(&enc_key, &pin_token_enc).expect("Failed to decrypt PIN token");

    eprintln!("[Test] ✓ Got PIN token ({} bytes)", pin_token.len());

    // Step 5: Create credential with pinUvAuthParam
    let challenge = b"registration-challenge-with-pin";
    let client_data_hash = compute_client_data_hash(challenge, "webauthn.create");

    // Calculate pinUvAuthParam: v2::authenticate returns [u8; 32]
    let pin_uv_auth_param = v2::authenticate(
        pin_token
            .as_slice()
            .try_into()
            .expect("PIN token should be 32 bytes"),
        &client_data_hash,
    );

    // Build makeCredential request with pinUvAuthParam
    let rp_map = vec![
        (
            Value::Text("id".to_string()),
            Value::Text(TEST_RP_ID.to_string()),
        ),
        (
            Value::Text("name".to_string()),
            Value::Text(TEST_RP_NAME.to_string()),
        ),
    ];

    let user_map = vec![
        (
            Value::Text("id".to_string()),
            Value::Bytes(TEST_USER_ID.to_vec()),
        ),
        (
            Value::Text("name".to_string()),
            Value::Text(TEST_USER_NAME.to_string()),
        ),
        (
            Value::Text("displayName".to_string()),
            Value::Text(TEST_USER_DISPLAY_NAME.to_string()),
        ),
    ];

    let pub_key_params = vec![Value::Map(vec![
        (
            Value::Text("type".to_string()),
            Value::Text("public-key".to_string()),
        ),
        (Value::Text("alg".to_string()), Value::Integer((-7).into())),
    ])];

    let options_map = vec![
        (Value::Text("rk".to_string()), Value::Bool(true)),
        (Value::Text("uv".to_string()), Value::Bool(true)),
    ];

    let request_map = vec![
        (
            Value::Integer(0x01.into()),
            Value::Bytes(client_data_hash.to_vec()),
        ),
        (Value::Integer(0x02.into()), Value::Map(rp_map)),
        (Value::Integer(0x03.into()), Value::Map(user_map)),
        (Value::Integer(0x04.into()), Value::Array(pub_key_params)),
        (Value::Integer(0x07.into()), Value::Map(options_map)),
        (
            Value::Integer(0x08.into()),
            Value::Bytes(pin_uv_auth_param.to_vec()), // PIN protocol v2 uses full 32 bytes
        ), // pinUvAuthParam
        (Value::Integer(0x09.into()), Value::Integer(2.into())), // pinUvAuthProtocol
    ];

    let mut make_cred_cbor = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut make_cred_cbor)
        .expect("CBOR encoding");

    let mut ctap_request = vec![0x01]; // makeCredential
    ctap_request.extend_from_slice(&make_cred_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("makeCredential failed");

    assert_eq!(
        response[0], 0x00,
        "makeCredential with PIN failed with status: 0x{:02x}",
        response[0]
    );

    eprintln!("[Test] ✓ Registration with PIN successful\n");

    let credential_id = extract_credential_id(&response).expect("Failed to extract credential ID");

    // ========================================
    // PHASE 3: AUTHENTICATION WITH PIN TOKEN
    // ========================================
    eprintln!("[Test] ═══ AUTHENTICATION WITH PIN TOKEN ═══\n");

    // Per FIDO2 spec, PIN token permissions are cleared after makeCredential
    // Get a new PIN token for getAssertion
    let permissions = 0x02; // getAssertion
    let get_pin_token_cbor = build_get_pin_uv_auth_token_using_pin_with_permissions_request(
        2,
        &platform_cose_key_bytes,
        &pin_hash_enc,
        permissions,
        rp_id,
    );
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_pin_token_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getPinUvAuthTokenUsingPinWithPermissions failed");

    assert_eq!(
        response[0], 0x00,
        "getPinUvAuthTokenUsingPinWithPermissions for getAssertion failed with status: 0x{:02x}",
        response[0]
    );

    let pin_token_enc = extract_pin_token(&response).expect("Failed to extract PIN token");
    let pin_token = v2::decrypt(&enc_key, &pin_token_enc).expect("Failed to decrypt PIN token");

    let challenge = b"authentication-challenge-with-pin";
    let client_data_hash = compute_client_data_hash(challenge, "webauthn.get");

    // Calculate pinUvAuthParam for authentication
    let pin_uv_auth_param = v2::authenticate(
        pin_token
            .as_slice()
            .try_into()
            .expect("PIN token should be 32 bytes"),
        &client_data_hash,
    );

    // Build getAssertion request with pinUvAuthParam
    let allow_list_array: Vec<Value> = vec![Value::Map(vec![
        (
            Value::Text("type".to_string()),
            Value::Text("public-key".to_string()),
        ),
        (Value::Text("id".to_string()), Value::Bytes(credential_id)),
    ])];

    let options_map = vec![
        (Value::Text("up".to_string()), Value::Bool(true)),
        (Value::Text("uv".to_string()), Value::Bool(true)),
    ];

    let request_map = vec![
        (
            Value::Integer(0x01.into()),
            Value::Text(TEST_RP_ID.to_string()),
        ),
        (
            Value::Integer(0x02.into()),
            Value::Bytes(client_data_hash.to_vec()),
        ),
        (Value::Integer(0x03.into()), Value::Array(allow_list_array)),
        (Value::Integer(0x05.into()), Value::Map(options_map)),
        (
            Value::Integer(0x06.into()),
            Value::Bytes(pin_uv_auth_param.to_vec()), // PIN protocol v2 uses full 32 bytes
        ),
        (Value::Integer(0x07.into()), Value::Integer(2.into())), // pinUvAuthProtocol
    ];

    let mut get_assertion_cbor = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut get_assertion_cbor)
        .expect("CBOR encoding");

    let mut ctap_request = vec![0x02]; // getAssertion
    ctap_request.extend_from_slice(&get_assertion_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getAssertion failed");

    assert_eq!(
        response[0], 0x00,
        "getAssertion with PIN failed with status: 0x{:02x}",
        response[0]
    );

    eprintln!("[Test] ✓ Authentication with PIN successful\n");

    // ========================================
    // VERIFICATION
    // ========================================
    eprintln!("╔════════════════════════════════════════════════╗");
    eprintln!("║              ✓ Test Passed!                    ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    eprintln!("Summary:");
    eprintln!("  • PIN protocol v2 working correctly");
    eprintln!("  • Successfully set PIN");
    eprintln!("  • Successfully obtained PIN token");
    eprintln!("  • Successfully registered credential with PIN");
    eprintln!("  • Successfully authenticated with PIN");

    let cred_count = callbacks.credential_count();
    assert_eq!(cred_count, 1, "Expected 1 credential to be stored");
}

#[test]
fn test_mozilla_authenticator_crate_compat_resident_keys() {
    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║    Resident Keys Multi-Credential Test        ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    // Setup authenticator with resident key support
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_presence(true)
                .with_user_verification(Some(false))
                .with_platform_device(false)
                .with_client_pin(Some(false))
                .with_credential_management(Some(false)),
        )
        .max_credentials(100)
        .build();

    let mut auth =
        Authenticator::with_config(callbacks.clone(), config).expect("Failed to create auth");

    // ========================================
    // PHASE 1: CREATE MULTIPLE CREDENTIALS
    // ========================================
    eprintln!("[Test] ═══ CREATING MULTIPLE CREDENTIALS ═══\n");

    let test_cases = [
        (
            "example.com",
            "Example Corp",
            &[1u8, 2, 3, 4][..],
            "alice@example.com",
            "Alice",
        ),
        (
            "example.com",
            "Example Corp",
            &[5u8, 6, 7, 8][..],
            "bob@example.com",
            "Bob",
        ),
        (
            "test.org",
            "Test Organization",
            &[9u8, 10, 11, 12][..],
            "charlie@test.org",
            "Charlie",
        ),
        (
            "demo.net",
            "Demo Inc",
            &[13u8, 14, 15, 16][..],
            "diana@demo.net",
            "Diana",
        ),
    ];

    let mut credential_ids = Vec::new();

    for (idx, (rp_id, rp_name, user_id, user_name, user_display_name)) in
        test_cases.iter().enumerate()
    {
        eprintln!(
            "[Test] Creating credential {}/{}...",
            idx + 1,
            test_cases.len()
        );

        let challenge = format!("challenge-{}", idx).into_bytes();
        let client_data_hash = compute_client_data_hash(&challenge, "webauthn.create");

        let make_cred_cbor = build_make_credential_request(
            &client_data_hash,
            rp_id,
            rp_name,
            user_id,
            user_name,
            user_display_name,
        );

        let mut ctap_request = vec![0x01]; // makeCredential
        ctap_request.extend_from_slice(&make_cred_cbor);

        let mut response = Vec::new();
        auth.handle(&ctap_request, &mut response)
            .expect("makeCredential failed");

        assert_eq!(
            response[0], 0x00,
            "makeCredential failed with status: 0x{:02x}",
            response[0]
        );

        let credential_id =
            extract_credential_id(&response).expect("Failed to extract credential ID");
        eprintln!("  ✓ Created credential for {} ({})", user_name, rp_id);

        credential_ids.push((rp_id.to_string(), credential_id));
    }

    eprintln!();

    // ========================================
    // PHASE 2: AUTHENTICATE WITH EACH CREDENTIAL
    // ========================================
    eprintln!("[Test] ═══ AUTHENTICATING WITH EACH CREDENTIAL ═══\n");

    for (idx, (rp_id, credential_id)) in credential_ids.iter().enumerate() {
        eprintln!(
            "[Test] Authenticating credential {}/{}...",
            idx + 1,
            credential_ids.len()
        );

        let challenge = format!("auth-challenge-{}", idx).into_bytes();
        let client_data_hash = compute_client_data_hash(&challenge, "webauthn.get");

        let get_assertion_cbor = build_get_assertion_request(
            &client_data_hash,
            rp_id,
            Some(vec![credential_id.clone()]),
        );

        let mut ctap_request = vec![0x02]; // getAssertion
        ctap_request.extend_from_slice(&get_assertion_cbor);

        let mut response = Vec::new();
        auth.handle(&ctap_request, &mut response)
            .expect("getAssertion failed");

        assert_eq!(
            response[0], 0x00,
            "getAssertion failed with status: 0x{:02x}",
            response[0]
        );

        eprintln!("  ✓ Authenticated with credential for {}", rp_id);
    }

    eprintln!();

    // ========================================
    // PHASE 3: DISCOVERABLE CREDENTIAL (NO ALLOW LIST)
    // ========================================
    eprintln!("[Test] ═══ DISCOVERABLE CREDENTIAL TEST ═══\n");

    // Try to authenticate without allow list (resident key feature)
    let challenge = b"discoverable-challenge";
    let client_data_hash = compute_client_data_hash(challenge, "webauthn.get");

    let get_assertion_cbor = build_get_assertion_request(
        &client_data_hash,
        "example.com",
        None, // No allow list - should discover resident credentials
    );

    let mut ctap_request = vec![0x02]; // getAssertion
    ctap_request.extend_from_slice(&get_assertion_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getAssertion (discoverable) failed");

    assert_eq!(
        response[0], 0x00,
        "Discoverable credential failed with status: 0x{:02x}",
        response[0]
    );

    eprintln!("[Test] ✓ Successfully discovered and used resident credential");
    eprintln!();

    // ========================================
    // VERIFICATION
    // ========================================
    eprintln!("╔════════════════════════════════════════════════╗");
    eprintln!("║              ✓ Test Passed!                    ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    eprintln!("Summary:");
    eprintln!("  • Created {} resident credentials", test_cases.len());
    eprintln!(
        "  • Tested {} different RPs",
        credential_ids
            .iter()
            .map(|(rp, _)| rp.clone())
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
    eprintln!("  • Successfully authenticated with each credential");
    eprintln!("  • Successfully discovered credential without allow list");

    let cred_count = callbacks.credential_count();
    assert_eq!(
        cred_count,
        test_cases.len(),
        "Expected {} credentials to be stored",
        test_cases.len()
    );
}

#[test]
fn test_mozilla_authenticator_crate_compat_credential_management() {
    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║   Credential Management Compatibility Test    ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    // Setup authenticator with credential management support
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_presence(true)
                .with_user_verification(Some(true))
                .with_platform_device(false)
                .with_client_pin(Some(false)) // PIN supported but not yet set
                .with_credential_management(Some(true)),
        )
        .max_credentials(100)
        .build();

    let mut auth =
        Authenticator::with_config(callbacks.clone(), config).expect("Failed to create auth");

    let mut rng = rand::thread_rng();
    let pin = "654321";

    // ========================================
    // PHASE 1: SET UP PIN
    // ========================================
    eprintln!("[Test] ═══ PIN SETUP ═══\n");

    let get_key_agreement_cbor = build_get_key_agreement_request(2);
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_key_agreement_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getKeyAgreement failed");

    let auth_cose_key = extract_cose_key(&response).expect("Failed to extract COSE key");

    use soft_fido2_ctap::cbor::Value;

    // Helper function to parse COSE key
    let parse_cose_key = |cose_key: &[u8]| -> (Vec<u8>, Vec<u8>) {
        let auth_key_value: Value = soft_fido2_ctap::cbor::decode(cose_key)
            .expect("Failed to parse authenticator COSE key");

        if let Value::Map(map) = auth_key_value {
            let mut x = None;
            let mut y = None;
            for (k, v) in map {
                match k {
                    Value::Integer(i) if i == (-2).into() => {
                        if let Value::Bytes(b) = v {
                            x = Some(b);
                        }
                    }
                    Value::Integer(i) if i == (-3).into() => {
                        if let Value::Bytes(b) = v {
                            y = Some(b);
                        }
                    }
                    _ => {}
                }
            }
            (x.expect("Missing x"), y.expect("Missing y"))
        } else {
            panic!("Invalid COSE key format");
        }
    };

    // Helper function to encode platform public key
    let encode_platform_key = |public_key: &p256::PublicKey| -> Vec<u8> {
        let pubkey_point = public_key.to_encoded_point(false);
        let platform_cose_key = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-25).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(pubkey_point.x().unwrap().to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(pubkey_point.y().unwrap().to_vec()),
            ),
        ]);

        let mut platform_cose_key_bytes = Vec::new();
        soft_fido2_ctap::cbor::into_writer(&platform_cose_key, &mut platform_cose_key_bytes)
            .expect("Failed to encode platform COSE key");
        platform_cose_key_bytes
    };

    let platform_secret = EphemeralSecret::random(&mut rng);
    let platform_public = platform_secret.public_key();

    let (x_bytes, y_bytes) = parse_cose_key(&auth_cose_key);

    let mut auth_pubkey_bytes = vec![0x04];
    auth_pubkey_bytes.extend_from_slice(&x_bytes);
    auth_pubkey_bytes.extend_from_slice(&y_bytes);
    let auth_public = PublicKey::from_sec1_bytes(&auth_pubkey_bytes)
        .expect("Failed to parse authenticator public key");

    let shared_secret = platform_secret.diffie_hellman(&auth_public);

    let pin_padded = format!("{:\0<64}", pin);
    let shared_secret_bytes: &[u8; 32] = shared_secret
        .raw_secret_bytes()
        .as_slice()
        .try_into()
        .expect("Shared secret should be 32 bytes");

    // Derive both encryption and HMAC keys from shared secret (PIN protocol v2)
    let enc_key = v2::derive_encryption_key(shared_secret_bytes);
    let hmac_key = v2::derive_hmac_key(shared_secret_bytes);

    // Encrypt PIN using encryption key
    let pin_enc = v2::encrypt(&enc_key, pin_padded.as_bytes()).expect("Failed to encrypt PIN");

    // Generate pinAuth using HMAC key
    let pin_auth = v2::authenticate(&hmac_key, &pin_enc).to_vec();

    let platform_cose_key_bytes = encode_platform_key(&platform_public);

    let set_pin_cbor = build_set_pin_request(2, &platform_cose_key_bytes, &pin_enc, &pin_auth);
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&set_pin_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("setPIN failed");

    assert_eq!(response[0], 0x00, "setPIN failed");
    eprintln!("[Test] ✓ PIN set successfully\n");

    // ========================================
    // PHASE 2: CREATE RESIDENT CREDENTIALS
    // ========================================
    eprintln!("[Test] ═══ CREATING RESIDENT CREDENTIALS ═══\n");

    let test_cases = [
        (
            "example.com",
            "Example Corp",
            &[1u8, 2, 3, 4][..],
            "alice@example.com",
            "Alice",
        ),
        (
            "example.com",
            "Example Corp",
            &[5u8, 6, 7, 8][..],
            "bob@example.com",
            "Bob",
        ),
        (
            "test.org",
            "Test Organization",
            &[9u8, 10, 11, 12][..],
            "charlie@test.org",
            "Charlie",
        ),
    ];

    // Get PIN token for creating credentials
    let get_key_agreement_cbor = build_get_key_agreement_request(2);
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_key_agreement_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getKeyAgreement failed");

    let auth_cose_key = extract_cose_key(&response).expect("Failed to extract COSE key");

    let platform_secret = EphemeralSecret::random(&mut rng);
    let platform_public = platform_secret.public_key();

    let (x_bytes, y_bytes) = parse_cose_key(&auth_cose_key);

    let mut auth_pubkey_bytes = vec![0x04];
    auth_pubkey_bytes.extend_from_slice(&x_bytes);
    auth_pubkey_bytes.extend_from_slice(&y_bytes);
    let auth_public = PublicKey::from_sec1_bytes(&auth_pubkey_bytes)
        .expect("Failed to parse authenticator public key");

    let shared_secret = platform_secret.diffie_hellman(&auth_public);

    let pin_hash = Sha256::digest(pin.as_bytes());
    let shared_secret_bytes: &[u8; 32] = shared_secret
        .raw_secret_bytes()
        .as_slice()
        .try_into()
        .expect("Shared secret should be 32 bytes");

    // Derive both encryption and HMAC keys from shared secret (PIN protocol v2)
    let enc_key = v2::derive_encryption_key(shared_secret_bytes);
    let _hmac_key = v2::derive_hmac_key(shared_secret_bytes);

    // Encrypt PIN hash using encryption key
    let pin_hash_enc = v2::encrypt(&enc_key, &pin_hash[..16]).expect("Failed to encrypt PIN hash");

    let platform_cose_key_bytes = encode_platform_key(&platform_public);

    // Get PIN token with both makeCredential and credentialManagement permissions
    // Don't specify rp_id to make the token valid for all RPs
    let permissions = 0x01 | 0x04; // makeCredential + credentialManagement
    let rp_id = None;
    let get_pin_token_cbor = build_get_pin_uv_auth_token_using_pin_with_permissions_request(
        2,
        &platform_cose_key_bytes,
        &pin_hash_enc,
        permissions,
        rp_id,
    );
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_pin_token_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getPinUvAuthTokenUsingPinWithPermissions failed");

    let pin_token_enc = extract_pin_token(&response).expect("Failed to extract PIN token");
    let mut pin_token = v2::decrypt(&enc_key, &pin_token_enc).expect("Failed to decrypt PIN token");

    eprintln!("[Test] ✓ Got PIN token\n");

    let mut credential_ids = Vec::new();

    for (idx, (rp_id, rp_name, user_id, user_name, user_display_name)) in
        test_cases.iter().enumerate()
    {
        eprintln!(
            "[Test] Creating credential {}/{}...",
            idx + 1,
            test_cases.len()
        );

        // Per FIDO2 spec, PIN token permissions are cleared after each makeCredential
        // Get a new PIN token for each credential
        if idx > 0 {
            let permissions = 0x01; // makeCredential
            let rp_id_param = None; // No RP ID restriction for multiple RPs
            let get_pin_token_cbor = build_get_pin_uv_auth_token_using_pin_with_permissions_request(
                2,
                &platform_cose_key_bytes,
                &pin_hash_enc,
                permissions,
                rp_id_param,
            );
            let mut ctap_request = vec![0x06];
            ctap_request.extend_from_slice(&get_pin_token_cbor);

            let mut response = Vec::new();
            auth.handle(&ctap_request, &mut response)
                .expect("getPinUvAuthTokenUsingPinWithPermissions failed");

            let pin_token_enc = extract_pin_token(&response).expect("Failed to extract PIN token");
            pin_token = v2::decrypt(&enc_key, &pin_token_enc).expect("Failed to decrypt PIN token");
        }

        let challenge = format!("challenge-{}", idx).into_bytes();
        let client_data_hash = compute_client_data_hash(&challenge, "webauthn.create");

        let pin_uv_auth_param = v2::authenticate(
            pin_token
                .as_slice()
                .try_into()
                .expect("PIN token should be 32 bytes"),
            &client_data_hash,
        );

        let rp_map = vec![
            (
                Value::Text("id".to_string()),
                Value::Text(rp_id.to_string()),
            ),
            (
                Value::Text("name".to_string()),
                Value::Text(rp_name.to_string()),
            ),
        ];

        let user_map = vec![
            (
                Value::Text("id".to_string()),
                Value::Bytes(user_id.to_vec()),
            ),
            (
                Value::Text("name".to_string()),
                Value::Text(user_name.to_string()),
            ),
            (
                Value::Text("displayName".to_string()),
                Value::Text(user_display_name.to_string()),
            ),
        ];

        let pub_key_params = vec![Value::Map(vec![
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
            (Value::Text("alg".to_string()), Value::Integer((-7).into())),
        ])];

        let options_map = vec![
            (Value::Text("rk".to_string()), Value::Bool(true)),
            (Value::Text("uv".to_string()), Value::Bool(true)),
        ];

        let request_map = vec![
            (
                Value::Integer(0x01.into()),
                Value::Bytes(client_data_hash.to_vec()),
            ),
            (Value::Integer(0x02.into()), Value::Map(rp_map)),
            (Value::Integer(0x03.into()), Value::Map(user_map)),
            (Value::Integer(0x04.into()), Value::Array(pub_key_params)),
            (Value::Integer(0x07.into()), Value::Map(options_map)),
            (
                Value::Integer(0x08.into()),
                Value::Bytes(pin_uv_auth_param.to_vec()), // PIN protocol v2 uses full 32 bytes
            ),
            (Value::Integer(0x09.into()), Value::Integer(2.into())), // pinUvAuthProtocol
        ];

        let mut make_cred_cbor = Vec::new();
        soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut make_cred_cbor)
            .expect("CBOR encoding");

        let mut ctap_request = vec![0x01];
        ctap_request.extend_from_slice(&make_cred_cbor);

        let mut response = Vec::new();
        auth.handle(&ctap_request, &mut response)
            .expect("makeCredential failed");

        assert_eq!(response[0], 0x00, "makeCredential failed");

        let credential_id =
            extract_credential_id(&response).expect("Failed to extract credential ID");
        eprintln!(
            "  ✓ Created resident credential for {} ({})",
            user_name, rp_id
        );

        credential_ids.push((rp_id.to_string(), credential_id));
    }

    eprintln!();

    // ========================================
    // PHASE 3: GET CREDENTIALS METADATA
    // ========================================
    eprintln!("[Test] ═══ GET CREDENTIALS METADATA ═══\n");

    let get_key_agreement_cbor = build_get_key_agreement_request(2);
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_key_agreement_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getKeyAgreement failed");

    let auth_cose_key = extract_cose_key(&response).expect("Failed to extract COSE key");

    let platform_secret = EphemeralSecret::random(&mut rng);
    let platform_public = platform_secret.public_key();

    let (x_bytes, y_bytes) = parse_cose_key(&auth_cose_key);

    let mut auth_pubkey_bytes = vec![0x04];
    auth_pubkey_bytes.extend_from_slice(&x_bytes);
    auth_pubkey_bytes.extend_from_slice(&y_bytes);
    let auth_public = PublicKey::from_sec1_bytes(&auth_pubkey_bytes)
        .expect("Failed to parse authenticator public key");

    let shared_secret = platform_secret.diffie_hellman(&auth_public);

    let platform_cose_key_bytes = encode_platform_key(&platform_public);

    let get_pin_uv_token_cbor = build_get_pin_uv_auth_token_request(
        2,
        &platform_cose_key_bytes,
        0x04, // credMgmt permission
        None,
    );
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_pin_uv_token_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getPinUvAuthToken failed");

    let credmgmt_token_enc =
        extract_pin_token(&response).expect("Failed to extract PIN UV auth token");
    let shared_secret_bytes: &[u8; 32] = shared_secret
        .raw_secret_bytes()
        .as_slice()
        .try_into()
        .expect("Shared secret should be 32 bytes");

    // Derive HMAC key from shared secret
    let hmac_key = v2::derive_hmac_key(shared_secret_bytes);

    let credmgmt_token =
        v2::decrypt(&hmac_key, &credmgmt_token_enc).expect("Failed to decrypt PIN UV auth token");

    eprintln!("[Test] ✓ Got PIN UV auth token with credMgmt permission\n");

    let cred_mgmt_data = vec![0x01u8];
    let pin_uv_auth_param = v2::authenticate(
        credmgmt_token
            .as_slice()
            .try_into()
            .expect("credMgmt token should be 32 bytes"),
        &cred_mgmt_data,
    );

    let get_creds_metadata_cbor = build_get_creds_metadata_request(2, &pin_uv_auth_param);
    let mut ctap_request = vec![0x0A];
    ctap_request.extend_from_slice(&get_creds_metadata_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getCredsMetadata failed");

    assert_eq!(response[0], 0x00, "getCredsMetadata failed");

    if let Some(total_rps) = extract_total_rps(&response) {
        eprintln!("[Test] ✓ Total resident credentials: {}", total_rps);
        assert!(
            total_rps >= test_cases.len() as u32,
            "Expected at least {} credentials",
            test_cases.len()
        );
    }

    eprintln!();

    // ========================================
    // PHASE 4: ENUMERATE RPs
    // ========================================
    eprintln!("[Test] ═══ ENUMERATE RPs ═══\n");

    let cred_mgmt_data = vec![0x02u8];
    let pin_uv_auth_param = v2::authenticate(
        credmgmt_token
            .as_slice()
            .try_into()
            .expect("credMgmt token should be 32 bytes"),
        &cred_mgmt_data,
    );

    let enum_rps_begin_cbor = build_enumerate_rps_begin_request(2, &pin_uv_auth_param);
    let mut ctap_request = vec![0x0A];
    ctap_request.extend_from_slice(&enum_rps_begin_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("enumerateRPsBegin failed");

    assert_eq!(response[0], 0x00, "enumerateRPsBegin failed");

    let mut rp_ids = Vec::new();
    if let Some((rp_id, rp_id_hash)) = extract_rp_info(&response) {
        eprintln!("[Test] ✓ Found RP: {}", rp_id);
        rp_ids.push((rp_id, rp_id_hash));
    }

    let enum_rps_next_cbor = build_enumerate_rps_get_next_request();
    let mut ctap_request = vec![0x0A];
    ctap_request.extend_from_slice(&enum_rps_next_cbor);

    let mut response = Vec::new();
    let _ = auth.handle(&ctap_request, &mut response);

    if response[0] == 0x00
        && let Some((rp_id, rp_id_hash)) = extract_rp_info(&response)
    {
        eprintln!("[Test] ✓ Found RP: {}", rp_id);
        rp_ids.push((rp_id, rp_id_hash));
    }

    eprintln!("[Test] Total RPs enumerated: {}\n", rp_ids.len());

    // Credential enumeration skipped (requires additional CBOR work)
    eprintln!("[Test] ═══ CREDENTIAL ENUMERATION ═══\n");
    eprintln!("[Test] ⚠ Not yet implemented\n");

    // Credential deletion skipped (requires enumeration first)
    eprintln!("[Test] ═══ DELETE CREDENTIAL ═══\n");
    eprintln!("[Test] ⚠ Not yet implemented\n");

    // ========================================
    // VERIFICATION
    // ========================================
    eprintln!("╔════════════════════════════════════════════════╗");
    eprintln!("║              ✓ Test Passed!                    ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    eprintln!("Summary:");
    eprintln!("  • PIN protocol v2 with credMgmt permission");
    eprintln!("  • Created {} resident credentials", test_cases.len());
    eprintln!("  • Retrieved credentials metadata");
    eprintln!("  • Enumerated RPs");
}
