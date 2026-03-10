//! Integration tests for EdDSA (Ed25519) algorithm support
//!
//! Tests the complete WebAuthn flow using EdDSA credentials.

mod common;

use soft_fido2::{Authenticator, AuthenticatorConfig, AuthenticatorOptions};
use soft_fido2_ctap::cbor::Value;

use base64::Engine;
use common::TestCallbacks;
use sha2::{Digest, Sha256};

const PIN: &str = "123456";
const RP_ID: &str = "eddsa-test.com";
const ORIGIN: &str = "https://eddsa-test.com";

#[test]
fn test_webauthn_eddsa_registration_and_auth() {
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
            0x7c, 0x88,
        ])
        .max_credentials(100)
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(true)),
        )
        .build();

    let pin_hash = compute_pin_hash(PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // Registration with EdDSA
    let challenge = b"eddsa-registration-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");

    let make_cred_request = build_make_credential_cbor_eddsa(
        &client_data_hash,
        RP_ID,
        "EdDSA Test Corp",
        &[1, 2, 3, 4],
        "user@eddsa-test.com",
        "EdDSA User",
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("EdDSA makeCredential failed");

    let status = response[0];
    assert_eq!(
        status, 0x00,
        "EdDSA makeCredential failed with status: 0x{:02x}",
        status
    );

    // Authentication with EdDSA
    let challenge = b"eddsa-auth-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.get");

    let get_assertion_request = build_get_assertion_cbor(&client_data_hash, RP_ID);

    let mut ctap_request = vec![0x02];
    ctap_request.extend_from_slice(&get_assertion_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("EdDSA getAssertion failed");

    let status = response[0];
    assert_eq!(
        status, 0x00,
        "EdDSA getAssertion failed with status: 0x{:02x}",
        status
    );

    assert_eq!(callbacks.credential_count(), 1);
}

#[test]
fn test_webauthn_es256_and_eddsa_both_supported() {
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
            0x7c, 0x88,
        ])
        .max_credentials(100)
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(true)),
        )
        .build();

    let pin_hash = compute_pin_hash(PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // Register with ES256
    let challenge = b"es256-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");
    let make_cred_request = build_make_credential_cbor_with_alg(
        &client_data_hash,
        RP_ID,
        "Test Corp",
        &[1, 2, 3, 4],
        "user1@test.com",
        "User ES256",
        -7, // ES256
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("ES256 makeCredential failed");
    assert_eq!(response[0], 0x00, "ES256 registration failed");

    // Register with EdDSA
    let challenge = b"eddsa-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");
    let make_cred_request = build_make_credential_cbor_with_alg(
        &client_data_hash,
        RP_ID,
        "Test Corp",
        &[5, 6, 7, 8],
        "user2@test.com",
        "User EdDSA",
        -8, // EdDSA
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("EdDSA makeCredential failed");
    assert_eq!(response[0], 0x00, "EdDSA registration failed");

    // Both credentials should be stored
    assert_eq!(callbacks.credential_count(), 2);

    // Authenticate - should find both credentials
    let challenge = b"auth-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.get");
    let get_assertion_request = build_get_assertion_cbor(&client_data_hash, RP_ID);

    let mut ctap_request = vec![0x02];
    ctap_request.extend_from_slice(&get_assertion_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getAssertion failed");
    assert_eq!(response[0], 0x00, "Authentication failed");
}

#[test]
fn test_webauthn_ed25519_registration_and_auth() {
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
            0x7c, 0x88,
        ])
        .max_credentials(100)
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(true)),
        )
        .build();

    let pin_hash = compute_pin_hash(PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // Registration with Ed25519 (-19)
    let challenge = b"ed25519-registration-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");

    let make_cred_request = build_make_credential_cbor_with_alg(
        &client_data_hash,
        RP_ID,
        "Ed25519 Test Corp",
        &[1, 2, 3, 4],
        "user@ed25519-test.com",
        "Ed25519 User",
        -19, // Ed25519 (IANA recommended)
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("Ed25519 makeCredential failed");

    let status = response[0];
    assert_eq!(
        status, 0x00,
        "Ed25519 makeCredential failed with status: 0x{:02x}",
        status
    );

    // Authentication with Ed25519
    let challenge = b"ed25519-auth-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.get");

    let get_assertion_request = build_get_assertion_cbor(&client_data_hash, RP_ID);

    let mut ctap_request = vec![0x02];
    ctap_request.extend_from_slice(&get_assertion_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("Ed25519 getAssertion failed");

    let status = response[0];
    assert_eq!(
        status, 0x00,
        "Ed25519 getAssertion failed with status: 0x{:02x}",
        status
    );

    assert_eq!(callbacks.credential_count(), 1);
}

#[test]
fn test_eddsa_algorithm_preference() {
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([0u8; 16])
        .max_credentials(100)
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(true)),
        )
        .build();

    let pin_hash = compute_pin_hash(PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // Request EdDSA as first preference (should be selected)
    let challenge = b"preference-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");

    // Build pubKeyCredParams with EdDSA first, then ES256
    let pub_key_params = vec![
        Value::Map(vec![
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
            (Value::Text("alg".to_string()), Value::Integer((-8).into())), // EdDSA first
        ]),
        Value::Map(vec![
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
            (Value::Text("alg".to_string()), Value::Integer((-7).into())), // ES256 second
        ]),
    ];

    let rp_map = vec![
        (
            Value::Text("id".to_string()),
            Value::Text(RP_ID.to_string()),
        ),
        (
            Value::Text("name".to_string()),
            Value::Text("Test".to_string()),
        ),
    ];

    let user_map = vec![
        (Value::Text("id".to_string()), Value::Bytes(vec![1, 2, 3])),
        (
            Value::Text("name".to_string()),
            Value::Text("user@test.com".to_string()),
        ),
        (
            Value::Text("displayName".to_string()),
            Value::Text("User".to_string()),
        ),
    ];

    let options_map = vec![
        (Value::Text("rk".to_string()), Value::Bool(true)),
        (Value::Text("uv".to_string()), Value::Bool(true)),
    ];

    let request_map = vec![
        (Value::Integer(0x01.into()), Value::Bytes(client_data_hash)),
        (Value::Integer(0x02.into()), Value::Map(rp_map)),
        (Value::Integer(0x03.into()), Value::Map(user_map)),
        (Value::Integer(0x04.into()), Value::Array(pub_key_params)),
        (Value::Integer(0x07.into()), Value::Map(options_map)),
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&buffer);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("makeCredential failed");
    assert_eq!(response[0], 0x00, "makeCredential failed");

    // Verify the credential was created (EdDSA should have been selected)
    assert_eq!(callbacks.credential_count(), 1);
}

fn compute_pin_hash(pin: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    hasher.finalize().into()
}

fn compute_client_data_hash(challenge: &[u8], origin: &str, ceremony_type: &str) -> Vec<u8> {
    let client_data_json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
        ceremony_type,
        base64::prelude::BASE64_STANDARD.encode(challenge),
        origin
    );
    Sha256::digest(client_data_json.as_bytes()).to_vec()
}

fn build_make_credential_cbor_eddsa(
    client_data_hash: &[u8],
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
) -> Vec<u8> {
    build_make_credential_cbor_with_alg(
        client_data_hash,
        rp_id,
        rp_name,
        user_id,
        user_name,
        user_display_name,
        -8, // EdDSA
    )
}

fn build_make_credential_cbor_with_alg(
    client_data_hash: &[u8],
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
    alg: i32,
) -> Vec<u8> {
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
        (Value::Text("alg".to_string()), Value::Integer(alg.into())),
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
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

fn build_get_assertion_cbor(client_data_hash: &[u8], rp_id: &str) -> Vec<u8> {
    let options_map = vec![
        (Value::Text("up".to_string()), Value::Bool(true)),
        (Value::Text("uv".to_string()), Value::Bool(true)),
    ];

    let request_map = vec![
        (Value::Integer(0x01.into()), Value::Text(rp_id.to_string())),
        (
            Value::Integer(0x02.into()),
            Value::Bytes(client_data_hash.to_vec()),
        ),
        (Value::Integer(0x05.into()), Value::Map(options_map)),
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}
