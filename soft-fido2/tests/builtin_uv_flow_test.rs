//! Integration tests for built-in UV (user verification) flow
//!
//! Tests the fix where built-in UV is automatically used when available
//! but client doesn't explicitly request it.

mod common;

use soft_fido2::{Authenticator, AuthenticatorConfig, AuthenticatorOptions};
use soft_fido2_ctap::cbor::Value;

use base64::Engine;
use common::TestCallbacks;
use sha2::{Digest, Sha256};

const RP_ID: &str = "uv-test.com";
const ORIGIN: &str = "https://uv-test.com";

#[test]
fn test_builtin_uv_auto_used_when_available_no_client_request() {
    let callbacks = TestCallbacks::new();

    // Configure authenticator with built-in UV enabled (uv = true)
    // but without PIN set
    let config = AuthenticatorConfig::builder()
        .aaguid([0u8; 16])
        .max_credentials(100)
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true)) // Built-in UV enabled
                .with_client_pin(Some(false)) // No PIN support
                .with_always_uv(Some(true)), // Always require UV
        )
        .build();

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // Registration WITHOUT requesting uv in options
    // The authenticator should automatically use built-in UV
    let challenge = b"registration-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");

    let make_cred_request = build_make_credential_cbor_no_uv(
        &client_data_hash,
        RP_ID,
        "UV Test Corp",
        &[1, 2, 3, 4],
        "user@uv-test.com",
        "UV User",
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("makeCredential should succeed with auto UV");

    let status = response[0];
    assert_eq!(
        status, 0x00,
        "makeCredential should succeed - built-in UV should be auto-used, got status: 0x{:02x}",
        status
    );

    // Verify credential was stored
    assert_eq!(callbacks.credential_count(), 1);
}

#[test]
fn test_builtin_uv_make_cred_uv_not_rqd_flow() {
    let callbacks = TestCallbacks::new();

    // Configure authenticator with makeCredUvNotRqd = true and built-in UV
    let config = AuthenticatorConfig::builder()
        .aaguid([0u8; 16])
        .max_credentials(100)
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true)) // Built-in UV enabled
                .with_make_cred_uv_not_required(Some(true))
                .with_client_pin(Some(false)),
        )
        .build();

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // Create resident credential without UV request
    // makeCredUvNotRqd allows this, but built-in UV should still be auto-used
    let challenge = b"reg-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");

    let make_cred_request = build_make_credential_cbor_no_uv(
        &client_data_hash,
        RP_ID,
        "Test",
        &[1, 2, 3, 4],
        "user@test.com",
        "User",
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("makeCredential should succeed");

    let status = response[0];
    assert_eq!(
        status, 0x00,
        "makeCredential should succeed with auto UV for resident key"
    );
}

#[test]
fn test_get_assertion_auto_uv_when_available() {
    let callbacks = TestCallbacks::new();

    // Configure with built-in UV and alwaysUv
    let config = AuthenticatorConfig::builder()
        .aaguid([0u8; 16])
        .max_credentials(100)
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(false))
                .with_always_uv(Some(true)),
        )
        .build();

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // First, register a credential (with UV)
    let challenge = b"reg-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");

    let make_cred_request = build_make_credential_cbor_with_uv(
        &client_data_hash,
        RP_ID,
        "Test",
        &[1, 2, 3, 4],
        "user@test.com",
        "User",
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("makeCredential failed");
    assert_eq!(response[0], 0x00);

    // Now authenticate WITHOUT requesting UV in options
    // Built-in UV should be auto-used due to alwaysUv
    let challenge = b"auth-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.get");

    let get_assertion_request = build_get_assertion_cbor_no_uv(&client_data_hash, RP_ID);

    let mut ctap_request = vec![0x02];
    ctap_request.extend_from_slice(&get_assertion_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getAssertion should succeed with auto UV");

    let status = response[0];
    assert_eq!(
        status, 0x00,
        "getAssertion should succeed - built-in UV should be auto-used, got status: 0x{:02x}",
        status
    );
}

#[test]
fn test_no_builtin_uv_fails_without_pin() {
    let callbacks = TestCallbacks::new();

    // Configure WITHOUT built-in UV, without PIN, but with alwaysUv
    // This should fail because there's no way to satisfy UV requirement
    let config = AuthenticatorConfig::builder()
        .aaguid([0u8; 16])
        .max_credentials(100)
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(false)) // No built-in UV
                .with_client_pin(Some(false)) // No PIN
                .with_always_uv(Some(true)), // But always require UV
        )
        .build();

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // Registration should fail - no UV method available
    let challenge = b"reg-challenge";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");

    let make_cred_request = build_make_credential_cbor_no_uv(
        &client_data_hash,
        RP_ID,
        "Test",
        &[1, 2, 3, 4],
        "user@test.com",
        "User",
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    let result = auth.handle(&ctap_request, &mut response);

    // Should fail because no UV method is available
    assert!(
        result.is_err() || (!response.is_empty() && response[0] != 0x00),
        "Should fail when no UV method is available and alwaysUv is true"
    );
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

fn build_make_credential_cbor_no_uv(
    client_data_hash: &[u8],
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
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
        (Value::Text("alg".to_string()), Value::Integer((-7).into())),
    ])];

    // Options WITHOUT uv
    let options_map = vec![
        (Value::Text("rk".to_string()), Value::Bool(true)),
        (Value::Text("up".to_string()), Value::Bool(true)),
        // uv is intentionally omitted
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

fn build_make_credential_cbor_with_uv(
    client_data_hash: &[u8],
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
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
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

fn build_get_assertion_cbor_no_uv(client_data_hash: &[u8], rp_id: &str) -> Vec<u8> {
    // Options without uv
    let options_map = vec![
        (Value::Text("up".to_string()), Value::Bool(true)),
        // uv is intentionally omitted
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
