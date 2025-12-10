//! no_std comprehensive test
//!
//! Run with: `cargo test --test nostd_comprehensive_test --no-default-features`

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg(not(feature = "std"))]

extern crate alloc;

mod common;

use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use common::TestCallbacks;
use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions,
};
use soft_fido2_ctap::cbor::Value;

use sha2::{Digest, Sha256};

const PIN: &str = "123456";
const RP_ID: &str = "example.com";
const RP_NAME: &str = "Example Corp";

fn compute_pin_hash(pin: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    hasher.finalize().into()
}

fn compute_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn create_config() -> AuthenticatorConfig {
    AuthenticatorConfig::builder()
        .aaguid([
            0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
            0x7c, 0x88,
        ])
        .max_credentials(100)
        .extensions(vec!["credProtect".to_string(), "hmac-secret".to_string()])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(true)),
        )
        .build()
}

fn build_make_credential(
    client_data_hash: &[u8],
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display: &str,
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
            Value::Text(user_display.to_string()),
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

fn build_get_assertion(client_data_hash: &[u8], rp_id: &str) -> Vec<u8> {
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

#[test]
fn test_get_info() {
    let callbacks = TestCallbacks::new();
    let config = create_config();

    let pin_hash = compute_pin_hash(PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth =
        Authenticator::with_config(callbacks, config).expect("Failed to create authenticator");

    let mut response = Vec::new();
    auth.handle(&[0x04], &mut response).expect("getInfo failed");

    assert!(!response.is_empty());
    assert_eq!(response[0], 0x00);
}

#[test]
fn test_make_credential_and_get_assertion() {
    let callbacks = TestCallbacks::new();
    let config = create_config();

    let pin_hash = compute_pin_hash(PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // makeCredential
    let client_data_hash = compute_hash(b"registration-challenge");
    let request = build_make_credential(
        &client_data_hash,
        RP_ID,
        RP_NAME,
        &[1, 2, 3, 4],
        "alice@example.com",
        "Alice",
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("makeCredential failed");

    assert_eq!(response[0], 0x00);
    assert_eq!(callbacks.credential_count(), 1);

    // getAssertion
    let client_data_hash = compute_hash(b"authentication-challenge");
    let request = build_get_assertion(&client_data_hash, RP_ID);

    let mut ctap_request = vec![0x02];
    ctap_request.extend_from_slice(&request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getAssertion failed");

    assert_eq!(response[0], 0x00);
}

#[test]
fn test_multiple_credentials() {
    let callbacks = TestCallbacks::new();
    let config = create_config();

    let pin_hash = compute_pin_hash(PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    // Register 5 users
    for i in 0..5u8 {
        let client_data_hash = compute_hash(&[i; 32]);
        let user_id = [i, i + 1, i + 2];
        let user_name = format!("user{}@example.com", i);
        let request = build_make_credential(
            &client_data_hash,
            RP_ID,
            RP_NAME,
            &user_id,
            &user_name,
            "User",
        );

        let mut ctap_request = vec![0x01];
        ctap_request.extend_from_slice(&request);

        let mut response = Vec::new();
        auth.handle(&ctap_request, &mut response)
            .expect("makeCredential failed");

        assert_eq!(response[0], 0x00);
    }

    assert_eq!(callbacks.credential_count(), 5);

    // Authenticate
    for i in 0..5u8 {
        let client_data_hash = compute_hash(&[i + 100; 32]);
        let request = build_get_assertion(&client_data_hash, RP_ID);

        let mut ctap_request = vec![0x02];
        ctap_request.extend_from_slice(&request);

        let mut response = Vec::new();
        auth.handle(&ctap_request, &mut response)
            .expect("getAssertion failed");

        assert_eq!(response[0], 0x00);
    }
}

#[test]
fn test_multiple_rps() {
    let callbacks = TestCallbacks::new();
    let config = create_config();

    let pin_hash = compute_pin_hash(PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth = Authenticator::with_config(callbacks.clone(), config)
        .expect("Failed to create authenticator");

    let rps = ["example.com", "test.com", "demo.org"];

    for (idx, rp_id) in rps.iter().enumerate() {
        let client_data_hash = compute_hash(&[idx as u8; 32]);
        let user_id = [idx as u8, idx as u8 + 1];
        let request = build_make_credential(
            &client_data_hash,
            rp_id,
            rp_id,
            &user_id,
            "user@example.com",
            "User",
        );

        let mut ctap_request = vec![0x01];
        ctap_request.extend_from_slice(&request);

        let mut response = Vec::new();
        auth.handle(&ctap_request, &mut response)
            .expect("makeCredential failed");

        assert_eq!(response[0], 0x00);
    }

    assert_eq!(callbacks.credential_count(), 3);

    let rp_list = callbacks.enumerate_rps().expect("enumerate_rps failed");
    assert_eq!(rp_list.len(), 3);
}

#[test]
fn test_error_handling() {
    let callbacks = TestCallbacks::new();
    let config = create_config();

    let pin_hash = compute_pin_hash(PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth =
        Authenticator::with_config(callbacks, config).expect("Failed to create authenticator");

    // Invalid command
    let mut response = Vec::new();
    let _result = auth.handle(&[0xFF], &mut response);
    assert!(response[0] != 0x00);

    // Malformed CBOR
    let mut request = vec![0x01];
    request.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    let mut response = Vec::new();
    let _result = auth.handle(&request, &mut response);
    assert!(response[0] != 0x00);
}
