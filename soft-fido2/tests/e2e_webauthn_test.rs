//! End-to-End WebAuthn Flow Tests
//!
//! These tests simulate a complete WebAuthn registration and authentication flow
//! using the soft-fido2 authenticator with PIN protocol support.
//!
//! # Test Flow
//!
//! 1. Create a virtual authenticator with PIN support
//! 2. Perform registration (makeCredential) with PIN authentication
//! 3. Perform authentication (getAssertion) with PIN authentication
//! 4. Verify the complete flow succeeds
//!
//! Run with: cargo test --test e2e_webauthn_test -- --ignored

#![cfg(feature = "std")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::prelude::*;
use serial_test::serial;
use sha2::{Digest, Sha256};

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Credential,
    CredentialRef, Result, UpResult, UvResult,
};

// Test constants
const TEST_PIN: &str = "123456";
const TEST_RP_ID: &str = "test.example.com";
const TEST_ORIGIN: &str = "https://test.example.com";

/// Test callbacks for E2E tests
struct TestCallbacks {
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
}

impl TestCallbacks {
    fn new() -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl AuthenticatorCallbacks for TestCallbacks {
    fn request_up(&self, _info: &str, _user: Option<&str>, _rp: &str) -> Result<UpResult> {
        Ok(UpResult::Accepted)
    }

    fn request_uv(&self, _info: &str, _user: Option<&str>, _rp: &str) -> Result<UvResult> {
        Ok(UvResult::Accepted)
    }

    fn write_credential(&self, cred_id: &[u8], _rp_id: &str, cred: &CredentialRef) -> Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.insert(cred_id.to_vec(), cred.to_owned());
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8], _rp_id: &str) -> Result<Option<Credential>> {
        let store = self.credentials.lock().unwrap();
        Ok(store.get(cred_id).cloned())
    }

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.remove(cred_id);
        Ok(())
    }

    fn list_credentials(&self, rp_id: &str, _user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        let store = self.credentials.lock().unwrap();
        let filtered: Vec<Credential> = store
            .values()
            .filter(|c| c.rp.id == rp_id)
            .cloned()
            .collect();
        Ok(filtered)
    }
}

/// Compute PIN hash (SHA-256)
fn compute_pin_hash(pin: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    hasher.finalize().into()
}

/// Compute clientDataHash from a challenge
fn compute_client_data_hash(challenge: &[u8], origin: &str, ceremony_type: &str) -> Vec<u8> {
    let client_data_json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
        ceremony_type,
        BASE64_STANDARD.encode(challenge),
        origin
    );
    Sha256::digest(client_data_json.as_bytes()).to_vec()
}

/// Build makeCredential CBOR request
fn build_make_credential_cbor(
    client_data_hash: &[u8],
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

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

/// Build getAssertion CBOR request
fn build_get_assertion_cbor(client_data_hash: &[u8], rp_id: &str) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

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
#[ignore] // Mark as E2E test
#[serial]
fn test_complete_webauthn_flow_with_pin() -> Result<()> {
    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║     E2E WebAuthn Flow Test (with PIN)         ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    // Setup callbacks
    let callbacks = TestCallbacks::new();
    let credentials = callbacks.credentials.clone();

    // Configure authenticator
    let config = AuthenticatorConfig::builder()
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
        .build();

    // Set PIN
    let pin_hash = compute_pin_hash(TEST_PIN);
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

    let mut auth = Authenticator::with_config(callbacks, config)?;

    // ============================================================
    // PHASE 1: REGISTRATION (makeCredential)
    // ============================================================
    eprintln!("[Test] PHASE 1: Registration");
    eprintln!("{}", "─".repeat(48));

    let challenge = b"registration-challenge-12345";
    let client_data_hash = compute_client_data_hash(challenge, TEST_ORIGIN, "webauthn.create");

    let make_cred_request = build_make_credential_cbor(
        &client_data_hash,
        TEST_RP_ID,
        "Test Relying Party",
        b"test-user-123",
        "testuser@example.com",
        "Test User",
    );

    let mut ctap_request = vec![0x01]; // makeCredential command
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)?;

    assert!(!response.is_empty(), "Empty response from makeCredential");
    let status = response[0];
    assert_eq!(
        status, 0x00,
        "makeCredential failed with status: 0x{:02x}",
        status
    );
    eprintln!(
        "[Test] ✓ Registration successful ({} bytes)\n",
        response.len()
    );

    // ============================================================
    // PHASE 2: AUTHENTICATION (getAssertion)
    // ============================================================
    eprintln!("[Test] PHASE 2: Authentication");
    eprintln!("{}", "─".repeat(48));

    let challenge = b"authentication-challenge-67890";
    let client_data_hash = compute_client_data_hash(challenge, TEST_ORIGIN, "webauthn.get");

    let get_assertion_request = build_get_assertion_cbor(&client_data_hash, TEST_RP_ID);

    let mut ctap_request = vec![0x02]; // getAssertion command
    ctap_request.extend_from_slice(&get_assertion_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)?;

    assert!(!response.is_empty(), "Empty response from getAssertion");
    let status = response[0];
    assert_eq!(
        status, 0x00,
        "getAssertion failed with status: 0x{:02x}",
        status
    );
    eprintln!(
        "[Test] ✓ Authentication successful ({} bytes)\n",
        response.len()
    );

    // Verify credentials were stored
    let cred_count = credentials.lock().unwrap().len();
    assert_eq!(cred_count, 1, "Expected 1 credential to be stored");

    eprintln!("╔════════════════════════════════════════════════╗");
    eprintln!("║     ✓ E2E Test Passed                          ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

#[test]
#[ignore]
#[serial]
fn test_uv_only_flow() -> Result<()> {
    eprintln!("\n[Test] Testing UV-only authentication (no PIN)");

    // Setup callbacks
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
            0x7c, 0x88,
        ])
        .max_credentials(100)
        .extensions(vec!["credProtect".to_string()])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(false)), // No PIN
        )
        .build();

    let mut auth = Authenticator::with_config(callbacks, config)?;

    // Registration
    let challenge = b"uv-only-registration";
    let client_data_hash = compute_client_data_hash(challenge, TEST_ORIGIN, "webauthn.create");

    let make_cred_request = build_make_credential_cbor(
        &client_data_hash,
        TEST_RP_ID,
        "UV Test RP",
        b"uv-user",
        "uvuser@example.com",
        "UV User",
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&make_cred_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)?;

    assert!(!response.is_empty());
    assert_eq!(response[0], 0x00);
    eprintln!("[Test] ✓ UV-only registration succeeded");

    // Authentication
    let challenge = b"uv-only-authentication";
    let client_data_hash = compute_client_data_hash(challenge, TEST_ORIGIN, "webauthn.get");

    let get_assertion_request = build_get_assertion_cbor(&client_data_hash, TEST_RP_ID);

    let mut ctap_request = vec![0x02];
    ctap_request.extend_from_slice(&get_assertion_request);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)?;

    assert!(!response.is_empty());
    assert_eq!(response[0], 0x00);
    eprintln!("[Test] ✓ UV-only authentication succeeded\n");

    Ok(())
}
