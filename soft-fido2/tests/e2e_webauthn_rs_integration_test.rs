//! Full E2E WebAuthn Integration Test with webauthn-rs
//!
//! This test demonstrates integration between soft-fido2 (authenticator) and
//! webauthn-rs (relying party), with manual cryptographic verification.
//!
//! # Architecture
//!
//! - **soft-fido2**: Authenticator (CTAP2 protocol level)
//! - **webauthn-rs**: Relying Party (challenge generation)
//! - **p256 crate**: Signature verification
//!
//! # Why Manual Cryptographic Verification?
//!
//! webauthn-rs's `finish_passkey_registration()` and `finish_passkey_authentication()`
//! methods expect browser-formatted data (RegisterPublicKeyCredential / PublicKeyCredential)
//! which includes Base64URL encoding, JSON serialization, and other browser transformations.
//!
//! The authenticator operates at the CTAP level, producing raw CBOR-encoded data.
//! Converting CTAP→WebAuthn format would require reimplementing browser logic, which is
//! beyond the scope of authenticator testing.
//!
//! **For full webauthn-rs integration testing with actual finish_* method verification,
//! use the manual testing example:**
//!
//! ```bash
//! cargo run --example virtual_authenticator
//! # Then test with https://webauthn.firstyear.id.au/
//! ```
//!
//! This test verifies:
//! 1. webauthn-rs generates valid challenges ✓
//! 2. soft-fido2 creates credentials with valid public keys ✓
//! 3. soft-fido2 generates valid ECDSA signatures ✓
//! 4. Cryptographic verification passes (p256) ✓
//!
//! Run with: cargo test --test e2e_webauthn_rs_integration_test -- --ignored

#![cfg(feature = "std")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::prelude::*;
use serial_test::serial;
use sha2::{Digest, Sha256};

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Credential,
    CredentialRef, Result as SoftFido2Result, UpResult, UvResult,
};

// webauthn-rs imports
use webauthn_rs::prelude::*;

// p256 for signature verification
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

const TEST_RP_ID: &str = "localhost";
const TEST_RP_NAME: &str = "Test Relying Party";
const TEST_ORIGIN: &str = "http://localhost:8080";

/// Test callbacks for E2E authenticator
struct TestCallbacks {
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
}

impl TestCallbacks {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl AuthenticatorCallbacks for TestCallbacks {
    fn request_up(&self, _info: &str, _user: Option<&str>, _rp: &str) -> SoftFido2Result<UpResult> {
        Ok(UpResult::Accepted)
    }

    fn request_uv(&self, _info: &str, _user: Option<&str>, _rp: &str) -> SoftFido2Result<UvResult> {
        Ok(UvResult::Accepted)
    }

    fn write_credential(
        &self,
        cred_id: &[u8],
        _rp_id: &str,
        cred: &CredentialRef,
    ) -> SoftFido2Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.insert(cred_id.to_vec(), cred.to_owned());
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8], _rp_id: &str) -> SoftFido2Result<Option<Credential>> {
        let store = self.credentials.lock().unwrap();
        Ok(store.get(cred_id).cloned())
    }

    fn delete_credential(&self, cred_id: &[u8]) -> SoftFido2Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.remove(cred_id);
        Ok(())
    }

    fn list_credentials(
        &self,
        rp_id: &str,
        _user_id: Option<&[u8]>,
    ) -> SoftFido2Result<Vec<Credential>> {
        let store = self.credentials.lock().unwrap();
        let filtered: Vec<Credential> = store
            .values()
            .filter(|c| c.rp.id == rp_id)
            .cloned()
            .collect();
        Ok(filtered)
    }
}

/// Helper to create test authenticator
fn create_authenticator(
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
) -> SoftFido2Result<Authenticator<TestCallbacks>> {
    let callbacks = TestCallbacks { credentials };

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
                .with_client_pin(Some(false)),
        )
        .build();

    Authenticator::with_config(callbacks, config)
}

/// Convert webauthn-rs challenge to clientDataHash
fn compute_client_data_hash(challenge_bytes: &[u8], ceremony_type: &str) -> Vec<u8> {
    let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(challenge_bytes);
    let client_data_json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
        ceremony_type, challenge_b64, TEST_ORIGIN
    );
    Sha256::digest(client_data_json.as_bytes()).to_vec()
}

/// Build CTAP makeCredential request
fn build_make_credential_request(
    client_data_hash: &[u8],
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

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

/// Build CTAP getAssertion request
fn build_get_assertion_request(client_data_hash: &[u8]) -> Vec<u8> {
    use soft_fido2_ctap::cbor::Value;

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
        (Value::Integer(0x05.into()), Value::Map(options_map)),
    ];

    let mut buffer = Vec::new();
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request_map), &mut buffer)
        .expect("CBOR encoding");
    buffer
}

/// Parse public key from COSE format to p256 VerifyingKey
fn parse_cose_public_key(cose_key_cbor: &[u8]) -> Option<VerifyingKey> {
    let cose_key: soft_fido2_ctap::cbor::Value =
        soft_fido2_ctap::cbor::decode(cose_key_cbor).ok()?;

    let map = match cose_key {
        soft_fido2_ctap::cbor::Value::Map(m) => m,
        _ => return None,
    };

    // Extract x and y coordinates (COSE keys -2 and -3)
    let x = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &(-2).into()))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Bytes(b) => Some(b),
            _ => None,
        })?;

    let y = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &(-3).into()))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Bytes(b) => Some(b),
            _ => None,
        })?;

    // Convert to uncompressed SEC1 format (0x04 || x || y)
    let mut public_key_bytes = vec![0x04];
    public_key_bytes.extend_from_slice(x);
    public_key_bytes.extend_from_slice(y);

    VerifyingKey::from_sec1_bytes(&public_key_bytes).ok()
}

#[test]
#[ignore] // E2E test
#[serial]
fn test_webauthn_rs_integration_with_crypto_verification() {
    eprintln!("\n╔═══════════════════════════════════════════════════╗");
    eprintln!("║  E2E: soft-fido2 + webauthn-rs + Crypto Verify   ║");
    eprintln!("╚═══════════════════════════════════════════════════╝\n");

    // ============================================================
    // Setup Relying Party (webauthn-rs)
    // ============================================================
    let rp_origin = Url::parse(TEST_ORIGIN).expect("Invalid URL");
    let builder = WebauthnBuilder::new(TEST_RP_ID, &rp_origin).expect("Invalid config");
    let webauthn = builder.build().expect("Failed to build webauthn");

    eprintln!("[RP] Relying Party initialized (using webauthn-rs)");
    eprintln!("[RP] RP ID: {}", TEST_RP_ID);
    eprintln!("[RP] Origin: {}\n", TEST_ORIGIN);

    // ============================================================
    // Setup Authenticator (soft-fido2)
    // ============================================================
    let credentials = Arc::new(Mutex::new(HashMap::new()));
    let mut authenticator =
        create_authenticator(credentials.clone()).expect("Failed to create authenticator");

    eprintln!("[Authenticator] Virtual authenticator created\n");

    // ============================================================
    // PHASE 1: REGISTRATION
    // ============================================================
    eprintln!("[RP] PHASE 1: Registration");
    eprintln!("{}", "─".repeat(51));

    let user_unique_id = Uuid::new_v4();
    let user_name = "testuser";
    let user_display_name = "Test User";

    // Use webauthn-rs to generate registration challenge
    let (ccr, _reg_state) = webauthn
        .start_passkey_registration(user_unique_id, user_name, user_display_name, None)
        .expect("Failed to start registration");

    eprintln!("[RP] ✓ Registration challenge generated (webauthn-rs)");
    eprintln!("[RP]   Challenge: {} bytes", ccr.public_key.challenge.len());

    // Simulate browser: convert challenge to clientDataHash
    let client_data_hash =
        compute_client_data_hash(ccr.public_key.challenge.as_ref(), "webauthn.create");

    // Create CTAP makeCredential request
    let make_cred_cbor = build_make_credential_request(
        &client_data_hash,
        user_unique_id.as_bytes(),
        user_name,
        user_display_name,
    );

    let mut ctap_request = vec![0x01]; // makeCredential
    ctap_request.extend_from_slice(&make_cred_cbor);

    // Authenticator processes request
    let mut ctap_response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut ctap_response)
        .expect("makeCredential failed");

    eprintln!("[Authenticator] ✓ Credential created");

    // Parse CTAP response to extract public key
    assert_eq!(ctap_response[0], 0x00, "CTAP error");
    let response: soft_fido2_ctap::cbor::Value =
        soft_fido2_ctap::cbor::decode(&ctap_response[1..]).expect("Invalid CBOR");

    let map = match response {
        soft_fido2_ctap::cbor::Value::Map(m) => m,
        _ => panic!("Expected CBOR map"),
    };

    let auth_data = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &2.into()))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Bytes(b) => Some(b),
            _ => None,
        })
        .expect("Missing authData");

    // Extract public key from authData
    let cred_id_len_offset = 32 + 1 + 4 + 16;
    let cred_id_len = u16::from_be_bytes([
        auth_data[cred_id_len_offset],
        auth_data[cred_id_len_offset + 1],
    ]) as usize;
    let public_key_offset = cred_id_len_offset + 2 + cred_id_len;
    let public_key_cose = &auth_data[public_key_offset..];

    // Parse COSE public key to p256 VerifyingKey
    let verifying_key = parse_cose_public_key(public_key_cose).expect("Failed to parse public key");

    eprintln!("[Browser] ✓ Parsed public key from attestation");
    eprintln!("[Test] ✓ Public key successfully converted to p256 format\n");

    // ============================================================
    // PHASE 2: AUTHENTICATION
    // ============================================================
    eprintln!("[RP] PHASE 2: Authentication");
    eprintln!("{}", "─".repeat(51));

    // Generate authentication challenge using webauthn-rs
    // Note: webauthn-rs expects Passkey objects for authentication,
    // so we'll generate a raw challenge instead
    use rand::RngCore;
    let mut challenge_bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);

    eprintln!("[RP] ✓ Authentication challenge generated (32 bytes)");

    // Simulate browser: convert to clientDataHash
    let client_data_hash = compute_client_data_hash(&challenge_bytes, "webauthn.get");

    // Create CTAP getAssertion request
    let get_assertion_cbor = build_get_assertion_request(&client_data_hash);

    let mut ctap_request = vec![0x02]; // getAssertion
    ctap_request.extend_from_slice(&get_assertion_cbor);

    // Authenticator processes request
    let mut ctap_response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut ctap_response)
        .expect("getAssertion failed");

    eprintln!("[Authenticator] ✓ Assertion generated");

    // Parse assertion response
    assert_eq!(ctap_response[0], 0x00, "CTAP error");
    let response: soft_fido2_ctap::cbor::Value =
        soft_fido2_ctap::cbor::decode(&ctap_response[1..]).expect("Invalid CBOR");

    let map = match response {
        soft_fido2_ctap::cbor::Value::Map(m) => m,
        _ => panic!("Expected CBOR map"),
    };

    let auth_data = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &2.into()))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Bytes(b) => Some(b),
            _ => None,
        })
        .expect("Missing authData");

    let signature_der = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &3.into()))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Bytes(b) => Some(b),
            _ => None,
        })
        .expect("Missing signature");

    eprintln!("[Browser] ✓ Parsed assertion response");
    eprintln!("[Browser]   authData: {} bytes", auth_data.len());
    eprintln!("[Browser]   signature: {} bytes", signature_der.len());

    // ============================================================
    // CRYPTOGRAPHIC VERIFICATION
    // ============================================================
    eprintln!("\n[Verify] Performing cryptographic signature verification...");

    // Construct signed data: authData || clientDataHash
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(auth_data);
    signed_data.extend_from_slice(&client_data_hash);

    eprintln!("[Verify] Signed data: {} bytes", signed_data.len());

    // Parse DER signature
    let signature = Signature::from_der(signature_der).expect("Invalid DER signature");

    // Verify signature using p256
    match verifying_key.verify(&signed_data, &signature) {
        Ok(()) => {
            eprintln!("[Verify] ✓ Signature VALID!");
            eprintln!("[Verify] ✓ Cryptographic verification passed (p256/ECDSA)");
        }
        Err(e) => {
            panic!("Signature verification failed: {:?}", e);
        }
    }

    eprintln!("\n╔═══════════════════════════════════════════════════╗");
    eprintln!("║  ✓ Full E2E Integration Test PASSED              ║");
    eprintln!("╚═══════════════════════════════════════════════════╝\n");

    eprintln!("Summary:");
    eprintln!("  ✓ webauthn-rs generated registration challenge");
    eprintln!("  ✓ soft-fido2 created credential with valid public key");
    eprintln!("  ✓ soft-fido2 generated authentication assertion");
    eprintln!("  ✓ p256 ECDSA signature verification PASSED");
    eprintln!("  ✓ Cryptographic correctness confirmed");
}
