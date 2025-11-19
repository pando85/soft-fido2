//! WebAuthn Compliance Integration Tests
//!
//! This test suite validates that soft-fido2 produces valid WebAuthn-compliant
//! responses that match the spec requirements.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Credential,
    CredentialRef, Result, UpResult, UvResult,
};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";
const USER_ID: &[u8] = b"user-123";
const USER_NAME: &str = "alice@example.com";
const USER_DISPLAY_NAME: &str = "Alice";

/// Test callbacks for compliance tests
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

/// Helper to create authenticator
fn create_test_authenticator(
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
) -> Authenticator<TestCallbacks> {
    let callbacks = TestCallbacks { credentials };

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
                .with_user_verification(Some(true)),
        )
        .build();

    Authenticator::with_config(callbacks, config).expect("Failed to create authenticator")
}

#[test]
fn test_authenticator_get_info_compliance() {
    let credentials = Arc::new(Mutex::new(HashMap::new()));
    let mut authenticator = create_test_authenticator(credentials);

    // Send authenticatorGetInfo command (0x04)
    let ctap_request = vec![0x04];
    let mut response = Vec::new();

    authenticator
        .handle(&ctap_request, &mut response)
        .expect("getInfo failed");

    // Validate response structure
    assert!(!response.is_empty(), "Empty response from getInfo");
    assert_eq!(response[0], 0x00, "getInfo failed with non-zero status");

    // Parse CBOR response
    let info: soft_fido2_ctap::cbor::Value =
        soft_fido2_ctap::cbor::decode(&response[1..]).expect("Failed to parse getInfo response");

    let map = match info {
        soft_fido2_ctap::cbor::Value::Map(m) => m,
        _ => panic!("getInfo response is not a CBOR map"),
    };

    // Verify required fields per CTAP spec
    // Field 0x01: versions (required)
    let versions = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &1.into()))
        .map(|(_, v)| v);
    assert!(versions.is_some(), "Missing required 'versions' field");

    if let Some(soft_fido2_ctap::cbor::Value::Array(vers)) = versions {
        assert!(!vers.is_empty(), "versions array is empty");
        // Should contain at least "FIDO_2_0" or "FIDO_2_1"
        let has_fido2 = vers.iter().any(
            |v| matches!(v, soft_fido2_ctap::cbor::Value::Text(s) if s.starts_with("FIDO_2_")),
        );
        assert!(has_fido2, "versions must include FIDO2 version");
    }

    // Field 0x03: aaguid (required)
    let aaguid = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &3.into()))
        .map(|(_, v)| v);
    assert!(aaguid.is_some(), "Missing required 'aaguid' field");

    if let Some(soft_fido2_ctap::cbor::Value::Bytes(guid)) = aaguid {
        assert_eq!(guid.len(), 16, "AAGUID must be 16 bytes");
    }

    // Field 0x04: options (optional but should be present)
    let options = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &4.into()))
        .map(|(_, v)| v);
    assert!(options.is_some(), "Missing 'options' field");
}

#[test]
fn test_make_credential_compliance() {
    let credentials = Arc::new(Mutex::new(HashMap::new()));
    let mut authenticator = create_test_authenticator(credentials.clone());

    // Create client data hash
    let challenge = b"registration-challenge-12345678";
    let client_data_json = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(challenge),
        ORIGIN
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes()).to_vec();

    // Build makeCredential CBOR request
    let request_cbor = build_make_credential_cbor(
        &client_data_hash,
        RP_ID,
        "Example Corp",
        USER_ID,
        USER_NAME,
        USER_DISPLAY_NAME,
    );

    // Send makeCredential command (0x01)
    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&request_cbor);

    let mut response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut response)
        .expect("makeCredential failed");

    // Validate response
    assert!(!response.is_empty(), "Empty response from makeCredential");
    assert_eq!(
        response[0], 0x00,
        "makeCredential failed with non-zero status"
    );

    // Parse CBOR response
    let resp: soft_fido2_ctap::cbor::Value = soft_fido2_ctap::cbor::decode(&response[1..])
        .expect("Failed to parse makeCredential response");

    let map = match resp {
        soft_fido2_ctap::cbor::Value::Map(m) => m,
        _ => panic!("makeCredential response is not a CBOR map"),
    };

    // Verify required fields per CTAP spec
    // Field 0x01: fmt (attestation format)
    let fmt = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &1.into()))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Text(s) => Some(s.as_str()),
            _ => None,
        });
    assert!(fmt.is_some(), "Missing required 'fmt' field");
    // Accept valid attestation formats: "none", "packed", "fido-u2f", etc.
    let valid_formats = [
        "none",
        "packed",
        "fido-u2f",
        "android-key",
        "android-safetynet",
        "tpm",
        "apple",
    ];
    assert!(
        valid_formats.contains(&fmt.unwrap()),
        "Invalid attestation format: {}",
        fmt.unwrap()
    );

    // Field 0x02: authData (required)
    let auth_data = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &2.into()))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Bytes(b) => Some(b),
            _ => None,
        });
    assert!(auth_data.is_some(), "Missing required 'authData' field");

    // Validate authData structure
    let auth_data = auth_data.unwrap();
    assert!(auth_data.len() >= 37, "authData too short (min 37 bytes)");

    // rpIdHash (32 bytes)
    let rp_id_hash = Sha256::digest(RP_ID.as_bytes());
    assert_eq!(
        &auth_data[0..32],
        rp_id_hash.as_slice(),
        "rpIdHash mismatch"
    );

    // flags (1 byte) - should have UP and AT flags set
    let flags = auth_data[32];
    assert_ne!(flags & 0x01, 0, "UP flag not set");
    assert_ne!(
        flags & 0x40,
        0,
        "AT flag not set (attested credential data)"
    );

    // signCount (4 bytes)
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    assert_eq!(sign_count, 0, "Initial sign count should be 0");

    // Verify credential was stored
    assert_eq!(
        credentials.lock().unwrap().len(),
        1,
        "Expected 1 credential to be stored"
    );
}

#[test]
fn test_get_assertion_compliance() {
    let credentials = Arc::new(Mutex::new(HashMap::new()));
    let mut authenticator = create_test_authenticator(credentials.clone());

    // First, create a credential
    let challenge = b"registration-challenge";
    let client_data_json = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(challenge),
        ORIGIN
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes()).to_vec();

    let request_cbor = build_make_credential_cbor(
        &client_data_hash,
        RP_ID,
        "Example Corp",
        USER_ID,
        USER_NAME,
        USER_DISPLAY_NAME,
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&request_cbor);

    let mut response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut response)
        .expect("makeCredential failed");

    assert_eq!(response[0], 0x00, "makeCredential failed");

    // Now test getAssertion
    let auth_challenge = b"authentication-challenge";
    let auth_client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(auth_challenge),
        ORIGIN
    );
    let auth_client_data_hash = Sha256::digest(auth_client_data_json.as_bytes()).to_vec();

    let assertion_cbor = build_get_assertion_cbor(&auth_client_data_hash, RP_ID);

    let mut ctap_request = vec![0x02]; // getAssertion command
    ctap_request.extend_from_slice(&assertion_cbor);

    let mut response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut response)
        .expect("getAssertion failed");

    // Validate response
    assert!(!response.is_empty(), "Empty response from getAssertion");
    assert_eq!(
        response[0], 0x00,
        "getAssertion failed with non-zero status"
    );

    // Parse CBOR response
    let resp: soft_fido2_ctap::cbor::Value = soft_fido2_ctap::cbor::decode(&response[1..])
        .expect("Failed to parse getAssertion response");

    let map = match resp {
        soft_fido2_ctap::cbor::Value::Map(m) => m,
        _ => panic!("getAssertion response is not a CBOR map"),
    };

    // Verify required fields per CTAP spec
    // Field 0x01: credential (optional in some cases, but should be present for resident keys)
    let credential = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &1.into()))
        .map(|(_, v)| v);
    assert!(credential.is_some(), "Missing 'credential' field");

    // Field 0x02: authData (required)
    let auth_data = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &2.into()))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Bytes(b) => Some(b),
            _ => None,
        });
    assert!(auth_data.is_some(), "Missing required 'authData' field");

    // Validate authData structure (minimum 37 bytes for getAssertion)
    let auth_data = auth_data.unwrap();
    assert!(auth_data.len() >= 37, "authData too short");

    // rpIdHash validation
    let rp_id_hash = Sha256::digest(RP_ID.as_bytes());
    assert_eq!(
        &auth_data[0..32],
        rp_id_hash.as_slice(),
        "rpIdHash mismatch"
    );

    // flags - should have UP flag set
    let flags = auth_data[32];
    assert_ne!(flags & 0x01, 0, "UP flag not set");

    // Field 0x03: signature (required)
    let signature = map
        .iter()
        .find(|(k, _)| matches!(k, soft_fido2_ctap::cbor::Value::Integer(i) if i == &3.into()))
        .and_then(|(_, v)| match v {
            soft_fido2_ctap::cbor::Value::Bytes(b) => Some(b),
            _ => None,
        });
    assert!(signature.is_some(), "Missing required 'signature' field");
    assert!(!signature.unwrap().is_empty(), "Signature is empty");
}

#[test]
fn test_multiple_credentials_same_rp() {
    let credentials = Arc::new(Mutex::new(HashMap::new()));
    let mut authenticator = create_test_authenticator(credentials.clone());

    // Create first credential
    for i in 1..=3 {
        let user_id = format!("user-{}", i);
        let challenge = format!("challenge-{}", i);
        let client_data_json = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(challenge.as_bytes()),
            ORIGIN
        );
        let client_data_hash = Sha256::digest(client_data_json.as_bytes()).to_vec();

        let request_cbor = build_make_credential_cbor(
            &client_data_hash,
            RP_ID,
            "Example Corp",
            user_id.as_bytes(),
            &format!("user{}@example.com", i),
            &format!("User {}", i),
        );

        let mut ctap_request = vec![0x01];
        ctap_request.extend_from_slice(&request_cbor);

        let mut response = Vec::new();
        authenticator
            .handle(&ctap_request, &mut response)
            .expect("makeCredential failed");

        assert_eq!(response[0], 0x00, "makeCredential failed for user {}", i);
    }

    // Verify all credentials were stored
    assert_eq!(
        credentials.lock().unwrap().len(),
        3,
        "Expected 3 credentials to be stored"
    );

    // Test getAssertion returns appropriate credential
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(b"auth-challenge"),
        ORIGIN
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes()).to_vec();

    let assertion_cbor = build_get_assertion_cbor(&client_data_hash, RP_ID);

    let mut ctap_request = vec![0x02];
    ctap_request.extend_from_slice(&assertion_cbor);

    let mut response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut response)
        .expect("getAssertion failed");

    assert_eq!(response[0], 0x00, "getAssertion failed");
}

// ============================================================================
// Helper functions
// ============================================================================

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
