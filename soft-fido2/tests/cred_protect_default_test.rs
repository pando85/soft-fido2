//! Integration tests for the default credProtect level.
//!
//! When the client sends no `credProtect` extension, the authenticator picks
//! the level: level 2 when UV was performed (so allowList signing with `up`
//! only, e.g. OpenSSH `ed25519-sk`, keeps working) and level 1 otherwise.

mod common;

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, CredProtect,
};
use soft_fido2_ctap::cbor::Value;

use common::TestCallbacks;

const RP_ID: &str = "cred-protect.test";
const NO_CREDENTIALS: u8 = 0x2E;

type TestAuthenticator = Authenticator<TestCallbacks>;

/// Authenticator with built-in UV: makeCredential always performs UV.
fn uv_authenticator(callbacks: &TestCallbacks) -> TestAuthenticator {
    let config = AuthenticatorConfig::builder()
        .extensions(vec!["credProtect".to_string()])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(false)),
        )
        .build();
    Authenticator::with_config(callbacks.clone(), config).expect("authenticator")
}

/// Authenticator without any UV method: makeCredential never performs UV.
fn no_uv_authenticator(callbacks: &TestCallbacks) -> TestAuthenticator {
    let config = AuthenticatorConfig::builder()
        .extensions(vec!["credProtect".to_string()])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(false))
                .with_client_pin(Some(false)),
        )
        .build();
    Authenticator::with_config(callbacks.clone(), config).expect("authenticator")
}

fn make_credential(auth: &mut TestAuthenticator, cred_protect: Option<u8>) {
    let rp = vec![(
        Value::Text("id".to_string()),
        Value::Text(RP_ID.to_string()),
    )];
    let user = vec![
        (
            Value::Text("id".to_string()),
            Value::Bytes(vec![1, 2, 3, 4]),
        ),
        (
            Value::Text("name".to_string()),
            Value::Text("user".to_string()),
        ),
    ];
    let params = vec![Value::Map(vec![
        (
            Value::Text("type".to_string()),
            Value::Text("public-key".to_string()),
        ),
        (Value::Text("alg".to_string()), Value::Integer((-7).into())),
    ])];
    let options = vec![(Value::Text("rk".to_string()), Value::Bool(true))];

    let mut request = vec![
        (Value::Integer(0x01.into()), Value::Bytes(vec![0x11; 32])),
        (Value::Integer(0x02.into()), Value::Map(rp)),
        (Value::Integer(0x03.into()), Value::Map(user)),
        (Value::Integer(0x04.into()), Value::Array(params)),
    ];
    if let Some(level) = cred_protect {
        let extensions = vec![(
            Value::Text("credProtect".to_string()),
            Value::Integer(level.into()),
        )];
        request.push((Value::Integer(0x06.into()), Value::Map(extensions)));
    }
    request.push((Value::Integer(0x07.into()), Value::Map(options)));

    let response = send(auth, 0x01, request);
    assert_eq!(
        response[0], 0x00,
        "makeCredential failed: {:02x}",
        response[0]
    );
}

/// getAssertion with `up` only (no `uv`), optionally with an allowList.
fn get_assertion(auth: &mut TestAuthenticator, allow: Option<&[u8]>) -> Vec<u8> {
    let mut request = vec![
        (Value::Integer(0x01.into()), Value::Text(RP_ID.to_string())),
        (Value::Integer(0x02.into()), Value::Bytes(vec![0x22; 32])),
    ];
    if let Some(id) = allow {
        let descriptor = Value::Map(vec![
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
            (Value::Text("id".to_string()), Value::Bytes(id.to_vec())),
        ]);
        request.push((Value::Integer(0x03.into()), Value::Array(vec![descriptor])));
    }
    let options = vec![(Value::Text("up".to_string()), Value::Bool(true))];
    request.push((Value::Integer(0x05.into()), Value::Map(options)));

    send(auth, 0x02, request)
}

fn send(auth: &mut TestAuthenticator, command: u8, request: Vec<(Value, Value)>) -> Vec<u8> {
    let mut payload = vec![command];
    soft_fido2_ctap::cbor::into_writer(&Value::Map(request), &mut payload).expect("CBOR encoding");

    let mut response = Vec::new();
    auth.handle(&payload, &mut response).expect("handle");
    response
}

/// Return the single stored credential's `(id, credProtect)`.
fn stored(callbacks: &TestCallbacks) -> (Vec<u8>, Option<u8>) {
    let mut creds = callbacks.list_credentials(RP_ID, None).expect("list");
    assert_eq!(creds.len(), 1, "expected exactly one stored credential");
    let cred = creds.remove(0);
    (cred.id, cred.extensions.cred_protect)
}

#[test]
fn uv_without_extension_stores_level_2() {
    let callbacks = TestCallbacks::new();
    let mut auth = uv_authenticator(&callbacks);

    make_credential(&mut auth, None);

    let (_, level) = stored(&callbacks);
    assert_eq!(
        level,
        Some(CredProtect::UserVerificationOptionalWithCredentialIdList as u8)
    );
}

#[test]
fn no_uv_without_extension_stores_level_1() {
    let callbacks = TestCallbacks::new();
    let mut auth = no_uv_authenticator(&callbacks);

    make_credential(&mut auth, None);

    let (_, level) = stored(&callbacks);
    assert_eq!(level, Some(CredProtect::UserVerificationOptional as u8));
}

#[test]
fn explicit_level_3_is_honoured_with_uv() {
    let callbacks = TestCallbacks::new();
    let mut auth = uv_authenticator(&callbacks);

    make_credential(&mut auth, Some(3));

    let (_, level) = stored(&callbacks);
    assert_eq!(level, Some(CredProtect::UserVerificationRequired as u8));
}

#[test]
fn explicit_level_1_is_honoured_with_uv() {
    let callbacks = TestCallbacks::new();
    let mut auth = uv_authenticator(&callbacks);

    make_credential(&mut auth, Some(1));

    let (_, level) = stored(&callbacks);
    assert_eq!(level, Some(CredProtect::UserVerificationOptional as u8));
}

#[test]
fn configured_default_with_uv_is_used() {
    let callbacks = TestCallbacks::new();
    let config = AuthenticatorConfig::builder()
        .default_cred_protect_with_uv(CredProtect::UserVerificationRequired)
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(false)),
        )
        .build();
    let mut auth = Authenticator::with_config(callbacks.clone(), config).expect("authenticator");

    make_credential(&mut auth, None);

    let (_, level) = stored(&callbacks);
    assert_eq!(level, Some(CredProtect::UserVerificationRequired as u8));
}

#[test]
fn level_2_credential_is_found_with_allow_list_and_up_only() {
    let callbacks = TestCallbacks::new();
    let mut auth = uv_authenticator(&callbacks);
    make_credential(&mut auth, None);
    let (id, _) = stored(&callbacks);

    // OpenSSH `*-sk` style signing: allowList, `up` only, no UV.
    let response = get_assertion(&mut auth, Some(&id));

    assert_eq!(response[0], 0x00, "getAssertion status {:02x}", response[0]);
}

#[test]
fn level_2_credential_is_hidden_without_allow_list_and_uv() {
    let callbacks = TestCallbacks::new();
    let mut auth = uv_authenticator(&callbacks);
    make_credential(&mut auth, None);

    // Discovery without allowList and without UV must not reveal it.
    let response = get_assertion(&mut auth, None);

    assert_eq!(response[0], NO_CREDENTIALS);
}

#[test]
fn level_3_credential_is_not_found_with_allow_list_and_up_only() {
    let callbacks = TestCallbacks::new();
    let mut auth = uv_authenticator(&callbacks);
    make_credential(&mut auth, Some(3));
    let (id, _) = stored(&callbacks);

    let response = get_assertion(&mut auth, Some(&id));

    assert_eq!(response[0], NO_CREDENTIALS);
}
