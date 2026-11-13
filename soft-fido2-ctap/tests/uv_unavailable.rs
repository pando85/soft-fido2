//! `UvResult::Unavailable` fails a request like `Denied` does, but nobody failed a
//! verification attempt, so it must not consume a UV retry and must keep answering
//! `CTAP2_ERR_PUAT_REQUIRED` while a PIN is set (the platform's cue to fall back to the PIN).

use soft_fido2_crypto::ecdh::KeyPair;
use soft_fido2_ctap::{
    Authenticator, AuthenticatorConfig, CommandDispatcher, Credential, CredentialStorageCallbacks,
    StatusCode, UpResult, UserInteractionCallbacks, UvResult,
    callbacks::PlatformCallbacks,
    cbor::{MapBuilder, Value, into_writer},
};

use std::sync::{Arc, Mutex};

const CLIENT_DATA_HASH: [u8; 32] = [0x5a; 32];
const MAX_RETRIES: u8 = 3;

/// Answers every built-in UV request with the scripted result.
#[derive(Clone)]
struct ScriptedUv {
    answer: Arc<Mutex<UvResult>>,
    asked: Arc<Mutex<usize>>,
}

impl ScriptedUv {
    fn new(answer: UvResult) -> Self {
        Self {
            answer: Arc::new(Mutex::new(answer)),
            asked: Arc::new(Mutex::new(0)),
        }
    }

    fn set(&self, answer: UvResult) {
        *self.answer.lock().unwrap() = answer;
    }

    fn asked(&self) -> usize {
        *self.asked.lock().unwrap()
    }
}

impl PlatformCallbacks for ScriptedUv {
    fn get_timestamp_ms(&self) -> u64 {
        1_000
    }
}

impl UserInteractionCallbacks for ScriptedUv {
    fn request_up(&self, _: &str, _: Option<&str>, _: &str) -> Result<UpResult, StatusCode> {
        Ok(UpResult::Accepted)
    }

    fn request_uv(&self, _: &str, _: Option<&str>, _: &str) -> Result<UvResult, StatusCode> {
        *self.asked.lock().unwrap() += 1;
        Ok(*self.answer.lock().unwrap())
    }

    fn select_credential(&self, _: &str, _: &[String]) -> Result<usize, StatusCode> {
        Ok(0)
    }
}

impl CredentialStorageCallbacks for ScriptedUv {
    fn write_credential(&self, _: &Credential) -> Result<(), StatusCode> {
        Ok(())
    }

    fn delete_credential(&self, _: &[u8]) -> Result<(), StatusCode> {
        Ok(())
    }

    fn read_credentials(&self, _: &str, _: Option<&[u8]>) -> Result<Vec<Credential>, StatusCode> {
        Ok(Vec::new())
    }

    fn credential_exists(&self, _: &[u8]) -> Result<bool, StatusCode> {
        Ok(false)
    }

    fn get_credential(&self, _: &[u8]) -> Result<Credential, StatusCode> {
        Err(StatusCode::NoCredentials)
    }

    fn update_credential(&self, _: &Credential) -> Result<(), StatusCode> {
        Ok(())
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>, StatusCode> {
        Ok(Vec::new())
    }

    fn credential_count(&self) -> Result<usize, StatusCode> {
        Ok(0)
    }
}

/// An authenticator with built-in UV configured and `with_pin` optionally set.
fn authenticator(
    callbacks: ScriptedUv,
    with_pin: bool,
) -> CommandDispatcher<ScriptedUv, soft_fido2_ctap::SoftwareCredentialKeyProvider> {
    let mut options = soft_fido2_ctap::authenticator::AuthenticatorOptions::new();
    options.pin_uv_auth_token = true;
    let config = AuthenticatorConfig::new()
        .with_options(options)
        .with_max_pin_retries(MAX_RETRIES);
    let mut auth = Authenticator::new(config, callbacks);
    if with_pin {
        auth.set_pin("1234").expect("set PIN");
    }
    CommandDispatcher::new(auth)
}

type Dispatcher = CommandDispatcher<ScriptedUv, soft_fido2_ctap::SoftwareCredentialKeyProvider>;

fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

fn request(code: u8, params: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = vec![code];
    into_writer(&Value::Map(params), &mut out).expect("encode request");
    out
}

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

/// MakeCredential asking for built-in UV (`"uv": true`) without a pinUvAuthParam.
fn make_credential_with_uv() -> Vec<u8> {
    request(
        0x01,
        vec![
            (int(1), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
            (int(2), Value::Map(vec![(text("id"), text("example.com"))])),
            (
                int(3),
                Value::Map(vec![
                    (text("id"), Value::Bytes(vec![1; 16])),
                    (text("name"), text("user")),
                ]),
            ),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ])]),
            ),
            (int(7), Value::Map(vec![(text("uv"), Value::Bool(true))])),
        ],
    )
}

/// GetAssertion asking for built-in UV (`"uv": true`) without a pinUvAuthParam.
fn get_assertion_with_uv() -> Vec<u8> {
    request(
        0x02,
        vec![
            (int(1), text("example.com")),
            (int(2), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
            (int(5), Value::Map(vec![(text("uv"), Value::Bool(true))])),
        ],
    )
}

/// getPinUvAuthTokenUsingUvWithPermissions (0x06): getKeyAgreement first, then the token request.
fn token_using_uv(dispatcher: &mut Dispatcher) -> Result<Vec<u8>, StatusCode> {
    let key_agreement = MapBuilder::new()
        .insert(1, 2u8)
        .and_then(|b| b.insert(2, 2u8))
        .and_then(|b| b.build())
        .expect("getKeyAgreement");
    let mut command = vec![0x06];
    command.extend(key_agreement);
    dispatcher.dispatch(&command).expect("getKeyAgreement");

    let platform = KeyPair::generate().expect("platform key pair");
    let (x, y) = platform.public_key_cose();
    let platform_cose = Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(-25)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(x.to_vec())),
        (int(-3), Value::Bytes(y.to_vec())),
    ]);
    let params = MapBuilder::new()
        .insert(1, 2u8)
        .and_then(|b| b.insert(2, 0x06u8))
        .and_then(|b| b.insert(3, &platform_cose))
        .and_then(|b| b.insert(9, 0x01u8))
        .and_then(|b| b.insert(10, "example.com"))
        .and_then(|b| b.build())
        .expect("token request");
    let mut command = vec![0x06];
    command.extend(params);
    dispatcher.dispatch(&command)
}

fn retries(dispatcher: &mut Dispatcher) -> u8 {
    dispatcher.authenticator_mut().uv_retries()
}

#[test]
fn unavailable_with_a_pin_answers_puat_required_and_consumes_no_retry() {
    for (name, command) in [
        ("makeCredential", make_credential_with_uv()),
        ("getAssertion", get_assertion_with_uv()),
    ] {
        let callbacks = ScriptedUv::new(UvResult::Unavailable);
        let mut dispatcher = authenticator(callbacks.clone(), true);
        assert_eq!(retries(&mut dispatcher), MAX_RETRIES);

        for attempt in 0..u32::from(MAX_RETRIES) * 3 {
            assert_eq!(
                dispatcher.dispatch(&command),
                Err(StatusCode::PuatRequired),
                "{name}, attempt {attempt}: the PIN fallback status never changes"
            );
        }
        assert_eq!(callbacks.asked(), usize::from(MAX_RETRIES) * 3, "{name}");
        assert_eq!(retries(&mut dispatcher), MAX_RETRIES, "{name}");
    }
}

#[test]
fn denied_with_a_pin_still_consumes_retries_and_ends_in_uv_blocked() {
    // The behaviour `Unavailable` exists to avoid for policy denials.
    for (name, command) in [
        ("makeCredential", make_credential_with_uv()),
        ("getAssertion", get_assertion_with_uv()),
    ] {
        let mut dispatcher = authenticator(ScriptedUv::new(UvResult::Denied), true);
        for expected in (0..MAX_RETRIES).rev() {
            let answer = dispatcher.dispatch(&command);
            assert_eq!(retries(&mut dispatcher), expected, "{name}");
            let status = if expected == 0 {
                StatusCode::UvBlocked
            } else {
                StatusCode::PuatRequired
            };
            assert_eq!(answer, Err(status), "{name}");
        }
    }
}

#[test]
fn unavailable_still_asks_for_the_pin_after_the_retries_are_exhausted() {
    for (name, command) in [
        ("makeCredential", make_credential_with_uv()),
        ("getAssertion", get_assertion_with_uv()),
    ] {
        let callbacks = ScriptedUv::new(UvResult::Denied);
        let mut dispatcher = authenticator(callbacks.clone(), true);
        for _ in 0..MAX_RETRIES {
            let _ = dispatcher.dispatch(&command);
        }
        assert_eq!(retries(&mut dispatcher), 0, "{name}");
        assert_eq!(dispatcher.dispatch(&command), Err(StatusCode::UvBlocked));

        // The browser's PIN fallback needs 0x36, not 0x3c, from here on.
        callbacks.set(UvResult::Unavailable);
        assert_eq!(
            dispatcher.dispatch(&command),
            Err(StatusCode::PuatRequired),
            "{name}"
        );
        assert_eq!(retries(&mut dispatcher), 0, "{name}");
    }
}

#[test]
fn unavailable_without_a_pin_fails_like_denied_without_consuming_a_retry() {
    let callbacks = ScriptedUv::new(UvResult::Unavailable);
    let mut dispatcher = authenticator(callbacks, false);
    for command in [make_credential_with_uv(), get_assertion_with_uv()] {
        assert_eq!(
            dispatcher.dispatch(&command),
            Err(StatusCode::OperationDenied)
        );
        assert_eq!(retries(&mut dispatcher), MAX_RETRIES);
    }

    // `Denied` answers the same status, but spends a retry.
    let mut denied = authenticator(ScriptedUv::new(UvResult::Denied), false);
    assert_eq!(
        denied.dispatch(&make_credential_with_uv()),
        Err(StatusCode::OperationDenied)
    );
    assert_eq!(retries(&mut denied), MAX_RETRIES - 1);
}

#[test]
fn unavailable_token_request_is_refused_without_consuming_a_retry() {
    let callbacks = ScriptedUv::new(UvResult::Unavailable);
    let mut dispatcher = authenticator(callbacks.clone(), false);
    for _ in 0..MAX_RETRIES * 2 {
        assert_eq!(
            token_using_uv(&mut dispatcher),
            Err(StatusCode::OperationDenied)
        );
    }
    assert_eq!(callbacks.asked(), usize::from(MAX_RETRIES) * 2);
    assert_eq!(retries(&mut dispatcher), MAX_RETRIES);

    // The same request answered `Denied` does consume them.
    callbacks.set(UvResult::Denied);
    assert_eq!(
        token_using_uv(&mut dispatcher),
        Err(StatusCode::OperationDenied)
    );
    assert_eq!(retries(&mut dispatcher), MAX_RETRIES - 1);
}
