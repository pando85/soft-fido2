#![cfg(feature = "transport")]

use soft_fido2_ctap::{
    Authenticator, AuthenticatorConfig, CommandDispatcher, Credential, CredentialStorageCallbacks,
    StatusCode, TransportBridge, UpResult, UserInteractionCallbacks, UvResult,
    callbacks::PlatformCallbacks,
    cbor::{MapBuilder, MapParser},
};
use soft_fido2_transport::{Cmd, CommandHandler};

#[derive(Clone, Copy)]
struct BatchCallbacks;

impl PlatformCallbacks for BatchCallbacks {
    fn get_timestamp_ms(&self) -> u64 {
        1_000
    }
}

impl UserInteractionCallbacks for BatchCallbacks {
    fn request_up(
        &self,
        _info: &str,
        _user_name: Option<&str>,
        _rp_id: &str,
    ) -> Result<UpResult, StatusCode> {
        Ok(UpResult::Accepted)
    }

    fn request_uv(
        &self,
        _info: &str,
        _user_name: Option<&str>,
        _rp_id: &str,
    ) -> Result<UvResult, StatusCode> {
        Ok(UvResult::Accepted)
    }

    fn select_credential(
        &self,
        _rp_id: &str,
        _user_names: &[String],
    ) -> Result<usize, StatusCode> {
        Ok(0)
    }
}

impl CredentialStorageCallbacks for BatchCallbacks {
    fn write_credential(&self, _credential: &Credential) -> Result<(), StatusCode> {
        Ok(())
    }

    fn delete_credential(&self, _credential_id: &[u8]) -> Result<(), StatusCode> {
        Ok(())
    }

    fn read_credentials(
        &self,
        _rp_id: &str,
        _user_id: Option<&[u8]>,
    ) -> Result<Vec<Credential>, StatusCode> {
        Ok(Vec::new())
    }

    fn credential_exists(&self, _credential_id: &[u8]) -> Result<bool, StatusCode> {
        Ok(false)
    }

    fn get_credential(&self, _credential_id: &[u8]) -> Result<Credential, StatusCode> {
        Err(StatusCode::NoCredentials)
    }

    fn update_credential(&self, _credential: &Credential) -> Result<(), StatusCode> {
        Ok(())
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>, StatusCode> {
        Ok(Vec::new())
    }

    fn credential_count(&self) -> Result<usize, StatusCode> {
        Ok(0)
    }
}

fn bridge() -> TransportBridge<BatchCallbacks> {
    let authenticator = Authenticator::new(AuthenticatorConfig::new(), BatchCallbacks);
    TransportBridge::new(CommandDispatcher::new(authenticator))
}

#[test]
#[ignore = "requires the composed FIDO 2.3 compatibility batch"]
fn missing_credential_management_authorization_is_wire_value_0x36() {
    let mut bridge = bridge();
    let params = MapBuilder::new().insert(1, 1u8).unwrap().build().unwrap();
    let mut command = vec![0x0a];
    command.extend_from_slice(&params);

    let response = bridge.handle_command(Cmd::Cbor, &command).unwrap();

    assert_eq!(response, vec![0x36]);
    assert_eq!(StatusCode::PuatRequired as u8, 0x36);
    assert_eq!(StatusCode::UnauthorizedPermission as u8, 0x40);
}

#[test]
#[ignore = "requires the composed FIDO 2.3 compatibility batch"]
fn reserved_and_non_standard_pin_uv_statuses_are_not_decoded() {
    assert_eq!(StatusCode::from_u8(0x38), StatusCode::Other);
    assert_eq!(StatusCode::from_u8(0x41), StatusCode::Other);
}

#[test]
#[ignore = "requires the composed FIDO 2.3 compatibility batch"]
fn get_info_advertises_only_the_truthful_version_baseline() {
    let mut bridge = bridge();
    let response = bridge.handle_command(Cmd::Cbor, &[0x04]).unwrap();

    assert_eq!(response.first(), Some(&0x00));
    let parser = MapParser::from_bytes(&response[1..]).unwrap();
    let versions: Vec<String> = parser.get(1).unwrap();

    assert_eq!(versions, vec!["FIDO_2_0".to_string()]);
    assert!(!versions.iter().any(|version| version == "FIDO_2_1"));
    assert!(!versions.iter().any(|version| version == "FIDO_2_2"));
    assert!(!versions.iter().any(|version| version == "FIDO_2_3"));
}
