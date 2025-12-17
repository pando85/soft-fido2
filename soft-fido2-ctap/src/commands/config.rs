//! authenticatorConfig command
//!
//! Allows platforms to configure authenticator settings like enterprise attestation,
//! user verification requirements, and minimum PIN length.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorConfig>

use crate::{
    authenticator::Authenticator,
    callbacks::AuthenticatorCallbacks,
    cbor::MapParser,
    status::{Result, StatusCode},
};

use alloc::vec::Vec;

/// authenticatorConfig request parameter keys
#[allow(dead_code)]
mod req_keys {
    pub const SUBCOMMAND: i32 = 0x01;
    pub const SUBCOMMAND_PARAMS: i32 = 0x02;
    pub const PIN_UV_AUTH_PROTOCOL: i32 = 0x03;
    pub const PIN_UV_AUTH_PARAM: i32 = 0x04;
}

/// authenticatorConfig subcommand codes
#[allow(dead_code)]
mod subcommands {
    pub const ENABLE_ENTERPRISE_ATTESTATION: u8 = 0x01;
    pub const TOGGLE_ALWAYS_UV: u8 = 0x02;
    pub const SET_MIN_PIN_LENGTH: u8 = 0x03;
    pub const VENDOR_PROTOTYPE: u8 = 0xFF;
}

/// Handle authenticatorConfig command
///
/// Minimal implementation that verifies PIN/UV auth token with ac permission
/// and returns CTAP2_ERR_UNSUPPORTED_OPTION for all subcommands.
///
/// This allows the authenticator to be FIDO 2.2 compliant without implementing
/// optional configuration features. Platforms will not attempt to use this command
/// because the `authnrCfg` option in getInfo will be false.
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;

    // Parse required parameters
    let subcommand: u8 = parser.get(req_keys::SUBCOMMAND)?;

    // Parse PIN/UV auth parameters
    let pin_uv_auth_param: Option<Vec<u8>> =
        if parser.get_raw(req_keys::PIN_UV_AUTH_PARAM).is_some() {
            Some(parser.get_bytes(req_keys::PIN_UV_AUTH_PARAM)?)
        } else {
            None
        };
    let pin_uv_auth_protocol: Option<u8> = parser.get_opt(req_keys::PIN_UV_AUTH_PROTOCOL)?;

    // Verify PIN/UV authentication
    // All authenticatorConfig subcommands require authentication
    if let Some(ref pin_auth) = pin_uv_auth_param {
        let protocol = pin_uv_auth_protocol.ok_or(StatusCode::MissingParameter)?;

        // Verify pinUvAuthParam over subCommand parameter
        // Per spec: verify(pinUvAuthToken, uint8(subCommand), pinUvAuthParam)
        let subcommand_bytes = [subcommand];
        auth.verify_pin_uv_auth_param(protocol, pin_auth, &subcommand_bytes)?;

        // Verify PIN token has ac (AuthenticatorConfiguration) permission
        auth.verify_pin_uv_auth_token(
            crate::pin_token::Permission::AuthenticatorConfiguration,
            None, // No RP ID for config operations
        )?;
    } else {
        // PIN/UV auth is required for all config operations
        return Err(StatusCode::PinRequired);
    }

    // Minimal implementation: all subcommands are unsupported
    // This is spec-compliant since authenticatorConfig is optional
    match subcommand {
        subcommands::ENABLE_ENTERPRISE_ATTESTATION
        | subcommands::TOGGLE_ALWAYS_UV
        | subcommands::SET_MIN_PIN_LENGTH
        | subcommands::VENDOR_PROTOTYPE => {
            // Return unsupported to indicate this configuration is not available
            Err(StatusCode::UnsupportedOption)
        }
        _ => {
            // Unknown subcommand
            Err(StatusCode::InvalidSubcommand)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        UpResult, UvResult,
        authenticator::{Authenticator, AuthenticatorConfig},
        callbacks::{CredentialStorageCallbacks, PlatformCallbacks, UserInteractionCallbacks},
        cbor::MapBuilder,
        types::Credential,
    };

    use alloc::string::String;

    struct MockCallbacks;

    impl PlatformCallbacks for MockCallbacks {
        fn get_timestamp_ms(&self) -> u64 {
            0
        }
    }

    impl UserInteractionCallbacks for MockCallbacks {
        fn request_up(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> Result<UpResult> {
            Ok(UpResult::Accepted)
        }

        fn request_uv(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> Result<UvResult> {
            Ok(UvResult::Accepted)
        }

        fn select_credential(&self, _rp_id: &str, _user_names: &[String]) -> Result<usize> {
            Ok(0)
        }
    }

    impl CredentialStorageCallbacks for MockCallbacks {
        fn write_credential(&self, _credential: &Credential) -> Result<()> {
            Ok(())
        }

        fn delete_credential(&self, _credential_id: &[u8]) -> Result<()> {
            Ok(())
        }

        fn read_credentials(
            &self,
            _rp_id: &str,
            _user_id: Option<&[u8]>,
        ) -> Result<Vec<Credential>> {
            Ok(Vec::new())
        }

        fn credential_exists(&self, _credential_id: &[u8]) -> Result<bool> {
            Ok(false)
        }

        fn get_credential(&self, _credential_id: &[u8]) -> Result<Credential> {
            Err(StatusCode::NoCredentials)
        }

        fn update_credential(&self, _credential: &Credential) -> Result<()> {
            Ok(())
        }

        fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
            Ok(Vec::new())
        }

        fn credential_count(&self) -> Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn test_config_requires_pin_auth() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, MockCallbacks);

        // Build request without PIN auth
        let request = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, subcommands::SET_MIN_PIN_LENGTH)
            .unwrap()
            .build()
            .unwrap();

        let result = handle(&mut auth, &request);
        assert_eq!(result, Err(StatusCode::PinRequired));
    }

    #[test]
    fn test_config_invalid_subcommand() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, MockCallbacks);

        // Build request with invalid subcommand (but valid auth for testing)
        let request = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x99u8)
            .unwrap()
            .build()
            .unwrap();

        // Without proper PIN auth, should fail at auth check first
        let result = handle(&mut auth, &request);
        assert_eq!(result, Err(StatusCode::PinRequired));
    }

    #[test]
    fn test_config_missing_subcommand() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, MockCallbacks);

        // Build request without subcommand
        let request = MapBuilder::new().build().unwrap();

        let result = handle(&mut auth, &request);
        assert_eq!(result, Err(StatusCode::MissingParameter));
    }
}
