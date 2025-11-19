//! Transport-Protocol Bridge
//!
//! Connects the CTAP transport layer (keylib-transport) with the CTAP
//! protocol layer (keylib-ctap) by implementing the CommandHandler trait.
//!
//! This module is only available when the "transport" feature is enabled.

#[cfg(feature = "transport")]
use crate::callbacks::AuthenticatorCallbacks;
#[cfg(feature = "transport")]
use crate::dispatcher::CommandDispatcher;
#[cfg(feature = "transport")]
use crate::status::StatusCode;

/// Bridge between transport CommandHandler and CTAP CommandDispatcher
///
/// Implements the `soft_fido2_transport::CommandHandler` trait to allow
/// the CTAP authenticator to be used with the CTAP HID transport layer.
#[cfg(feature = "transport")]
pub struct TransportBridge<C: AuthenticatorCallbacks> {
    dispatcher: CommandDispatcher<C>,
}

#[cfg(feature = "transport")]
impl<C: AuthenticatorCallbacks> TransportBridge<C> {
    /// Create a new transport bridge
    pub fn new(dispatcher: CommandDispatcher<C>) -> Self {
        Self { dispatcher }
    }

    /// Get a reference to the dispatcher
    pub fn dispatcher(&self) -> &CommandDispatcher<C> {
        &self.dispatcher
    }

    /// Get a mutable reference to the dispatcher
    pub fn dispatcher_mut(&mut self) -> &mut CommandDispatcher<C> {
        &mut self.dispatcher
    }

    /// Consume the bridge and return the dispatcher
    pub fn into_dispatcher(self) -> CommandDispatcher<C> {
        self.dispatcher
    }
}

#[cfg(feature = "transport")]
impl<C: AuthenticatorCallbacks> soft_fido2_transport::CommandHandler for TransportBridge<C> {
    fn handle_command(
        &mut self,
        cmd: soft_fido2_transport::Cmd,
        data: &[u8],
    ) -> soft_fido2_transport::Result<Vec<u8>> {
        match cmd {
            soft_fido2_transport::Cmd::Cbor => {
                // CBOR command - dispatch to CTAP protocol handler
                self.dispatcher.dispatch(data).map_err(|e| {
                    // Convert CTAP status code to transport error
                    match e {
                        StatusCode::InvalidParameter => {
                            soft_fido2_transport::Error::Other("Invalid parameter".to_string())
                        }
                        StatusCode::InvalidCommand => soft_fido2_transport::Error::InvalidCommand,
                        _ => soft_fido2_transport::Error::Other(format!("CTAP error: {:?}", e)),
                    }
                })
            }
            soft_fido2_transport::Cmd::Msg => {
                // CTAP1/U2F message - not yet supported
                Err(soft_fido2_transport::Error::Other(
                    "CTAP1/U2F not supported".to_string(),
                ))
            }
            _ => {
                // Other commands should be handled by the transport layer
                // This should not happen in normal operation
                Err(soft_fido2_transport::Error::InvalidCommand)
            }
        }
    }
}

#[cfg(all(test, feature = "transport"))]
mod tests {
    use super::*;
    use crate::authenticator::{Authenticator, AuthenticatorConfig};
    use crate::callbacks::{CredentialStorageCallbacks, UserInteractionCallbacks};
    use crate::types::Credential;
    use crate::{Result, UpResult, UvResult};
    use soft_fido2_transport::CommandHandler;

    struct MockCallbacks;

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
            Ok(vec![])
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
            Ok(vec![])
        }

        fn credential_count(&self) -> Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn test_cbor_command() {
        let config = AuthenticatorConfig::new();
        let authenticator = Authenticator::new(config, MockCallbacks);
        let dispatcher = CommandDispatcher::new(authenticator);
        let mut bridge = TransportBridge::new(dispatcher);

        // GetInfo command (0x04) with no data
        let data = vec![0x04];

        let result = bridge.handle_command(soft_fido2_transport::Cmd::Cbor, &data);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_msg_command_unsupported() {
        let config = AuthenticatorConfig::new();
        let authenticator = Authenticator::new(config, MockCallbacks);
        let dispatcher = CommandDispatcher::new(authenticator);
        let mut bridge = TransportBridge::new(dispatcher);

        let data = vec![];
        let result = bridge.handle_command(soft_fido2_transport::Cmd::Msg, &data);
        assert!(result.is_err());
    }
}
