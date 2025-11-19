//! CTAP Command Dispatcher
//!
//! Routes CTAP commands to their appropriate handlers and manages the
//! authenticator state.

use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::commands::CommandCode;
use crate::status::{Result, StatusCode};

/// CTAP command dispatcher
///
/// Receives raw CTAP command bytes and dispatches to the appropriate
/// command handler. Manages the authenticator instance and its state.
pub struct CommandDispatcher<C: AuthenticatorCallbacks> {
    /// The authenticator instance
    authenticator: Authenticator<C>,
}

impl<C: AuthenticatorCallbacks> CommandDispatcher<C> {
    /// Create a new command dispatcher
    pub fn new(authenticator: Authenticator<C>) -> Self {
        Self { authenticator }
    }

    /// Dispatch a CTAP command
    ///
    /// The input data format is:
    /// - First byte: command code
    /// - Remaining bytes: CBOR-encoded command parameters
    ///
    /// Returns the CBOR-encoded response, or a status code on error.
    pub fn dispatch(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(StatusCode::InvalidParameter);
        }

        let command_code = data[0];
        let command_data = &data[1..];

        let cmd = CommandCode::from_u8(command_code).ok_or(StatusCode::InvalidCommand)?;

        match cmd {
            CommandCode::MakeCredential => {
                crate::commands::make_credential::handle(&mut self.authenticator, command_data)
            }
            CommandCode::GetAssertion => {
                crate::commands::get_assertion::handle(&mut self.authenticator, command_data)
            }
            CommandCode::GetInfo => crate::commands::get_info::handle(&self.authenticator),
            CommandCode::ClientPin => {
                crate::commands::client_pin::handle(&mut self.authenticator, command_data)
            }
            CommandCode::Reset => {
                // Reset requires user confirmation
                self.authenticator.reset()?;
                Ok(vec![]) // Empty response on success
            }
            CommandCode::GetNextAssertion => {
                crate::commands::get_next_assertion::handle(&mut self.authenticator, command_data)
            }
            CommandCode::CredentialManagement => crate::commands::credential_management::handle(
                &mut self.authenticator,
                command_data,
            ),
            CommandCode::Selection => {
                crate::commands::selection::handle(&mut self.authenticator, command_data)
            }
            CommandCode::LargeBlobs | CommandCode::Config => {
                // Not yet implemented
                Err(StatusCode::InvalidCommand)
            }
        }
    }

    /// Get a reference to the authenticator
    pub fn authenticator(&self) -> &Authenticator<C> {
        &self.authenticator
    }

    /// Get a mutable reference to the authenticator
    pub fn authenticator_mut(&mut self) -> &mut Authenticator<C> {
        &mut self.authenticator
    }

    /// Consume the dispatcher and return the authenticator
    pub fn into_authenticator(self) -> Authenticator<C> {
        self.authenticator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::AuthenticatorConfig;
    use crate::callbacks::{CredentialStorageCallbacks, UserInteractionCallbacks};
    use crate::types::Credential;
    use crate::{UpResult, UvResult};

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
    fn test_get_info_command() {
        let config = AuthenticatorConfig::new();
        let authenticator = Authenticator::new(config, MockCallbacks);
        let mut dispatcher = CommandDispatcher::new(authenticator);

        // GetInfo command code is 0x04, with empty parameters
        let command = vec![0x04];

        let response = dispatcher.dispatch(&command).unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn test_invalid_command() {
        let config = AuthenticatorConfig::new();
        let authenticator = Authenticator::new(config, MockCallbacks);
        let mut dispatcher = CommandDispatcher::new(authenticator);

        // Invalid command code
        let command = vec![0xFF];

        let result = dispatcher.dispatch(&command);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::InvalidCommand);
    }

    #[test]
    fn test_empty_command() {
        let config = AuthenticatorConfig::new();
        let authenticator = Authenticator::new(config, MockCallbacks);
        let mut dispatcher = CommandDispatcher::new(authenticator);

        let result = dispatcher.dispatch(&[]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::InvalidParameter);
    }

    #[test]
    fn test_reset_command() {
        let config = AuthenticatorConfig::new();
        let mut authenticator = Authenticator::new(config, MockCallbacks);
        authenticator.set_pin("test1234").unwrap();

        let mut dispatcher = CommandDispatcher::new(authenticator);

        // Reset command code is 0x07
        let command = vec![0x07];

        let response = dispatcher.dispatch(&command).unwrap();
        assert!(response.is_empty()); // Reset returns empty response

        // PIN should be cleared after reset
        assert!(!dispatcher.authenticator().is_pin_set());
    }
}
