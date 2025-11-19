//! authenticatorSelection command
//!
//! Simple command to blink/flash the authenticator for user identification.
//! Used when multiple authenticators are present.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorSelection>

use crate::UpResult;
use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::cbor::MapBuilder;
use crate::status::{Result, StatusCode};

/// Handle authenticatorSelection command
///
/// This command requests user presence (typically by blinking an LED or
/// similar indication) to allow the user to identify which authenticator
/// they want to use.
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    _data: &[u8],
) -> Result<Vec<u8>> {
    // Request user presence with selection-specific message
    let info = "Select this authenticator";
    match auth.callbacks().request_up(info, None, "")? {
        UpResult::Accepted => {
            // User confirmed this authenticator
            MapBuilder::new().build()
        }
        UpResult::Denied => Err(StatusCode::OperationDenied),
        UpResult::Timeout => Err(StatusCode::UserActionTimeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UvResult;
    use crate::authenticator::{Authenticator, AuthenticatorConfig};
    use crate::callbacks::{CredentialStorageCallbacks, UserInteractionCallbacks};
    use crate::types::Credential;

    struct AcceptingCallbacks;

    impl UserInteractionCallbacks for AcceptingCallbacks {
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

    impl CredentialStorageCallbacks for AcceptingCallbacks {
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

    struct DenyingCallbacks;

    impl UserInteractionCallbacks for DenyingCallbacks {
        fn request_up(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> Result<UpResult> {
            Ok(UpResult::Denied)
        }

        fn request_uv(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> Result<UvResult> {
            Ok(UvResult::Denied)
        }

        fn select_credential(&self, _rp_id: &str, _user_names: &[String]) -> Result<usize> {
            Ok(0)
        }
    }

    impl CredentialStorageCallbacks for DenyingCallbacks {
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
    fn test_selection_accepted() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, AcceptingCallbacks);

        let response = handle(&mut auth, &[]).unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn test_selection_denied() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, DenyingCallbacks);

        let result = handle(&mut auth, &[]);
        assert_eq!(result, Err(StatusCode::OperationDenied));
    }
}
