//! authenticatorGetNextAssertion command
//!
//! Continues an assertion operation when there are multiple credentials
//! for a given RP. Must be called after authenticatorGetAssertion.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetNextAssertion>

use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::status::{Result, StatusCode};

/// Handle authenticatorGetNextAssertion command
///
/// Returns the next assertion from the batch created by authenticatorGetAssertion.
/// This is a simplified implementation that returns an error - full implementation
/// would require maintaining assertion state in the Authenticator.
pub fn handle<C: AuthenticatorCallbacks>(
    _auth: &mut Authenticator<C>,
    _data: &[u8],
) -> Result<Vec<u8>> {
    // TODO: Implement full getNextAssertion with state management
    // For now, return NoCredentials to indicate no more assertions available
    // A full implementation would:
    // 1. Check if there's an ongoing assertion operation
    // 2. Verify the assertion hasn't timed out
    // 3. Return the next credential from the list
    // 4. Update the remaining count
    Err(StatusCode::NoCredentials)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::{Authenticator, AuthenticatorConfig};
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
    fn test_get_next_assertion_no_state() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, MockCallbacks);

        // Should return error when no assertion is in progress
        let result = handle(&mut auth, &[]);
        assert_eq!(result, Err(StatusCode::NoCredentials));
    }
}
