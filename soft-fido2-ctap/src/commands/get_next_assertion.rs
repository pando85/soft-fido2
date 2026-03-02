//! authenticatorGetNextAssertion command
//!
//! Continues an assertion operation when there are multiple credentials
//! for a given RP. Must be called after authenticatorGetAssertion.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetNextAssertion>

use crate::{
    authenticator::Authenticator,
    callbacks::AuthenticatorCallbacks,
    status::{Result, StatusCode},
};

use alloc::vec::Vec;

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

    use crate::{
        authenticator::{Authenticator, AuthenticatorConfig},
        test_utils::MockCallbacks,
    };

    #[test]
    fn test_get_next_assertion_no_state() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, MockCallbacks);

        // Should return error when no assertion is in progress
        let result = handle(&mut auth, &[]);
        assert_eq!(result, Err(StatusCode::NoCredentials));
    }
}
