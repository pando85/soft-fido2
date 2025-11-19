//! Callback traits for authenticator user interaction and credential storage
//!
//! These traits define the interface between the CTAP protocol implementation
//! and the platform-specific user interaction and storage mechanisms.

use crate::StatusCode;
use crate::types::Credential;

/// Result of a user presence check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpResult {
    /// User denied the operation
    Denied,
    /// User accepted (presence confirmed)
    Accepted,
    /// Operation timed out waiting for user
    Timeout,
}

impl UpResult {
    /// Check if user presence was confirmed
    pub fn is_accepted(self) -> bool {
        self == Self::Accepted
    }
}

/// Result of a user verification check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvResult {
    /// User verification denied
    Denied,
    /// User verification accepted
    Accepted,
    /// User verification accepted with user presence also confirmed
    AcceptedWithUp,
    /// Operation timed out
    Timeout,
}

impl UvResult {
    /// Check if user verification succeeded
    pub fn is_verified(self) -> bool {
        matches!(self, Self::Accepted | Self::AcceptedWithUp)
    }

    /// Check if user presence was also confirmed
    pub fn has_up(self) -> bool {
        self == Self::AcceptedWithUp
    }
}

/// Callbacks for user interaction
///
/// These callbacks are invoked by the authenticator to request user consent
/// and verification during CTAP operations.
pub trait UserInteractionCallbacks {
    /// Request user presence confirmation
    ///
    /// This is typically a simple "tap to confirm" action.
    ///
    /// # Arguments
    ///
    /// * `info` - Context information (e.g., "Register", "Authenticate")
    /// * `user_name` - User name if available
    /// * `rp_id` - Relying party identifier
    ///
    /// # Returns
    ///
    /// Result indicating whether user presence was confirmed
    fn request_up(
        &self,
        info: &str,
        user_name: Option<&str>,
        rp_id: &str,
    ) -> Result<UpResult, StatusCode>;

    /// Request user verification
    ///
    /// This typically involves biometric verification or PIN entry.
    ///
    /// # Arguments
    ///
    /// * `info` - Context information
    /// * `user_name` - User name if available
    /// * `rp_id` - Relying party identifier
    ///
    /// # Returns
    ///
    /// Result indicating whether user verification succeeded
    fn request_uv(
        &self,
        info: &str,
        user_name: Option<&str>,
        rp_id: &str,
    ) -> Result<UvResult, StatusCode>;

    /// Request user to select from multiple credentials
    ///
    /// Called during getAssertion when multiple credentials match.
    ///
    /// # Arguments
    ///
    /// * `rp_id` - Relying party identifier
    /// * `user_names` - List of user names for available credentials
    ///
    /// # Returns
    ///
    /// Index of selected credential, or error
    fn select_credential(&self, rp_id: &str, user_names: &[String]) -> Result<usize, StatusCode>;
}

/// Callbacks for credential storage operations
///
/// These callbacks handle persistent storage and retrieval of credentials.
pub trait CredentialStorageCallbacks {
    /// Write (store) a credential
    ///
    /// # Arguments
    ///
    /// * `credential` - The credential to store
    ///
    /// # Returns
    ///
    /// Success or error status
    fn write_credential(&self, credential: &Credential) -> Result<(), StatusCode>;

    /// Delete a credential by ID
    ///
    /// # Arguments
    ///
    /// * `credential_id` - ID of credential to delete
    ///
    /// # Returns
    ///
    /// Success or error status
    fn delete_credential(&self, credential_id: &[u8]) -> Result<(), StatusCode>;

    /// Read credentials for a specific RP and user
    ///
    /// # Arguments
    ///
    /// * `rp_id` - Relying party identifier
    /// * `user_id` - User handle (optional - if None, return all for RP)
    ///
    /// # Returns
    ///
    /// List of matching credentials
    fn read_credentials(
        &self,
        rp_id: &str,
        user_id: Option<&[u8]>,
    ) -> Result<Vec<Credential>, StatusCode>;

    /// Check if a credential exists
    ///
    /// # Arguments
    ///
    /// * `credential_id` - Credential ID to check
    ///
    /// # Returns
    ///
    /// True if credential exists
    fn credential_exists(&self, credential_id: &[u8]) -> Result<bool, StatusCode>;

    /// Get credential by ID
    ///
    /// # Arguments
    ///
    /// * `credential_id` - Credential ID
    ///
    /// # Returns
    ///
    /// The credential if found
    fn get_credential(&self, credential_id: &[u8]) -> Result<Credential, StatusCode>;

    /// Update credential (e.g., increment signature counter)
    ///
    /// # Arguments
    ///
    /// * `credential` - Updated credential
    ///
    /// # Returns
    ///
    /// Success or error status
    fn update_credential(&self, credential: &Credential) -> Result<(), StatusCode>;

    /// Enumerate all relying parties with stored credentials
    ///
    /// Used for credential management.
    ///
    /// # Returns
    ///
    /// List of (rp_id, rp_name, credential_count) tuples
    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>, StatusCode>;

    /// Get total number of discoverable credentials
    ///
    /// # Returns
    ///
    /// Count of discoverable credentials
    fn credential_count(&self) -> Result<usize, StatusCode>;
}

/// Combined callbacks interface
///
/// Combines user interaction and credential storage callbacks.
pub trait AuthenticatorCallbacks: UserInteractionCallbacks + CredentialStorageCallbacks {
    // This trait is intentionally empty - it just combines the two callback traits
}

// Blanket implementation: any type implementing both traits also implements AuthenticatorCallbacks
impl<T> AuthenticatorCallbacks for T where T: UserInteractionCallbacks + CredentialStorageCallbacks {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_up_result() {
        assert!(UpResult::Accepted.is_accepted());
        assert!(!UpResult::Denied.is_accepted());
        assert!(!UpResult::Timeout.is_accepted());
    }

    #[test]
    fn test_uv_result() {
        assert!(UvResult::Accepted.is_verified());
        assert!(UvResult::AcceptedWithUp.is_verified());
        assert!(!UvResult::Denied.is_verified());
        assert!(!UvResult::Timeout.is_verified());

        assert!(!UvResult::Accepted.has_up());
        assert!(UvResult::AcceptedWithUp.has_up());
    }

    // Mock implementation for testing
    pub struct MockCallbacks;

    impl UserInteractionCallbacks for MockCallbacks {
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
            Ok(0) // Select first credential
        }
    }

    impl CredentialStorageCallbacks for MockCallbacks {
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
            Ok(vec![])
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
            Ok(vec![])
        }

        fn credential_count(&self) -> Result<usize, StatusCode> {
            Ok(0)
        }
    }

    #[test]
    fn test_mock_callbacks() {
        let callbacks = MockCallbacks;

        // Test user interaction callbacks
        let up = callbacks.request_up("Test", None, "example.com").unwrap();
        assert_eq!(up, UpResult::Accepted);

        let uv = callbacks.request_uv("Test", None, "example.com").unwrap();
        assert_eq!(uv, UvResult::Accepted);

        // Test storage callbacks
        assert!(!callbacks.credential_exists(&[1, 2, 3]).unwrap());
        assert_eq!(callbacks.credential_count().unwrap(), 0);
    }

    #[test]
    fn test_authenticator_callbacks_blanket_impl() {
        let callbacks = MockCallbacks;

        // Should work as AuthenticatorCallbacks due to blanket impl
        fn _accepts_combined_callbacks<T: AuthenticatorCallbacks>(_callbacks: &T) {}
        _accepts_combined_callbacks(&callbacks);
    }
}
