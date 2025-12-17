//! PIN token management
//!
//! PIN tokens are used to authorize CTAP operations after successful PIN verification.
//! They have a limited lifetime and specific permissions that control which operations
//! can be performed.
//!
//! # Token Lifetime
//!
//! - **Usage Window**: 19 seconds from creation (for starting new operations)
//! - **Maximum Lifetime**: 10 minutes from creation (absolute expiration)
//!
//! # SECURITY WARNING: no_std Builds
//!
//! In `no_std` builds without a real-time clock, `current_timestamp_ms()` returns 0,
//! which means **PIN tokens never expire**. This creates a security risk:
//!
//! - Captured tokens can be replayed indefinitely
//! - The 19-second usage window is not enforced
//! - The 10-minute lifetime is not enforced
//!
//! **Mitigation for no_std integrators:**
//! 1. Provide a custom time source by implementing a platform-specific `current_timestamp_ms()`
//! 2. Implement session-based token invalidation at the transport layer
//! 3. Limit token usage to single operations where possible
//!
//! Reference: FIDO2 CTAP 2.1 specification, Section 6.5.5.7

use crate::SecBytes;
use crate::StatusCode;

use alloc::string::String;

/// PIN token usage window in milliseconds (19 seconds)
///
/// Per FIDO2 spec, a PIN token must be used within 19 seconds of generation,
/// after which it can no longer authorize new operations.
const USAGE_WINDOW_MS: u64 = 19_000;

/// PIN token lifetime in milliseconds (10 minutes)
///
/// Maximum lifetime of a PIN token from creation to expiration.
const LIFETIME_MS: u64 = 600_000;

/// PIN/UV auth token permissions
///
/// These permissions control which CTAP operations can be authorized
/// with a given PIN token. Multiple permissions can be combined using
/// bitwise OR.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Make credential permission (0x01)
    ///
    /// Allows authenticatorMakeCredential operations
    MakeCredential = 0x01,

    /// Get assertion permission (0x02)
    ///
    /// Allows authenticatorGetAssertion operations
    GetAssertion = 0x02,

    /// Credential management permission (0x04)
    ///
    /// Allows authenticatorCredentialManagement operations
    CredentialManagement = 0x04,

    /// Bio enrollment permission (0x08)
    ///
    /// Allows authenticatorBioEnrollment operations
    BioEnrollment = 0x08,

    /// Large blob write permission (0x10)
    ///
    /// Allows writing to the large blob array
    LargeBlobWrite = 0x10,

    /// Authenticator configuration permission (0x20)
    ///
    /// Allows authenticatorConfig operations
    AuthenticatorConfiguration = 0x20,
}

impl Permission {
    /// Convert permission to u8 bitmask value
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Check if a permission bitmask includes this permission
    pub fn is_set_in(self, permissions: u8) -> bool {
        (permissions & self.to_u8()) != 0
    }
}

/// PIN/UV auth token
///
/// Represents an authorization token obtained after successful PIN verification.
/// The token has limited lifetime and specific permissions.
#[derive(Clone)]
pub struct PinToken {
    /// The token value (32 random bytes, mlock + zeroed on drop)
    token: SecBytes,

    /// Permission bitmask
    permissions: u8,

    /// RP ID for permissions that require it (e.g., MakeCredential, GetAssertion)
    rp_id: Option<String>,

    /// Creation timestamp (milliseconds since UNIX epoch)
    created_at: u64,

    /// Last usage timestamp (milliseconds since UNIX epoch)
    last_used: u64,
}

impl PinToken {
    /// Create a new PIN token with specified permissions
    ///
    /// # Arguments
    ///
    /// * `token` - Random 32-byte token value
    /// * `permissions` - Permission bitmask
    /// * `rp_id` - Optional RP ID for RP-scoped permissions
    /// * `now` - Current timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// New PIN token with current timestamp
    pub fn new(token: [u8; 32], permissions: u8, rp_id: Option<String>, now: u64) -> Self {
        Self {
            token: SecBytes::from_array(token),
            permissions,
            rp_id,
            created_at: now,
            last_used: now,
        }
    }

    /// Get the token value as a fixed-size array reference
    ///
    /// # Panics
    ///
    /// Panics if the internal token is not exactly 32 bytes (should never happen
    /// since tokens are always created with 32 bytes).
    pub fn value(&self) -> &[u8; 32] {
        self.token
            .as_slice()
            .try_into()
            .expect("PinToken always contains exactly 32 bytes")
    }

    /// Get the permission bitmask
    pub fn permissions(&self) -> u8 {
        self.permissions
    }

    /// Get the RP ID if set
    pub fn rp_id(&self) -> Option<&str> {
        self.rp_id.as_deref()
    }

    /// Check if token has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        permission.is_set_in(self.permissions)
    }

    /// Check if token is still valid (within lifetime)
    pub fn is_valid(&self, now: u64) -> bool {
        let age = now.saturating_sub(self.created_at);
        age < LIFETIME_MS
    }

    /// Check if token can be used for a new operation (within usage window)
    ///
    /// Per FIDO2 spec, a token can only be used to start new operations
    /// within 19 seconds of creation, but operations started within that
    /// window can continue until the token's full lifetime expires.
    pub fn is_within_usage_window(&self, now: u64) -> bool {
        let age = now.saturating_sub(self.created_at);
        age < USAGE_WINDOW_MS
    }

    /// Update the last used timestamp
    ///
    /// Should be called when the token is used to authorize an operation.
    pub fn mark_used(&mut self, now: u64) {
        self.last_used = now;
    }

    /// Verify token can authorize an operation with given permission and RP ID
    ///
    /// # Arguments
    ///
    /// * `permission` - Required permission
    /// * `rp_id` - RP ID for the operation (if applicable)
    /// * `now` - Current timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// Ok if authorized, error status code otherwise
    pub fn verify_permission(
        &mut self,
        permission: Permission,
        rp_id: Option<&str>,
        now: u64,
    ) -> Result<(), StatusCode> {
        // Check token is still valid
        if !self.is_valid(now) {
            return Err(StatusCode::PinTokenExpired);
        }

        // Check usage window for new operations
        if !self.is_within_usage_window(now) {
            return Err(StatusCode::PinTokenExpired);
        }

        // Check permission is granted
        if !self.has_permission(permission) {
            return Err(StatusCode::UnauthorizedPermission);
        }

        // For RP-scoped permissions, verify RP ID matches
        if matches!(
            permission,
            Permission::MakeCredential | Permission::GetAssertion
        ) {
            match (&self.rp_id, rp_id) {
                (Some(token_rp), Some(req_rp)) if token_rp == req_rp => {
                    // RP ID matches
                }
                (None, _) => {
                    // Token has no RP ID restriction - allow any RP
                }
                _ => {
                    // RP ID mismatch or missing
                    return Err(StatusCode::UnauthorizedPermission);
                }
            }
        }

        // Authorization successful - update last used
        self.mark_used(now);
        Ok(())
    }
}

impl core::fmt::Debug for PinToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinToken")
            .field("token", &"<redacted>")
            .field("permissions", &self.permissions)
            .field("rp_id", &self.rp_id)
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .finish()
    }
}

/// PIN token manager
///
/// Manages the lifecycle of PIN tokens for an authenticator.
/// Only one token can be active at a time.
pub struct PinTokenManager {
    /// Currently active PIN token
    current_token: Option<PinToken>,
}

impl PinTokenManager {
    /// Create a new PIN token manager
    pub fn new() -> Self {
        Self {
            current_token: None,
        }
    }

    /// Set a new PIN token
    ///
    /// This replaces any existing token.
    pub fn set_token(&mut self, token: PinToken) {
        self.current_token = Some(token);
    }

    /// Clear the current token
    pub fn clear_token(&mut self) {
        self.current_token = None;
    }

    /// Get the current token if valid
    ///
    /// Returns None if no token exists or if the token has expired.
    pub fn get_token(&self, now: u64) -> Option<&PinToken> {
        self.current_token
            .as_ref()
            .filter(|token| token.is_valid(now))
    }

    /// Get mutable reference to current token if valid
    pub fn get_token_mut(&mut self, now: u64) -> Option<&mut PinToken> {
        if let Some(token) = &self.current_token
            && !token.is_valid(now)
        {
            self.current_token = None;
            return None;
        }
        self.current_token.as_mut()
    }

    /// Verify current token can authorize an operation
    ///
    /// # Arguments
    ///
    /// * `permission` - Required permission
    /// * `rp_id` - RP ID for the operation (if applicable)
    /// * `now` - Current timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// Ok if authorized, error status code otherwise
    pub fn verify_permission(
        &mut self,
        permission: Permission,
        rp_id: Option<&str>,
        now: u64,
    ) -> Result<(), StatusCode> {
        match self.get_token_mut(now) {
            Some(token) => token.verify_permission(permission, rp_id, now),
            None => Err(StatusCode::PinRequired),
        }
    }

    /// Check if a valid token exists
    pub fn has_valid_token(&self, now: u64) -> bool {
        self.get_token(now).is_some()
    }

    /// Check if a valid token exists within the usage window (19 seconds)
    pub fn has_valid_token_within_usage_window(&self, now: u64) -> bool {
        match &self.current_token {
            Some(token) => token.is_valid(now) && token.is_within_usage_window(now),
            None => false,
        }
    }

    /// Clear PIN/UV auth token permissions except large blob write (lbw)
    ///
    /// Per FIDO2 spec section 6.1.2 step 14.3, after makeCredential completes,
    /// all permissions except lbw should be cleared.
    pub fn clear_permissions_except_lbw(&mut self) {
        if let Some(token) = &mut self.current_token {
            // Keep only LargeBlobWrite permission (0x10)
            token.permissions &= Permission::LargeBlobWrite.to_u8();
        }
    }
}

impl Default for PinTokenManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test token with default values
    fn create_test_token(now: u64) -> PinToken {
        let token = [0x42u8; 32];
        let permissions = Permission::MakeCredential.to_u8() | Permission::GetAssertion.to_u8();
        PinToken::new(token, permissions, Some("example.com".to_string()), now)
    }

    #[test]
    fn test_permission_bits() {
        assert_eq!(Permission::MakeCredential.to_u8(), 0x01);
        assert_eq!(Permission::GetAssertion.to_u8(), 0x02);
        assert_eq!(Permission::CredentialManagement.to_u8(), 0x04);
        assert_eq!(Permission::BioEnrollment.to_u8(), 0x08);
        assert_eq!(Permission::LargeBlobWrite.to_u8(), 0x10);
        assert_eq!(Permission::AuthenticatorConfiguration.to_u8(), 0x20);
    }

    #[test]
    fn test_permission_is_set() {
        let permissions = 0x03; // MakeCredential | GetAssertion
        assert!(Permission::MakeCredential.is_set_in(permissions));
        assert!(Permission::GetAssertion.is_set_in(permissions));
        assert!(!Permission::CredentialManagement.is_set_in(permissions));
    }

    #[test]
    fn test_token_creation() {
        let now = 1000;
        let token = create_test_token(now);
        assert_eq!(token.value(), &[0x42u8; 32]);
        assert_eq!(token.permissions(), 0x03);
        assert_eq!(token.rp_id(), Some("example.com"));
        assert!(token.is_valid(now));
        assert!(token.is_within_usage_window(now));
    }

    #[test]
    fn test_token_has_permission() {
        let now = 1000;
        let token = create_test_token(now);
        assert!(token.has_permission(Permission::MakeCredential));
        assert!(token.has_permission(Permission::GetAssertion));
        assert!(!token.has_permission(Permission::CredentialManagement));
    }

    #[test]
    fn test_token_verify_permission_success() {
        let now = 1000;
        let mut token = create_test_token(now);
        assert!(
            token
                .verify_permission(Permission::MakeCredential, Some("example.com"), now)
                .is_ok()
        );
        assert!(
            token
                .verify_permission(Permission::GetAssertion, Some("example.com"), now)
                .is_ok()
        );
    }

    #[test]
    fn test_token_verify_permission_wrong_rp() {
        let now = 1000;
        let mut token = create_test_token(now);
        let result = token.verify_permission(Permission::MakeCredential, Some("other.com"), now);
        assert_eq!(result, Err(StatusCode::UnauthorizedPermission));
    }

    #[test]
    fn test_token_verify_permission_no_permission() {
        let now = 1000;
        let mut token = create_test_token(now);
        let result = token.verify_permission(Permission::CredentialManagement, None, now);
        assert_eq!(result, Err(StatusCode::UnauthorizedPermission));
    }

    #[test]
    fn test_token_no_rp_restriction() {
        let now = 1000;
        let token_data = [0x42u8; 32];
        let permissions = Permission::MakeCredential.to_u8();
        let mut token = PinToken::new(token_data, permissions, None, now);

        // Token without RP ID should allow any RP
        assert!(
            token
                .verify_permission(Permission::MakeCredential, Some("example.com"), now)
                .is_ok()
        );
        assert!(
            token
                .verify_permission(Permission::MakeCredential, Some("other.com"), now)
                .is_ok()
        );
    }

    #[test]
    fn test_token_usage_window_expiry() {
        let now = 1000;
        let token_data = [0x42u8; 32];
        let permissions = Permission::MakeCredential.to_u8();
        let mut token = PinToken::new(token_data, permissions, None, now);

        // Simulate time passing beyond usage window
        let later = now + USAGE_WINDOW_MS + 1000;

        assert!(token.is_valid(later)); // Still within lifetime
        assert!(!token.is_within_usage_window(later)); // But usage window expired

        let result = token.verify_permission(Permission::MakeCredential, None, later);
        assert_eq!(result, Err(StatusCode::PinTokenExpired));
    }

    #[test]
    fn test_token_lifetime_expiry() {
        let now = 1000;
        let token_data = [0x42u8; 32];
        let permissions = Permission::MakeCredential.to_u8();
        let mut token = PinToken::new(token_data, permissions, None, now);

        // Simulate time passing beyond lifetime
        let later = now + LIFETIME_MS + 1000;

        assert!(!token.is_valid(later));

        let result = token.verify_permission(Permission::MakeCredential, None, later);
        assert_eq!(result, Err(StatusCode::PinTokenExpired));
    }

    #[test]
    fn test_token_manager_basic() {
        let now = 1000;
        let mut manager = PinTokenManager::new();
        assert!(!manager.has_valid_token(now));
        assert!(manager.get_token(now).is_none());

        let token = create_test_token(now);
        manager.set_token(token);
        assert!(manager.has_valid_token(now));
        assert!(manager.get_token(now).is_some());

        manager.clear_token();
        assert!(!manager.has_valid_token(now));
    }

    #[test]
    fn test_token_manager_verify_permission() {
        let now = 1000;
        let mut manager = PinTokenManager::new();

        // No token - should fail
        let result =
            manager.verify_permission(Permission::MakeCredential, Some("example.com"), now);
        assert_eq!(result, Err(StatusCode::PinRequired));

        // Set valid token
        manager.set_token(create_test_token(now));

        // Should succeed
        assert!(
            manager
                .verify_permission(Permission::MakeCredential, Some("example.com"), now)
                .is_ok()
        );

        // Wrong permission
        let result = manager.verify_permission(Permission::CredentialManagement, None, now);
        assert_eq!(result, Err(StatusCode::UnauthorizedPermission));
    }

    #[test]
    fn test_token_manager_expired_token() {
        let now = 1000;
        let mut manager = PinTokenManager::new();
        let token = create_test_token(now);

        // Expire the token
        let later = now + LIFETIME_MS + 1000;
        manager.set_token(token);

        // Should be treated as no token
        assert!(!manager.has_valid_token(later));
        assert!(manager.get_token(later).is_none());
    }

    #[test]
    fn test_token_mark_used() {
        let now = 1000;
        let mut token = create_test_token(now);
        let initial_last_used = token.last_used;

        // Simulate time passing
        let later = now + 100;

        token.mark_used(later);
        assert!(token.last_used > initial_last_used);
    }
}
