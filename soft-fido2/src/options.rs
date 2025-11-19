//! Authenticator Options (pure-rust compatibility layer)
//!
//! This module provides API compatibility with zig-ffi for options configuration.
//! In pure-rust implementation, these options control the authenticator's reported
//! capabilities via getInfo responses.

/// Authenticator options for controlling device capabilities
///
/// This struct provides API compatibility with zig-ffi.
/// In pure-rust implementation, these options are informational and control
/// what capabilities are reported in getInfo responses.
#[derive(Debug, Clone)]
pub struct AuthenticatorOptions {
    /// Resident key (discoverable credentials) support
    pub rk: bool,

    /// User presence capable
    pub up: bool,

    /// User verification capability
    pub uv: Option<bool>,

    /// Platform device (cannot be removed)
    pub plat: bool,

    /// Client PIN capability
    pub client_pin: Option<bool>,

    /// PIN/UV auth token support
    pub pin_uv_auth_token: Option<bool>,

    /// Credential management support
    pub cred_mgmt: Option<bool>,

    /// Biometric enrollment support
    pub bio_enroll: Option<bool>,

    /// Large blobs support
    pub large_blobs: Option<bool>,

    /// Enterprise attestation
    pub ep: Option<bool>,

    /// Always require user verification
    pub always_uv: Option<bool>,

    /// Make credential without UV (makeCredUvNotRqd)
    ///
    /// When true, indicates that the authenticator can create credentials
    /// without performing UV when UV is not required by the relying party.
    /// This provides more flexible UV behavior for testing.
    pub make_cred_uv_not_required: Option<bool>,
}

impl Default for AuthenticatorOptions {
    fn default() -> Self {
        Self {
            rk: true,
            up: true,
            uv: None,
            plat: false,
            client_pin: Some(true),
            pin_uv_auth_token: Some(true),
            cred_mgmt: None,
            bio_enroll: None,
            large_blobs: None,
            ep: None,
            always_uv: None,
            make_cred_uv_not_required: None,
        }
    }
}

impl AuthenticatorOptions {
    /// Create new options with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set resident key support
    pub fn with_resident_keys(mut self, enabled: bool) -> Self {
        self.rk = enabled;
        self
    }

    /// Set user presence capability
    pub fn with_user_presence(mut self, enabled: bool) -> Self {
        self.up = enabled;
        self
    }

    /// Set user verification capability
    pub fn with_user_verification(mut self, state: Option<bool>) -> Self {
        self.uv = state;
        self
    }

    /// Set platform device flag
    pub fn with_platform_device(mut self, is_platform: bool) -> Self {
        self.plat = is_platform;
        self
    }

    /// Set client PIN capability
    pub fn with_client_pin(mut self, state: Option<bool>) -> Self {
        self.client_pin = state;
        self
    }

    /// Set PIN/UV auth token support
    pub fn with_pin_uv_auth_token(mut self, state: Option<bool>) -> Self {
        self.pin_uv_auth_token = state;
        self
    }

    /// Set credential management support
    pub fn with_credential_management(mut self, state: Option<bool>) -> Self {
        self.cred_mgmt = state;
        self
    }

    /// Set biometric enrollment support
    pub fn with_biometric_enrollment(mut self, state: Option<bool>) -> Self {
        self.bio_enroll = state;
        self
    }

    /// Set large blobs support
    pub fn with_large_blobs(mut self, state: Option<bool>) -> Self {
        self.large_blobs = state;
        self
    }

    /// Set enterprise attestation support
    pub fn with_enterprise_attestation(mut self, state: Option<bool>) -> Self {
        self.ep = state;
        self
    }

    /// Set always require user verification
    pub fn with_always_uv(mut self, state: Option<bool>) -> Self {
        self.always_uv = state;
        self
    }

    /// Set make credential without UV support
    pub fn with_make_cred_uv_not_required(mut self, state: Option<bool>) -> Self {
        self.make_cred_uv_not_required = state;
        self
    }
}
