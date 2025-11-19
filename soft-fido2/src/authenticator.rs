//! FIDO2 Authenticator Implementation
//!
//! Provides a high-level FIDO2 authenticator with trait-based callbacks for user interaction.

use crate::error::{Error, Result};
use crate::types::{Credential, CredentialRef};

use soft_fido2_ctap::{
    CommandDispatcher, StatusCode,
    authenticator::{Authenticator as CtapAuthenticator, AuthenticatorConfig as CtapConfig},
    callbacks::{
        CredentialStorageCallbacks, UpResult as CtapUpResult, UserInteractionCallbacks,
        UvResult as CtapUvResult,
    },
    types::Credential as CtapCredential,
};

use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::sync::{Mutex, OnceLock};

#[cfg(not(feature = "std"))]
use spin::Mutex;

/// Global PIN hash storage (std version with lazy initialization)
#[cfg(feature = "std")]
static PRESET_PIN_HASH: OnceLock<Mutex<Option<[u8; 32]>>> = OnceLock::new();

/// Global PIN hash storage (no_std version, always initialized)
#[cfg(not(feature = "std"))]
static PRESET_PIN_HASH: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// User presence result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpResult {
    Denied,
    Accepted,
    Timeout,
}

impl From<UpResult> for CtapUpResult {
    fn from(result: UpResult) -> Self {
        match result {
            UpResult::Denied => CtapUpResult::Denied,
            UpResult::Accepted => CtapUpResult::Accepted,
            UpResult::Timeout => CtapUpResult::Timeout,
        }
    }
}

impl From<CtapUpResult> for UpResult {
    fn from(result: CtapUpResult) -> Self {
        match result {
            CtapUpResult::Denied => UpResult::Denied,
            CtapUpResult::Accepted => UpResult::Accepted,
            CtapUpResult::Timeout => UpResult::Timeout,
        }
    }
}

/// User verification result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvResult {
    Denied,
    Accepted,
    AcceptedWithUp,
    Timeout,
}

impl From<UvResult> for CtapUvResult {
    fn from(result: UvResult) -> Self {
        match result {
            UvResult::Denied => CtapUvResult::Denied,
            UvResult::Accepted => CtapUvResult::Accepted,
            UvResult::AcceptedWithUp => CtapUvResult::AcceptedWithUp,
            UvResult::Timeout => CtapUvResult::Timeout,
        }
    }
}

impl From<CtapUvResult> for UvResult {
    fn from(result: CtapUvResult) -> Self {
        match result {
            CtapUvResult::Denied => UvResult::Denied,
            CtapUvResult::Accepted => UvResult::Accepted,
            CtapUvResult::AcceptedWithUp => UvResult::AcceptedWithUp,
            CtapUvResult::Timeout => UvResult::Timeout,
        }
    }
}

/// Trait for handling authenticator callbacks
///
/// Implement this trait to provide custom user interaction and credential storage logic.
///
/// # Example
///
/// ```no_run
/// use soft_fido2::{AuthenticatorCallbacks, UpResult, UvResult, Credential, CredentialRef};
/// use std::collections::HashMap;
///
/// struct MyCallbacks {
///     store: HashMap<Vec<u8>, Credential>,
/// }
///
/// impl AuthenticatorCallbacks for MyCallbacks {
///     fn request_up(&self, _info: &str, _user: Option<&str>, _rp: &str) -> soft_fido2::Result<UpResult> {
///         Ok(UpResult::Accepted)
///     }
///
///     fn request_uv(&self, _info: &str, _user: Option<&str>, _rp: &str) -> soft_fido2::Result<UvResult> {
///         Ok(UvResult::Accepted)
///     }
///
///     fn write_credential(&self, cred_id: &[u8], _rp_id: &str, cred: &CredentialRef) -> soft_fido2::Result<()> {
///         // Store credential
///         Ok(())
///     }
///
///     fn read_credential(&self, cred_id: &[u8], _rp_id: &str) -> soft_fido2::Result<Option<Credential>> {
///         // Retrieve credential
///         Ok(None)
///     }
///
///     fn delete_credential(&self, cred_id: &[u8]) -> soft_fido2::Result<()> {
///         // Delete credential
///         Ok(())
///     }
///
///     fn list_credentials(&self, rp_id: &str, _user_id: Option<&[u8]>) -> soft_fido2::Result<Vec<Credential>> {
///         // List credentials for RP
///         Ok(vec![])
///     }
/// }
/// ```
pub trait AuthenticatorCallbacks: Send + Sync {
    /// Request user presence (e.g., tap security key, press button)
    ///
    /// # Arguments
    ///
    /// * `info` - Information about the request
    /// * `user_name` - Optional user name
    /// * `rp_id` - Relying party identifier
    fn request_up(&self, info: &str, user_name: Option<&str>, rp_id: &str) -> Result<UpResult>;

    /// Request user verification (e.g., PIN, biometric, password)
    ///
    /// # Arguments
    ///
    /// * `info` - Information about the request
    /// * `user_name` - Optional user name
    /// * `rp_id` - Relying party identifier
    fn request_uv(&self, info: &str, user_name: Option<&str>, rp_id: &str) -> Result<UvResult>;

    /// Store a credential
    ///
    /// # Arguments
    ///
    /// * `cred_id` - Credential ID (binary data)
    /// * `rp_id` - Relying party identifier
    /// * `credential` - Credential data to store
    fn write_credential(
        &self,
        cred_id: &[u8],
        rp_id: &str,
        credential: &CredentialRef,
    ) -> Result<()>;

    /// Read a specific credential
    ///
    /// # Arguments
    ///
    /// * `cred_id` - Credential ID (binary data)
    /// * `rp_id` - Relying party identifier
    ///
    /// # Returns
    ///
    /// The credential if found, None otherwise
    fn read_credential(&self, cred_id: &[u8], rp_id: &str) -> Result<Option<Credential>>;

    /// Delete a credential
    ///
    /// # Arguments
    ///
    /// * `cred_id` - Credential ID (binary data)
    fn delete_credential(&self, cred_id: &[u8]) -> Result<()>;

    /// List all credentials for a relying party
    ///
    /// # Arguments
    ///
    /// * `rp_id` - Relying party identifier
    /// * `user_id` - Optional user ID to filter by
    ///
    /// # Returns
    ///
    /// Vector of credentials matching the filter criteria
    fn list_credentials(&self, rp_id: &str, user_id: Option<&[u8]>) -> Result<Vec<Credential>>;

    /// Select which credential to use from multiple matches
    ///
    /// Default implementation returns the first credential (index 0).
    ///
    /// # Arguments
    ///
    /// * `rp_id` - Relying party identifier
    /// * `credentials` - Available credentials to choose from
    ///
    /// # Returns
    ///
    /// Index of the selected credential
    fn select_credential(&self, _rp_id: &str, _credentials: &[Credential]) -> Result<usize> {
        Ok(0) // Default: select first credential
    }
}

/// Callback adapter that implements soft-fido2-ctap traits
struct CallbackAdapter<C: AuthenticatorCallbacks> {
    callbacks: Arc<C>,
}

impl<C: AuthenticatorCallbacks> UserInteractionCallbacks for CallbackAdapter<C> {
    fn request_up(
        &self,
        info: &str,
        user_name: Option<&str>,
        rp_id: &str,
    ) -> soft_fido2_ctap::Result<CtapUpResult> {
        let result = self
            .callbacks
            .request_up(info, user_name, rp_id)
            .map_err(|_| StatusCode::Other)?;
        Ok(result.into())
    }

    fn request_uv(
        &self,
        info: &str,
        user_name: Option<&str>,
        rp_id: &str,
    ) -> soft_fido2_ctap::Result<CtapUvResult> {
        let result = self
            .callbacks
            .request_uv(info, user_name, rp_id)
            .map_err(|_| StatusCode::Other)?;
        Ok(result.into())
    }

    fn select_credential(
        &self,
        rp_id: &str,
        _user_names: &[String],
    ) -> soft_fido2_ctap::Result<usize> {
        // Note: We don't use user_names from CTAP layer since we use credential-based selection
        // Get credentials for this RP and let the trait implementation choose
        let credentials = self
            .callbacks
            .list_credentials(rp_id, None)
            .map_err(|_| StatusCode::Other)?;

        self.callbacks
            .select_credential(rp_id, &credentials)
            .map_err(|_| StatusCode::Other)
    }
}

impl<C: AuthenticatorCallbacks> CredentialStorageCallbacks for CallbackAdapter<C> {
    fn write_credential(&self, credential: &CtapCredential) -> soft_fido2_ctap::Result<()> {
        // Convert CTAP credential to CredentialRef
        let cred_ref = CredentialRef {
            id: &credential.id,
            rp_id: &credential.rp_id,
            rp_name: credential.rp_name.as_deref(),
            user_id: &credential.user_id,
            user_name: credential.user_name.as_deref(),
            user_display_name: credential.user_display_name.as_deref(),
            sign_count: credential.sign_count,
            alg: credential.algorithm,
            private_key: &credential.private_key,
            created: credential.created,
            discoverable: credential.discoverable,
            cred_protect: Some(credential.cred_protect),
        };

        self.callbacks
            .write_credential(&credential.id, &credential.rp_id, &cred_ref)
            .map_err(|_| StatusCode::Other)
    }

    fn delete_credential(&self, credential_id: &[u8]) -> soft_fido2_ctap::Result<()> {
        self.callbacks
            .delete_credential(credential_id)
            .map_err(|_| StatusCode::Other)
    }

    fn read_credentials(
        &self,
        rp_id: &str,
        user_id: Option<&[u8]>,
    ) -> soft_fido2_ctap::Result<Vec<CtapCredential>> {
        let credentials = self
            .callbacks
            .list_credentials(rp_id, user_id)
            .map_err(|_| StatusCode::NoCredentials)?;
        Ok(credentials.into_iter().map(|c| c.into()).collect())
    }

    fn credential_exists(&self, credential_id: &[u8]) -> soft_fido2_ctap::Result<bool> {
        // Try to read the credential with a placeholder RP ID
        // Note: This is a limitation of the current design
        match self.callbacks.read_credential(credential_id, "") {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    fn get_credential(&self, credential_id: &[u8]) -> soft_fido2_ctap::Result<CtapCredential> {
        // Try to read the credential with a placeholder RP ID
        // Note: This is a limitation of the current design
        let cred = self
            .callbacks
            .read_credential(credential_id, "")
            .map_err(|_| StatusCode::NoCredentials)?
            .ok_or(StatusCode::NoCredentials)?;
        Ok(cred.into())
    }

    fn update_credential(&self, credential: &CtapCredential) -> soft_fido2_ctap::Result<()> {
        // Update is same as write for our purposes
        self.write_credential(credential)
    }

    fn enumerate_rps(&self) -> soft_fido2_ctap::Result<Vec<(String, Option<String>, usize)>> {
        // Not directly supported in callback model
        Ok(vec![])
    }

    fn credential_count(&self) -> soft_fido2_ctap::Result<usize> {
        // Not directly supported in callback model
        Ok(0)
    }
}

// Note: CallbackAdapter automatically implements AuthenticatorCallbacks
// because there's a blanket impl in soft-fido2-ctap for any type that implements
// both UserInteractionCallbacks and CredentialStorageCallbacks

/// Authenticator configuration
#[derive(Debug, Clone)]
pub struct AuthenticatorConfig {
    pub aaguid: [u8; 16],
    pub commands: Vec<crate::ctap::CtapCommand>,
    pub options: Option<crate::options::AuthenticatorOptions>,
    pub max_credentials: usize,
    pub extensions: Vec<String>,
    pub force_resident_keys: bool,
    pub firmware_version: Option<u32>,
}

impl Default for AuthenticatorConfig {
    fn default() -> Self {
        Self {
            aaguid: [0u8; 16],
            commands: crate::ctap::CtapCommand::default_commands(),
            options: None,
            max_credentials: 100,
            extensions: vec![],
            force_resident_keys: true, // Default to true for testing use cases
            firmware_version: None,
        }
    }
}

impl AuthenticatorConfig {
    pub fn builder() -> AuthenticatorConfigBuilder {
        AuthenticatorConfigBuilder::default()
    }
}

/// Builder for AuthenticatorConfig
pub struct AuthenticatorConfigBuilder {
    aaguid: [u8; 16],
    commands: Vec<crate::ctap::CtapCommand>,
    options: Option<crate::options::AuthenticatorOptions>,
    max_credentials: usize,
    extensions: Vec<String>,
    force_resident_keys: bool,
    firmware_version: Option<u32>,
}

impl Default for AuthenticatorConfigBuilder {
    fn default() -> Self {
        Self {
            aaguid: [0u8; 16],
            commands: vec![],
            options: None,
            max_credentials: 0,
            extensions: vec![],
            force_resident_keys: true, // Default to true for testing use cases
            firmware_version: None,
        }
    }
}

impl AuthenticatorConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn aaguid(mut self, aaguid: [u8; 16]) -> Self {
        self.aaguid = aaguid;
        self
    }

    pub fn commands(mut self, commands: Vec<crate::ctap::CtapCommand>) -> Self {
        self.commands = commands;
        self
    }

    pub fn options(mut self, options: crate::options::AuthenticatorOptions) -> Self {
        self.options = Some(options);
        self
    }

    pub fn max_credentials(mut self, max: usize) -> Self {
        self.max_credentials = max;
        self
    }

    pub fn extensions(mut self, extensions: Vec<String>) -> Self {
        self.extensions = extensions;
        self
    }

    pub fn force_resident_keys(mut self, force: bool) -> Self {
        self.force_resident_keys = force;
        self
    }

    pub fn firmware_version(mut self, version: u32) -> Self {
        self.firmware_version = Some(version);
        self
    }

    pub fn build(self) -> AuthenticatorConfig {
        AuthenticatorConfig {
            aaguid: self.aaguid,
            commands: if self.commands.is_empty() {
                crate::ctap::CtapCommand::default_commands()
            } else {
                self.commands
            },
            options: self.options,
            max_credentials: if self.max_credentials == 0 {
                100
            } else {
                self.max_credentials
            },
            extensions: self.extensions,
            force_resident_keys: self.force_resident_keys,
            firmware_version: self.firmware_version,
        }
    }
}

/// High-level FIDO2 authenticator
///
/// Provides a thread-safe authenticator that processes CTAP commands via callbacks.
pub struct Authenticator<C: AuthenticatorCallbacks> {
    dispatcher: Arc<Mutex<CommandDispatcher<CallbackAdapter<C>>>>,
}

impl<C: AuthenticatorCallbacks> Authenticator<C> {
    /// Set the PIN hash for the authenticator (must be called before creating instance)
    ///
    /// The PIN hash will be applied to the next authenticator instance created.
    /// This is useful for testing scenarios where you want to simulate a PIN being set.
    ///
    /// # Arguments
    ///
    /// * `pin_hash` - SHA-256 hash of the PIN (32 bytes)
    #[cfg(feature = "std")]
    pub fn set_pin_hash(pin_hash: &[u8]) {
        if pin_hash.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(pin_hash);

            let lock = PRESET_PIN_HASH.get_or_init(|| Mutex::new(None));
            if let Ok(mut guard) = lock.lock() {
                *guard = Some(hash);
            }
        }
    }

    /// Set the PIN hash for the authenticator (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn set_pin_hash(pin_hash: &[u8]) {
        if pin_hash.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(pin_hash);
            *PRESET_PIN_HASH.lock() = Some(hash);
        }
    }

    /// Create a new authenticator with default configuration
    pub fn new(callbacks: C) -> Result<Self>
    where
        C: 'static,
    {
        Self::with_config(callbacks, AuthenticatorConfig::default())
    }

    /// Create a new authenticator with custom configuration
    pub fn with_config(callbacks: C, config: AuthenticatorConfig) -> Result<Self>
    where
        C: 'static,
    {
        let adapter = CallbackAdapter {
            callbacks: Arc::new(callbacks),
        };

        // Create CTAP authenticator config
        let mut ctap_config = CtapConfig::new()
            .with_aaguid(config.aaguid)
            .with_max_credentials(config.max_credentials)
            .with_extensions(config.extensions)
            .with_force_resident_keys(config.force_resident_keys);

        if let Some(fw_version) = config.firmware_version {
            ctap_config = ctap_config.with_firmware_version(fw_version);
        }

        // Convert and apply high-level options to CTAP options
        if let Some(ref hl_options) = config.options {
            let ctap_options = soft_fido2_ctap::authenticator::AuthenticatorOptions {
                plat: hl_options.plat,
                rk: hl_options.rk,
                client_pin: hl_options.client_pin,
                up: hl_options.up,
                uv: hl_options.uv,
                always_uv: hl_options.always_uv.unwrap_or(false),
                cred_mgmt: hl_options.cred_mgmt.unwrap_or(true),
                authnr_cfg: false,
                bio_enroll: hl_options.bio_enroll,
                ep: hl_options.ep,
                large_blobs: hl_options.large_blobs,
                pin_uv_auth_token: hl_options.pin_uv_auth_token.unwrap_or(true),
                set_min_pin_length: false,
                make_cred_uv_not_required: hl_options.make_cred_uv_not_required.unwrap_or(false),
            };
            ctap_config = ctap_config.with_options(ctap_options);
        }

        let mut authenticator = CtapAuthenticator::new(ctap_config, adapter);

        // Apply preset PIN hash if available (std version)
        #[cfg(feature = "std")]
        if let Some(lock) = PRESET_PIN_HASH.get()
            && let Ok(mut guard) = lock.lock()
            && let Some(pin_hash) = guard.take()
        {
            authenticator.set_pin_hash_for_testing(pin_hash);
        }

        // Apply preset PIN hash if available (no_std version)
        #[cfg(not(feature = "std"))]
        {
            let mut guard = PRESET_PIN_HASH.lock();
            if let Some(pin_hash) = guard.take() {
                authenticator.set_pin_hash_for_testing(pin_hash);
            }
        }

        let dispatcher = CommandDispatcher::new(authenticator);

        Ok(Self {
            dispatcher: Arc::new(Mutex::new(dispatcher)),
        })
    }

    /// Handle a CTAP request
    ///
    /// # Arguments
    ///
    /// * `request` - CTAP command bytes (command code + CBOR parameters)
    /// * `response` - Buffer for response (will be resized as needed)
    ///
    /// # Returns
    ///
    /// Number of bytes written to response buffer
    pub fn handle(&mut self, request: &[u8], response: &mut Vec<u8>) -> Result<usize> {
        let mut dispatcher = self.dispatcher.lock().map_err(|_| Error::Other)?;

        // Dispatch command
        match dispatcher.dispatch(request) {
            Ok(response_data) => {
                // CTAP success response: [0x00 status] [CBOR data...]
                response.clear();
                response.push(0x00); // Success status byte
                response.extend_from_slice(&response_data);
                Ok(response.len())
            }
            Err(status_code) => {
                // CTAP error response: [error status byte] (no CBOR data)
                *response = vec![status_code as u8];
                Ok(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple test implementation of AuthenticatorCallbacks
    struct TestCallbacks;

    impl AuthenticatorCallbacks for TestCallbacks {
        fn request_up(&self, _: &str, _: Option<&str>, _: &str) -> Result<UpResult> {
            Ok(UpResult::Accepted)
        }

        fn request_uv(&self, _: &str, _: Option<&str>, _: &str) -> Result<UvResult> {
            Ok(UvResult::Accepted)
        }

        fn write_credential(&self, _: &[u8], _: &str, _: &CredentialRef) -> Result<()> {
            Ok(())
        }

        fn read_credential(&self, _: &[u8], _: &str) -> Result<Option<Credential>> {
            Ok(None)
        }

        fn delete_credential(&self, _: &[u8]) -> Result<()> {
            Ok(())
        }

        fn list_credentials(&self, _: &str, _: Option<&[u8]>) -> Result<Vec<Credential>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_authenticator_creation() {
        let callbacks = TestCallbacks;
        let config = AuthenticatorConfig::default();
        let result = Authenticator::with_config(callbacks, config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_builder() {
        let config = AuthenticatorConfig::builder()
            .aaguid([1u8; 16])
            .max_credentials(50)
            .build();

        assert_eq!(config.aaguid, [1u8; 16]);
        assert_eq!(config.max_credentials, 50);
    }
}
