//! CTAP Authenticator state machine
//!
//! This module implements the core authenticator logic including configuration,
//! PIN management, and overall state coordination.

use crate::{
    CoseAlgorithm, SecBytes, StatusCode,
    callbacks::AuthenticatorCallbacks,
    cbor::MAX_CTAP_MESSAGE_SIZE,
    pin_token::{Permission, PinToken, PinTokenManager},
};

use soft_fido2_crypto::pin_protocol::{self, v2};

use zeroize::Zeroizing;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Maximum PIN retries before blocking
const MAX_PIN_RETRIES: u8 = 8;

/// Maximum UV retries before blocking
const MAX_UV_RETRIES: u8 = 3;

/// Type alias for custom command handlers
type CustomCommandHandler = Box<dyn Fn(&[u8]) -> Result<Vec<u8>, StatusCode> + Send + Sync>;

/// Authenticator configuration
///
/// Defines the capabilities and settings of a FIDO2 authenticator.
#[derive(Debug, Clone)]
pub struct AuthenticatorConfig {
    /// Authenticator Attestation GUID (16 bytes)
    ///
    /// Unique identifier for the authenticator model.
    pub aaguid: [u8; 16],

    /// Supported COSE algorithms
    pub algorithms: Vec<i32>,

    /// Authenticator options
    pub options: AuthenticatorOptions,

    /// Maximum number of credentials
    pub max_credentials: usize,

    /// Supported extensions
    pub extensions: Vec<String>,

    /// Firmware version
    pub firmware_version: Option<u32>,

    /// Maximum message size
    pub max_msg_size: Option<usize>,

    /// Supported PIN/UV auth protocols (1 = V1, 2 = V2)
    pub pin_uv_auth_protocols: Vec<u8>,

    /// Maximum credential ID length
    pub max_credential_id_length: Option<usize>,

    /// Transports supported
    pub transports: Vec<String>,

    /// Maximum credential blob length
    pub max_cred_blob_length: Option<usize>,

    /// Minimum PIN length
    pub min_pin_length: Option<usize>,

    /// Credential wrapping key for non-resident credentials
    ///
    /// Used to encrypt private keys into credential IDs when rk=false.
    /// If None, a random key will be generated at runtime.
    pub credential_wrapping_key: Option<[u8; 32]>,

    /// Force all credentials to be resident keys (for testing)
    ///
    /// When true, all credentials are stored regardless of the rk option
    /// in makeCredential requests. This is useful for testing without a
    /// proper client that saves credential IDs.
    ///
    /// Default: true (optimized for testing/virtual authenticator use cases)
    pub force_resident_keys: bool,

    /// Use constant signature counter (for privacy)
    ///
    /// When true, the signature counter will not increment and remain at 0.
    /// This enhances privacy by preventing cross-site tracking via counter correlation.
    /// Some authenticators use this mode to avoid leaking usage patterns.
    ///
    /// Default: false (counter increments normally)
    pub constant_sign_count: bool,
}

impl AuthenticatorConfig {
    /// Create a new authenticator configuration with defaults
    pub fn new() -> Self {
        Self {
            aaguid: [0u8; 16],
            algorithms: vec![CoseAlgorithm::ES256.to_i32()],
            options: AuthenticatorOptions::default(),
            max_credentials: 100,
            extensions: vec![],
            firmware_version: None,
            max_msg_size: Some(MAX_CTAP_MESSAGE_SIZE), // CTAP max message size
            pin_uv_auth_protocols: vec![2],            // Only V2 (V1 is associated with U2F)
            max_credential_id_length: Some(128),
            transports: vec!["usb".to_string()], // Only USB (NFC might trigger U2F probing)
            max_cred_blob_length: Some(32),
            min_pin_length: Some(4),       // CTAP default minimum PIN length
            credential_wrapping_key: None, // Will be generated if needed
            force_resident_keys: true,     // Default to true for testing use cases
            constant_sign_count: false,    // Default: counter increments normally
        }
    }

    /// Set AAGUID
    pub fn with_aaguid(mut self, aaguid: [u8; 16]) -> Self {
        self.aaguid = aaguid;
        self
    }

    /// Set supported algorithms
    pub fn with_algorithms(mut self, algorithms: Vec<i32>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Set authenticator options
    pub fn with_options(mut self, options: AuthenticatorOptions) -> Self {
        self.options = options;
        self
    }

    /// Set maximum credentials
    pub fn with_max_credentials(mut self, max: usize) -> Self {
        self.max_credentials = max;
        self
    }

    /// Add extension
    pub fn with_extension(mut self, ext: String) -> Self {
        self.extensions.push(ext);
        self
    }

    /// Set extensions
    pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Set firmware version
    pub fn with_firmware_version(mut self, version: u32) -> Self {
        self.firmware_version = Some(version);
        self
    }

    /// Force all credentials to be resident keys (for testing)
    pub fn with_force_resident_keys(mut self, force: bool) -> Self {
        self.force_resident_keys = force;
        self
    }

    /// Use constant signature counter (for privacy)
    ///
    /// When enabled, the signature counter will not increment and remain at 0.
    /// This enhances privacy by preventing cross-site tracking via counter correlation.
    pub fn with_constant_sign_count(mut self, constant: bool) -> Self {
        self.constant_sign_count = constant;
        self
    }

    /// Set maximum message size
    pub fn with_max_msg_size(mut self, size: usize) -> Self {
        assert!(
            size >= 1024,
            "maxMsgSize must be at least 1024 bytes per CTAP spec"
        );
        assert!(
            size <= MAX_CTAP_MESSAGE_SIZE,
            "maxMsgSize cannot exceed 7609 bytes (CTAP HID limit)"
        );
        self.max_msg_size = Some(size);
        self
    }
}

impl Default for AuthenticatorConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Authenticator options
///
/// Boolean capabilities of the authenticator.
#[derive(Debug, Clone, Default)]
pub struct AuthenticatorOptions {
    /// Platform device (vs roaming authenticator)
    pub plat: bool,

    /// Resident key (discoverable credential) support
    pub rk: bool,

    /// Client PIN supported
    pub client_pin: Option<bool>,

    /// User presence supported
    pub up: bool,

    /// User verification supported
    pub uv: Option<bool>,

    /// Always require user verification
    pub always_uv: bool,

    /// Credential management supported
    pub cred_mgmt: bool,

    /// Authenticator configuration supported
    pub authnr_cfg: bool,

    /// Bio enrollment supported
    pub bio_enroll: Option<bool>,

    /// Enterprise attestation supported
    pub ep: Option<bool>,

    /// Large blobs supported
    pub large_blobs: Option<bool>,

    /// PIN/UV auth token supported
    pub pin_uv_auth_token: bool,

    /// Set minimum PIN length supported
    pub set_min_pin_length: bool,

    /// Make credential with UV optional supported
    pub make_cred_uv_not_rqd: bool,
}

impl AuthenticatorOptions {
    /// Create new options with common defaults
    pub fn new() -> Self {
        Self {
            plat: false,
            rk: true,
            client_pin: Some(true),
            up: true,
            uv: Some(true),
            always_uv: false,
            cred_mgmt: true,
            authnr_cfg: false,
            bio_enroll: Some(false),
            ep: None,
            large_blobs: None,
            pin_uv_auth_token: false,
            set_min_pin_length: false,
            make_cred_uv_not_rqd: false,
        }
    }
}

/// Authenticator state machine
///
/// Central component managing authenticator configuration, PIN state,
/// and command processing.
pub struct Authenticator<C: AuthenticatorCallbacks> {
    /// Authenticator configuration
    config: AuthenticatorConfig,

    /// Callbacks for user interaction and storage
    callbacks: Arc<C>,

    /// PIN hash (SHA-256 of PIN, if set)
    pin_hash: Option<[u8; 32]>,

    /// PIN retry counter
    pin_retries: u8,

    /// PIN token manager
    pin_tokens: PinTokenManager,

    /// Force change PIN flag
    force_change_pin: bool,

    /// Minimum PIN length (4-63)
    min_pin_length: usize,

    /// User verification retry counter
    uv_retries: u8,

    /// Custom command handlers (command code -> handler)
    custom_commands: BTreeMap<u8, CustomCommandHandler>,

    /// Ephemeral ECDH keypair for PIN protocol (protocol version -> keypair)
    /// This is used for key agreement in PIN operations
    pin_protocol_keypairs: BTreeMap<u8, soft_fido2_crypto::ecdh::KeyPair>,

    /// Credential wrapping key for non-resident credentials
    /// Generated at runtime if not provided in config
    credential_wrapping_key: [u8; 32],

    /// RP enumeration state (for enumerateRPsBegin/GetNext)
    /// Format: Vec<(rp_id, rp_name, credential_count)>
    rp_enumeration_state: Option<Vec<(String, Option<String>, usize)>>,

    /// Current index in RP enumeration
    rp_enumeration_index: usize,

    /// Credential enumeration state (for enumerateCredentialsBegin/GetNext)
    credential_enumeration_state: Option<Vec<crate::types::Credential>>,

    /// Current index in credential enumeration
    credential_enumeration_index: usize,
}

impl<C: AuthenticatorCallbacks> Authenticator<C> {
    /// Create a new authenticator with configuration and callbacks
    ///
    /// # Arguments
    ///
    /// * `config` - Authenticator configuration
    /// * `callbacks` - User interaction and storage callbacks
    pub fn new(config: AuthenticatorConfig, callbacks: C) -> Self {
        // Generate or use provided wrapping key
        let credential_wrapping_key = config.credential_wrapping_key.unwrap_or_else(|| {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            key
        });

        Self {
            config,
            callbacks: Arc::new(callbacks),
            pin_hash: None,
            pin_retries: MAX_PIN_RETRIES,
            pin_tokens: PinTokenManager::new(),
            force_change_pin: false,
            min_pin_length: 4, // Default minimum PIN length
            uv_retries: MAX_UV_RETRIES,
            custom_commands: BTreeMap::new(),
            pin_protocol_keypairs: BTreeMap::new(),
            credential_wrapping_key,
            rp_enumeration_state: None,
            rp_enumeration_index: 0,
            credential_enumeration_state: None,
            credential_enumeration_index: 0,
        }
    }

    /// Get authenticator configuration
    pub fn config(&self) -> &AuthenticatorConfig {
        &self.config
    }

    /// Get callbacks reference
    pub fn callbacks(&self) -> &C {
        &self.callbacks
    }

    /// Check if PIN is set
    pub fn is_pin_set(&self) -> bool {
        self.pin_hash.is_some()
    }

    /// Get PIN retry counter
    pub fn pin_retries(&self) -> u8 {
        self.pin_retries
    }

    /// Check if PIN is blocked
    pub fn is_pin_blocked(&self) -> bool {
        self.pin_retries == 0
    }

    /// Set PIN
    ///
    /// # Arguments
    ///
    /// * `new_pin` - New PIN (UTF-8 string, 4-63 bytes)
    ///
    /// # Returns
    ///
    /// Success or error status
    pub fn set_pin(&mut self, new_pin: &str) -> Result<(), StatusCode> {
        // Validate PIN length
        let pin_bytes = new_pin.as_bytes();
        if pin_bytes.len() < self.min_pin_length || pin_bytes.len() > 63 {
            return Err(StatusCode::PinPolicyViolation);
        }

        // Hash the PIN (according to CTAP spec, store SHA-256 of raw PIN, not padded)
        let hash = Sha256::digest(pin_bytes);
        self.pin_hash = Some(hash.into());

        // Reset retry counter
        self.pin_retries = MAX_PIN_RETRIES;
        self.force_change_pin = false;

        Ok(())
    }

    /// Change PIN
    ///
    /// # Arguments
    ///
    /// * `current_pin` - Current PIN
    /// * `new_pin` - New PIN
    ///
    /// # Returns
    ///
    /// Success or error status
    pub fn change_pin(&mut self, current_pin: &str, new_pin: &str) -> Result<(), StatusCode> {
        // Verify current PIN first
        self.verify_pin(current_pin)?;

        // Set new PIN
        self.set_pin(new_pin)
    }

    /// Verify PIN
    ///
    /// # Arguments
    ///
    /// * `pin` - PIN to verify
    ///
    /// # Returns
    ///
    /// Success or error status
    pub fn verify_pin(&mut self, pin: &str) -> Result<(), StatusCode> {
        // Check if PIN is set
        let pin_hash = self.pin_hash.ok_or(StatusCode::PinNotSet)?;

        // Check if blocked
        if self.is_pin_blocked() {
            return Err(StatusCode::PinBlocked);
        }

        // Hash the provided PIN (raw PIN, not padded, per CTAP spec)
        let pin_bytes = pin.as_bytes();
        let hash = Sha256::digest(pin_bytes);

        // Compare using constant-time comparison
        if pin_hash.ct_eq(&hash[..]).into() {
            // PIN correct - reset retry counter
            self.pin_retries = MAX_PIN_RETRIES;
            Ok(())
        } else {
            // PIN incorrect - decrement retry counter
            self.pin_retries = self.pin_retries.saturating_sub(1);
            if self.is_pin_blocked() {
                Err(StatusCode::PinBlocked)
            } else {
                Err(StatusCode::PinInvalid)
            }
        }
    }

    /// Get stored PIN hash (for PIN protocol operations)
    ///
    /// Returns the full 32-byte SHA-256 hash of the PIN, if set.
    pub(crate) fn pin_hash(&self) -> Option<[u8; 32]> {
        self.pin_hash
    }

    /// Set PIN hash directly for testing purposes
    ///
    /// This bypasses normal PIN validation and should only be used in tests.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte PIN hash to set
    pub fn set_pin_hash_for_testing(&mut self, hash: [u8; 32]) {
        self.pin_hash = Some(hash);
        self.pin_retries = MAX_PIN_RETRIES;
    }

    /// Decrement PIN retry counter (for failed PIN attempts)
    pub(crate) fn decrement_pin_retries(&mut self) {
        self.pin_retries = self.pin_retries.saturating_sub(1);
    }

    /// Get PIN token with permissions
    ///
    /// # Arguments
    ///
    /// * `pin` - PIN for verification
    /// * `permissions` - Requested permission bitmask
    /// * `rp_id` - RP ID for scoped permissions
    ///
    /// # Returns
    ///
    /// PIN token value (32 bytes) or error
    pub fn get_pin_token(
        &mut self,
        pin: &str,
        permissions: u8,
        rp_id: Option<String>,
    ) -> Result<[u8; 32], StatusCode> {
        // Verify PIN
        self.verify_pin(pin)?;

        self.get_pin_token_after_verification(permissions, rp_id)
    }

    /// Get PIN token with permissions (without PIN verification)
    ///
    /// This should only be called after PIN has already been verified
    /// (e.g., via encrypted PIN hash in CTAP command).
    ///
    /// # Arguments
    ///
    /// * `permissions` - Requested permission bitmask
    /// * `rp_id` - RP ID for scoped permissions
    ///
    /// # Returns
    ///
    /// PIN token value (32 bytes) or error
    pub fn get_pin_token_after_verification(
        &mut self,
        permissions: u8,
        rp_id: Option<String>,
    ) -> Result<[u8; 32], StatusCode> {
        // Generate random token
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);

        // Create and store token
        let token = PinToken::new(token_bytes, permissions, rp_id);
        let value = *token.value();
        self.pin_tokens.set_token(token);

        Ok(value)
    }

    /// Verify PIN/UV auth token has required permission
    ///
    /// # Arguments
    ///
    /// * `permission` - Required permission
    /// * `rp_id` - RP ID for the operation
    ///
    /// # Returns
    ///
    /// Success or error status
    pub fn verify_pin_uv_auth_token(
        &mut self,
        permission: Permission,
        rp_id: Option<&str>,
    ) -> Result<(), StatusCode> {
        self.pin_tokens.verify_permission(permission, rp_id)
    }

    /// Verify PIN/UV auth parameter
    ///
    /// # Arguments
    ///
    /// * `pin_uv_auth_protocol` - Protocol version (1 or 2)
    /// * `pin_uv_auth_param` - Authentication parameter (16 bytes)
    /// * `client_data_hash` - Client data hash to verify
    ///
    /// # Returns
    ///
    /// Success or error status
    pub fn verify_pin_uv_auth_param(
        &self,
        pin_uv_auth_protocol: u8,
        pin_uv_auth_param: &[u8],
        client_data_hash: &[u8],
    ) -> Result<(), StatusCode> {
        // Get current PIN token
        let token = self.pin_tokens.get_token().ok_or(StatusCode::PinRequired)?;

        // Verify based on protocol version
        // Protocol v1 uses 16-byte HMAC, v2 uses 32-byte HMAC
        let valid = match pin_uv_auth_protocol {
            1 => {
                if pin_uv_auth_param.len() != 16 {
                    return Err(StatusCode::PinAuthInvalid);
                }
                let expected: [u8; 16] = pin_uv_auth_param
                    .try_into()
                    .map_err(|_| StatusCode::PinAuthInvalid)?;
                pin_protocol::v1::verify(token.value(), client_data_hash, &expected)
            }
            2 => {
                if pin_uv_auth_param.len() != 32 {
                    return Err(StatusCode::PinAuthInvalid);
                }
                let expected: [u8; 32] = pin_uv_auth_param
                    .try_into()
                    .map_err(|_| StatusCode::PinAuthInvalid)?;
                pin_protocol::v2::verify(token.value(), client_data_hash, &expected)
            }
            _ => {
                return Err(StatusCode::InvalidParameter);
            }
        };

        if valid {
            Ok(())
        } else {
            Err(StatusCode::PinAuthInvalid)
        }
    }

    /// Get minimum PIN length
    pub fn min_pin_length(&self) -> usize {
        self.min_pin_length
    }

    /// Set minimum PIN length (4-63)
    pub fn set_min_pin_length(&mut self, length: usize) -> Result<(), StatusCode> {
        if !(4..=63).contains(&length) {
            return Err(StatusCode::PinPolicyViolation);
        }
        self.min_pin_length = length;
        Ok(())
    }

    /// Clear PIN/UV auth token permissions except large blob write
    ///
    /// Per FIDO2 spec section 6.1.2 step 14.3, after makeCredential or getAssertion
    /// completes, all permissions except lbw should be cleared.
    pub fn clear_pin_uv_auth_token_permissions_except_lbw(&mut self) {
        self.pin_tokens.clear_permissions_except_lbw();
    }

    /// Start RP enumeration and return the first RP
    ///
    /// Returns (rp_id, rp_name, total_rps)
    // TODO: simplify return type
    #[allow(clippy::type_complexity)]
    pub fn start_rp_enumeration(
        &mut self,
    ) -> Result<((String, Option<String>, usize), usize), StatusCode> {
        let rps = self.callbacks.enumerate_rps()?;
        if rps.is_empty() {
            return Err(StatusCode::NoCredentials);
        }

        let total = rps.len();
        let first_rp = rps[0].clone();
        self.rp_enumeration_state = Some(rps);
        self.rp_enumeration_index = 1; // Next index to return

        Ok((first_rp, total))
    }

    /// Get next RP in enumeration
    ///
    /// Returns (rp_id, rp_name, credential_count)
    pub fn get_next_rp(&mut self) -> Result<(String, Option<String>, usize), StatusCode> {
        let rps = self
            .rp_enumeration_state
            .as_ref()
            .ok_or(StatusCode::NotAllowed)?; // No enumeration in progress

        if self.rp_enumeration_index >= rps.len() {
            // Clear state when enumeration is complete
            self.rp_enumeration_state = None;
            self.rp_enumeration_index = 0;
            return Err(StatusCode::NotAllowed);
        }

        let rp = rps[self.rp_enumeration_index].clone();
        self.rp_enumeration_index += 1;

        Ok(rp)
    }

    /// Start credential enumeration for an RP and return the first credential
    ///
    /// Returns (credential, total_credentials)
    pub fn start_credential_enumeration(
        &mut self,
        rp_id: &str,
    ) -> Result<(crate::types::Credential, usize), StatusCode> {
        let credentials = self.callbacks.read_credentials(rp_id, None)?;
        if credentials.is_empty() {
            return Err(StatusCode::NoCredentials);
        }

        let total = credentials.len();
        let first_cred = credentials[0].clone();
        self.credential_enumeration_state = Some(credentials);
        self.credential_enumeration_index = 1; // Next index to return

        Ok((first_cred, total))
    }

    /// Get next credential in enumeration
    pub fn get_next_credential(&mut self) -> Result<crate::types::Credential, StatusCode> {
        let credentials = self
            .credential_enumeration_state
            .as_ref()
            .ok_or(StatusCode::NotAllowed)?; // No enumeration in progress

        if self.credential_enumeration_index >= credentials.len() {
            // Clear state when enumeration is complete
            self.credential_enumeration_state = None;
            self.credential_enumeration_index = 0;
            return Err(StatusCode::NotAllowed);
        }

        let cred = credentials[self.credential_enumeration_index].clone();
        self.credential_enumeration_index += 1;

        Ok(cred)
    }

    /// Register a custom command handler
    ///
    /// # Arguments
    ///
    /// * `command` - Command code (0x40-0xFF vendor range)
    /// * `handler` - Handler function
    pub fn register_custom_command<F>(&mut self, command: u8, handler: F)
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, StatusCode> + Send + Sync + 'static,
    {
        self.custom_commands.insert(command, Box::new(handler));
    }

    /// Handle custom command
    ///
    /// # Arguments
    ///
    /// * `command` - Command code
    /// * `request` - Request payload
    ///
    /// # Returns
    ///
    /// Response payload or error
    pub fn handle_custom_command(
        &self,
        command: u8,
        request: &[u8],
    ) -> Result<Vec<u8>, StatusCode> {
        match self.custom_commands.get(&command) {
            Some(handler) => handler(request),
            None => Err(StatusCode::InvalidCommand),
        }
    }

    /// Store ephemeral ECDH keypair for PIN protocol
    ///
    /// # Arguments
    ///
    /// * `protocol` - PIN/UV auth protocol version (1 or 2)
    /// * `keypair` - ECDH keypair to store
    pub fn set_pin_protocol_keypair(
        &mut self,
        protocol: u8,
        keypair: soft_fido2_crypto::ecdh::KeyPair,
    ) {
        self.pin_protocol_keypairs.insert(protocol, keypair);
    }

    /// Get stored ECDH keypair for PIN protocol
    ///
    /// # Arguments
    ///
    /// * `protocol` - PIN/UV auth protocol version (1 or 2)
    ///
    /// # Returns
    ///
    /// Reference to stored keypair, or None if not found
    pub fn get_pin_protocol_keypair(
        &self,
        protocol: u8,
    ) -> Option<&soft_fido2_crypto::ecdh::KeyPair> {
        self.pin_protocol_keypairs.get(&protocol)
    }

    /// Clear stored PIN protocol keypairs
    pub fn clear_pin_protocol_keypairs(&mut self) {
        self.pin_protocol_keypairs.clear();
    }

    /// Delete all credentials via callbacks
    ///
    /// This will enumerate all RPs and delete all credentials for each RP.
    pub fn delete_all_credentials(&self) -> Result<(), StatusCode> {
        // Enumerate all RPs to get all credentials
        let rps = self.callbacks.enumerate_rps()?;

        // For each RP, read all credentials and delete them
        for (rp_id, _, _) in rps {
            // Read all credentials for this RP
            let credentials = self.callbacks.read_credentials(&rp_id, None)?;

            // Delete each credential
            for credential in credentials {
                self.callbacks.delete_credential(&credential.id)?;
            }
        }

        Ok(())
    }

    /// Reset authenticator to factory defaults
    ///
    /// This will clear all credentials, reset PIN, and clear tokens.
    pub fn reset(&mut self) -> Result<(), StatusCode> {
        // Clear PIN state
        self.pin_hash = None;
        self.pin_retries = MAX_PIN_RETRIES;
        self.pin_tokens.clear_token();
        self.force_change_pin = false;
        self.min_pin_length = 4;
        self.pin_protocol_keypairs.clear();

        // Delete all credentials via callbacks
        self.delete_all_credentials()?;

        Ok(())
    }

    /// Get remaining discoverable credentials capacity
    ///
    /// Returns the number of additional discoverable credentials that can be stored,
    /// or None if the authenticator doesn't track this information.
    pub fn remaining_discoverable_credentials(&self) -> Option<usize> {
        Some(self.config.max_credentials)
    }

    /// Wrap credential data into a credential ID (for non-resident credentials)
    ///
    /// Encrypts the private key and metadata into the credential ID itself.
    /// This allows non-resident credentials to work without storing them.
    ///
    /// Format: version(1) || IV(16) || encrypted_data || HMAC(16)
    /// Encrypted data contains: private_key(32) || rp_id_len(1) || rp_id || algorithm(4)
    pub fn wrap_credential(
        &self,
        private_key: &[u8],
        rp_id: &str,
        algorithm: i32,
    ) -> Result<Vec<u8>, StatusCode> {
        // Version byte (1 = wrapped credential v1)
        let version: u8 = 1;

        // Build plaintext: private_key || rp_id_len || rp_id || algorithm
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(private_key); // 32 bytes
        plaintext.push(rp_id.len() as u8); // 1 byte
        plaintext.extend_from_slice(rp_id.as_bytes());
        plaintext.extend_from_slice(&algorithm.to_be_bytes()); // 4 bytes

        // Pad to 16-byte boundary for AES-CBC
        while plaintext.len() % 16 != 0 {
            plaintext.push(0);
        }

        // Encrypt using PIN protocol V2 (AES-256-CBC with random IV)
        let encrypted = v2::encrypt(&self.credential_wrapping_key, &plaintext)
            .map_err(|_| StatusCode::Other)?;

        // Build credential ID: version || encrypted_data
        let mut credential_id = Vec::new();
        credential_id.push(version);
        credential_id.extend_from_slice(&encrypted);

        // Add HMAC for integrity
        let hmac = v2::authenticate(&self.credential_wrapping_key, &credential_id);
        credential_id.extend_from_slice(&hmac[..16]); // First 16 bytes of HMAC

        Ok(credential_id)
    }

    /// Unwrap credential data from a credential ID (for non-resident credentials)
    ///
    /// Decrypts and verifies a wrapped credential ID, returning the private key
    /// and metadata if valid.
    ///
    /// Returns: (private_key, rp_id, algorithm)
    pub fn unwrap_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<(SecBytes, String, i32), StatusCode> {
        // Minimum size: version(1) + IV(16) + min_encrypted(16) + HMAC(16) = 49 bytes
        if credential_id.len() < 49 {
            return Err(StatusCode::InvalidParameter);
        }

        // Split: version || encrypted_data || HMAC
        let version = credential_id[0];
        let hmac_start = credential_id.len() - 16;
        let data_with_version = &credential_id[..hmac_start];
        let hmac_received = &credential_id[hmac_start..];

        // Verify version
        if version != 1 {
            return Err(StatusCode::InvalidParameter);
        }

        // Verify HMAC
        let hmac_computed = v2::authenticate(&self.credential_wrapping_key, data_with_version);
        let hmac_valid: bool = hmac_computed[..16].ct_eq(hmac_received).into();
        if !hmac_valid {
            return Err(StatusCode::InvalidParameter);
        }

        // Decrypt with protected buffer
        let encrypted = &credential_id[1..hmac_start];
        let plaintext = Zeroizing::new(
            v2::decrypt(&self.credential_wrapping_key, encrypted)
                .map_err(|_| StatusCode::InvalidParameter)?,
        );

        // Parse plaintext: private_key(32) || rp_id_len(1) || rp_id || algorithm(4)
        if plaintext.len() < 37 {
            return Err(StatusCode::InvalidParameter);
        }

        // Extract into SecBytes immediately
        let private_key = SecBytes::from_slice(&plaintext[0..32]);
        let rp_id_len = plaintext[32] as usize;

        if plaintext.len() < 33 + rp_id_len + 4 {
            return Err(StatusCode::InvalidParameter);
        }

        let rp_id = core::str::from_utf8(&plaintext[33..33 + rp_id_len])
            .map_err(|_| StatusCode::InvalidParameter)?
            .to_string();

        let algorithm = i32::from_be_bytes([
            plaintext[33 + rp_id_len],
            plaintext[34 + rp_id_len],
            plaintext[35 + rp_id_len],
            plaintext[36 + rp_id_len],
        ]);

        // plaintext dropped and zeroed here
        Ok((private_key, rp_id, algorithm))
    }

    /// Get the number of UV retries remaining.
    pub fn uv_retries(&self) -> u8 {
        // TODO: implement UV retry tracking
        self.uv_retries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        UpResult, UvResult,
        callbacks::{CredentialStorageCallbacks, UserInteractionCallbacks},
        types::Credential,
    };

    // Mock callbacks for testing
    struct MockCallbacks;

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
            Ok(0)
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

    fn create_test_authenticator() -> Authenticator<MockCallbacks> {
        let config = AuthenticatorConfig::new();
        Authenticator::new(config, MockCallbacks)
    }

    #[test]
    fn test_authenticator_creation() {
        let auth = create_test_authenticator();
        assert!(!auth.is_pin_set());
        assert_eq!(auth.pin_retries(), MAX_PIN_RETRIES);
        assert!(!auth.is_pin_blocked());
    }

    #[test]
    fn test_set_pin() {
        let mut auth = create_test_authenticator();
        assert!(auth.set_pin("1234").is_ok());
        assert!(auth.is_pin_set());
    }

    #[test]
    fn test_pin_too_short() {
        let mut auth = create_test_authenticator();
        let result = auth.set_pin("123");
        assert_eq!(result, Err(StatusCode::PinPolicyViolation));
    }

    #[test]
    fn test_pin_too_long() {
        let mut auth = create_test_authenticator();
        let long_pin = "a".repeat(64);
        let result = auth.set_pin(&long_pin);
        assert_eq!(result, Err(StatusCode::PinPolicyViolation));
    }

    #[test]
    fn test_verify_pin_success() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();
        assert!(auth.verify_pin("1234").is_ok());
        assert_eq!(auth.pin_retries(), MAX_PIN_RETRIES);
    }

    #[test]
    fn test_verify_pin_incorrect() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();
        let result = auth.verify_pin("wrong");
        assert_eq!(result, Err(StatusCode::PinInvalid));
        assert_eq!(auth.pin_retries(), MAX_PIN_RETRIES - 1);
    }

    #[test]
    fn test_pin_retry_exhaustion() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();

        // Exhaust retries
        for _ in 0..MAX_PIN_RETRIES {
            let _ = auth.verify_pin("wrong");
        }

        assert!(auth.is_pin_blocked());
        let result = auth.verify_pin("1234");
        assert_eq!(result, Err(StatusCode::PinBlocked));
    }

    #[test]
    fn test_change_pin() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();
        assert!(auth.change_pin("1234", "5678").is_ok());
        assert!(auth.verify_pin("5678").is_ok());
        assert!(auth.verify_pin("1234").is_err());
    }

    #[test]
    fn test_get_pin_token() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();

        let token = auth
            .get_pin_token("1234", Permission::MakeCredential.to_u8(), None)
            .unwrap();
        assert_eq!(token.len(), 32);
    }

    #[test]
    fn test_verify_pin_uv_auth_token() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();

        // Get token with MakeCredential permission
        let _ = auth
            .get_pin_token(
                "1234",
                Permission::MakeCredential.to_u8(),
                Some("example.com".to_string()),
            )
            .unwrap();

        // Should succeed with correct permission and RP
        assert!(
            auth.verify_pin_uv_auth_token(Permission::MakeCredential, Some("example.com"))
                .is_ok()
        );

        // Should fail with wrong permission
        assert_eq!(
            auth.verify_pin_uv_auth_token(Permission::CredentialManagement, None),
            Err(StatusCode::UnauthorizedPermission)
        );
    }

    #[test]
    fn test_custom_command() {
        let mut auth = create_test_authenticator();

        // Register custom command
        auth.register_custom_command(0x40, |request| {
            Ok(request.iter().map(|b| b.wrapping_add(1)).collect())
        });

        // Test custom command
        let response = auth.handle_custom_command(0x40, &[1, 2, 3]).unwrap();
        assert_eq!(response, vec![2, 3, 4]);
    }

    #[test]
    fn test_reset() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();
        auth.reset().unwrap();
        assert!(!auth.is_pin_set());
        assert_eq!(auth.pin_retries(), MAX_PIN_RETRIES);
    }

    #[test]
    fn test_delete_all_credentials() {
        use alloc::collections::BTreeMap;
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicUsize, Ordering};

        #[cfg(feature = "std")]
        use std::sync::Mutex;

        #[cfg(not(feature = "std"))]
        use spin::Mutex;

        // Mock callbacks that track deletion calls
        struct TrackingCallbacks {
            credentials: Arc<Mutex<BTreeMap<Vec<u8>, Credential>>>,
            delete_count: Arc<AtomicUsize>,
        }

        impl UserInteractionCallbacks for TrackingCallbacks {
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
                Ok(0)
            }
        }

        impl CredentialStorageCallbacks for TrackingCallbacks {
            fn write_credential(&self, credential: &Credential) -> Result<(), StatusCode> {
                #[cfg(feature = "std")]
                let mut creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let mut creds = self.credentials.lock();

                creds.insert(credential.id.clone(), credential.clone());
                Ok(())
            }

            fn delete_credential(&self, credential_id: &[u8]) -> Result<(), StatusCode> {
                #[cfg(feature = "std")]
                let mut creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let mut creds = self.credentials.lock();

                creds.remove(credential_id);
                self.delete_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn read_credentials(
                &self,
                rp_id: &str,
                _user_id: Option<&[u8]>,
            ) -> Result<Vec<Credential>, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                let filtered: Vec<Credential> = creds
                    .values()
                    .filter(|c| c.rp_id == rp_id)
                    .cloned()
                    .collect();
                Ok(filtered)
            }

            fn credential_exists(&self, credential_id: &[u8]) -> Result<bool, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                Ok(creds.contains_key(credential_id))
            }

            fn get_credential(&self, credential_id: &[u8]) -> Result<Credential, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                creds
                    .get(credential_id)
                    .cloned()
                    .ok_or(StatusCode::NoCredentials)
            }

            fn update_credential(&self, credential: &Credential) -> Result<(), StatusCode> {
                #[cfg(feature = "std")]
                let mut creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let mut creds = self.credentials.lock();

                creds.insert(credential.id.clone(), credential.clone());
                Ok(())
            }

            fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                let mut rp_map: BTreeMap<String, (Option<String>, usize)> = BTreeMap::new();

                for cred in creds.values() {
                    let entry = rp_map
                        .entry(cred.rp_id.clone())
                        .or_insert((Some(cred.rp_id.clone()), 0));
                    entry.1 += 1;
                }

                let result: Vec<(String, Option<String>, usize)> = rp_map
                    .into_iter()
                    .map(|(rp_id, (rp_name, count))| (rp_id, rp_name, count))
                    .collect();

                Ok(result)
            }

            fn credential_count(&self) -> Result<usize, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                Ok(creds.len())
            }
        }

        // Create test credentials
        let credentials = Arc::new(Mutex::new(BTreeMap::new()));
        let delete_count = Arc::new(AtomicUsize::new(0));

        let callbacks = TrackingCallbacks {
            credentials: credentials.clone(),
            delete_count: delete_count.clone(),
        };

        // Add some test credentials
        let cred1 = Credential {
            id: vec![1, 2, 3],
            rp_id: "example.com".to_string(),
            rp_name: Some("Example".to_string()),
            user_id: vec![1],
            user_name: Some("user1".to_string()),
            user_display_name: None,
            private_key: crate::SecBytes::from_slice(&[0u8; 32]),
            algorithm: CoseAlgorithm::ES256.to_i32(),
            sign_count: 0,
            created: 0,
            discoverable: true,
            cred_protect: 0,
        };

        let cred2 = Credential {
            id: vec![4, 5, 6],
            rp_id: "example.org".to_string(),
            rp_name: Some("Example Org".to_string()),
            user_id: vec![2],
            user_name: Some("user2".to_string()),
            user_display_name: None,
            private_key: crate::SecBytes::from_slice(&[0u8; 32]),
            algorithm: CoseAlgorithm::ES256.to_i32(),
            sign_count: 0,
            created: 0,
            discoverable: true,
            cred_protect: 0,
        };

        callbacks.write_credential(&cred1).unwrap();
        callbacks.write_credential(&cred2).unwrap();

        // Verify credentials were added
        assert_eq!(callbacks.credential_count().unwrap(), 2);

        // Create authenticator and call delete_all_credentials
        let config = AuthenticatorConfig::new();
        let auth = Authenticator::new(config, callbacks);

        auth.delete_all_credentials().unwrap();

        // Verify all credentials were deleted
        assert_eq!(delete_count.load(Ordering::SeqCst), 2);

        #[cfg(feature = "std")]
        assert_eq!(credentials.lock().unwrap().len(), 0);

        #[cfg(not(feature = "std"))]
        assert_eq!(credentials.lock().len(), 0);
    }

    #[test]
    fn test_reset_deletes_credentials() {
        use alloc::collections::BTreeMap;
        use alloc::sync::Arc;

        #[cfg(feature = "std")]
        use std::sync::Mutex;

        #[cfg(not(feature = "std"))]
        use spin::Mutex;

        // Mock callbacks with credential storage
        struct StorageCallbacks {
            credentials: Arc<Mutex<BTreeMap<Vec<u8>, Credential>>>,
        }

        impl UserInteractionCallbacks for StorageCallbacks {
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
                Ok(0)
            }
        }

        impl CredentialStorageCallbacks for StorageCallbacks {
            fn write_credential(&self, credential: &Credential) -> Result<(), StatusCode> {
                #[cfg(feature = "std")]
                let mut creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let mut creds = self.credentials.lock();

                creds.insert(credential.id.clone(), credential.clone());
                Ok(())
            }

            fn delete_credential(&self, credential_id: &[u8]) -> Result<(), StatusCode> {
                #[cfg(feature = "std")]
                let mut creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let mut creds = self.credentials.lock();

                creds.remove(credential_id);
                Ok(())
            }

            fn read_credentials(
                &self,
                rp_id: &str,
                _user_id: Option<&[u8]>,
            ) -> Result<Vec<Credential>, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                let filtered: Vec<Credential> = creds
                    .values()
                    .filter(|c| c.rp_id == rp_id)
                    .cloned()
                    .collect();
                Ok(filtered)
            }

            fn credential_exists(&self, credential_id: &[u8]) -> Result<bool, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                Ok(creds.contains_key(credential_id))
            }

            fn get_credential(&self, credential_id: &[u8]) -> Result<Credential, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                creds
                    .get(credential_id)
                    .cloned()
                    .ok_or(StatusCode::NoCredentials)
            }

            fn update_credential(&self, credential: &Credential) -> Result<(), StatusCode> {
                #[cfg(feature = "std")]
                let mut creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let mut creds = self.credentials.lock();

                creds.insert(credential.id.clone(), credential.clone());
                Ok(())
            }

            fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                let mut rp_map: BTreeMap<String, (Option<String>, usize)> = BTreeMap::new();

                for cred in creds.values() {
                    let entry = rp_map
                        .entry(cred.rp_id.clone())
                        .or_insert((Some(cred.rp_id.clone()), 0));
                    entry.1 += 1;
                }

                let result: Vec<(String, Option<String>, usize)> = rp_map
                    .into_iter()
                    .map(|(rp_id, (rp_name, count))| (rp_id, rp_name, count))
                    .collect();

                Ok(result)
            }

            fn credential_count(&self) -> Result<usize, StatusCode> {
                #[cfg(feature = "std")]
                let creds = self.credentials.lock().unwrap();

                #[cfg(not(feature = "std"))]
                let creds = self.credentials.lock();

                Ok(creds.len())
            }
        }

        let credentials = Arc::new(Mutex::new(BTreeMap::new()));
        let callbacks = StorageCallbacks {
            credentials: credentials.clone(),
        };

        // Add test credentials
        let cred = Credential {
            id: vec![1, 2, 3],
            rp_id: "example.com".to_string(),
            rp_name: Some("Example".to_string()),
            user_id: vec![1],
            user_name: Some("user1".to_string()),
            user_display_name: None,
            private_key: crate::SecBytes::from_slice(&[0u8; 32]),
            algorithm: CoseAlgorithm::ES256.to_i32(),
            sign_count: 0,
            created: 0,
            discoverable: true,
            cred_protect: 0,
        };

        callbacks.write_credential(&cred).unwrap();
        assert_eq!(callbacks.credential_count().unwrap(), 1);

        // Create authenticator and reset
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, callbacks);
        auth.set_pin("1234").unwrap();
        auth.reset().unwrap();

        // Verify reset cleared PIN and deleted credentials
        assert!(!auth.is_pin_set());
        assert_eq!(auth.pin_retries(), MAX_PIN_RETRIES);

        #[cfg(feature = "std")]
        assert_eq!(credentials.lock().unwrap().len(), 0);

        #[cfg(not(feature = "std"))]
        assert_eq!(credentials.lock().len(), 0);
    }

    #[test]
    fn test_min_pin_length() {
        let mut auth = create_test_authenticator();
        assert_eq!(auth.min_pin_length(), 4);

        auth.set_min_pin_length(8).unwrap();
        assert_eq!(auth.min_pin_length(), 8);

        // PIN too short for new minimum
        let result = auth.set_pin("1234");
        assert_eq!(result, Err(StatusCode::PinPolicyViolation));

        // PIN meets new minimum
        assert!(auth.set_pin("12345678").is_ok());
    }
}
