//! Request and response types for CTAP client operations

use crate::error::{Error, Result};

use soft_fido2_ctap::types::{RelyingParty, User};

use alloc::string::String;
use alloc::vec::Vec;

/// A validated client data hash (must be exactly 32 bytes)
///
/// This newtype ensures that client data hashes are always the correct length,
/// preventing runtime validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDataHash([u8; 32]);

impl ClientDataHash {
    /// Create a new ClientDataHash from a 32-byte array
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Create a ClientDataHash from a slice
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidClientDataHash` if the slice is not exactly 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(Error::InvalidClientDataHash);
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(slice);
        Ok(Self(hash))
    }

    /// Get a reference to the underlying hash bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get the hash as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ClientDataHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ClientDataHash {
    fn from(hash: [u8; 32]) -> Self {
        Self::new(hash)
    }
}

/// Type of credential
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    /// Public key credential (the only type currently defined in CTAP2)
    #[default]
    PublicKey,
}

impl CredentialType {
    /// Get the string representation for CBOR encoding
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialType::PublicKey => "public-key",
        }
    }
}

/// A credential descriptor identifying a specific credential
///
/// Used in getAssertion to specify which credentials are allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDescriptor {
    /// The credential ID
    pub id: Vec<u8>,
    /// The type of credential (typically PublicKey)
    pub credential_type: CredentialType,
}

impl CredentialDescriptor {
    /// Create a new credential descriptor
    pub fn new(id: Vec<u8>, credential_type: CredentialType) -> Self {
        Self {
            id,
            credential_type,
        }
    }

    /// Create a public key credential descriptor (convenience method)
    pub fn public_key(id: Vec<u8>) -> Self {
        Self {
            id,
            credential_type: CredentialType::PublicKey,
        }
    }
}

/// PIN/UV authentication protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PinUvAuthProtocol {
    /// PIN/UV protocol version 1
    V1 = 1,
    /// PIN/UV protocol version 2 (recommended)
    V2 = 2,
}

impl PinUvAuthProtocol {
    /// Convert to u8 for CBOR encoding
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<PinUvAuthProtocol> for u8 {
    fn from(protocol: PinUvAuthProtocol) -> u8 {
        protocol.as_u8()
    }
}

/// Bundle of PIN/UV authentication parameter and protocol version
///
/// This ensures that the auth parameter and protocol version are always paired correctly.
#[derive(Debug, Clone)]
pub struct PinUvAuth {
    param: Vec<u8>,
    protocol: PinUvAuthProtocol,
}

impl PinUvAuth {
    /// Create a new PIN/UV authentication bundle
    ///
    /// # Arguments
    ///
    /// * `param` - The authentication parameter bytes
    /// * `protocol` - The protocol version used to generate the parameter
    pub fn new(param: Vec<u8>, protocol: PinUvAuthProtocol) -> Self {
        Self { param, protocol }
    }

    /// Get the authentication parameter bytes
    pub fn param(&self) -> &[u8] {
        &self.param
    }

    /// Get the protocol version
    pub fn protocol(&self) -> PinUvAuthProtocol {
        self.protocol
    }

    /// Get the protocol version as u8
    pub fn protocol_u8(&self) -> u8 {
        self.protocol.as_u8()
    }
}

/// Request for creating a new credential (authenticatorMakeCredential)
///
/// Use the builder pattern to construct requests with optional parameters.
#[derive(Debug)]
pub struct MakeCredentialRequest {
    pub(crate) client_data_hash: ClientDataHash,
    pub(crate) rp: RelyingParty,
    pub(crate) user: User,
    pub(crate) pin_uv_auth: Option<PinUvAuth>,
    pub(crate) timeout_ms: i32,
    pub(crate) resident_key: Option<bool>,
    pub(crate) user_verification: Option<bool>,
}

impl MakeCredentialRequest {
    /// Create a new MakeCredentialRequest with required parameters
    ///
    /// # Arguments
    ///
    /// * `client_data_hash` - SHA-256 hash of the WebAuthn client data
    /// * `rp` - Relying party information (ID and optional name)
    /// * `user` - User information (ID, name, optional display name)
    pub fn new(client_data_hash: ClientDataHash, rp: RelyingParty, user: User) -> Self {
        Self {
            client_data_hash,
            rp,
            user,
            pin_uv_auth: None,
            timeout_ms: 30000, // 30 second default
            resident_key: None,
            user_verification: None,
        }
    }

    /// Set the PIN/UV authentication parameter
    pub fn with_pin_uv_auth(mut self, auth: PinUvAuth) -> Self {
        self.pin_uv_auth = Some(auth);
        self
    }

    /// Set the timeout in milliseconds (default: 30000ms)
    pub fn with_timeout(mut self, timeout_ms: i32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set whether to create a resident key (discoverable credential)
    pub fn with_resident_key(mut self, resident_key: bool) -> Self {
        self.resident_key = Some(resident_key);
        self
    }

    /// Set whether to require user verification
    pub fn with_user_verification(mut self, user_verification: bool) -> Self {
        self.user_verification = Some(user_verification);
        self
    }

    /// Get the client data hash
    pub fn client_data_hash(&self) -> &ClientDataHash {
        &self.client_data_hash
    }

    /// Get the relying party information
    pub fn rp(&self) -> &RelyingParty {
        &self.rp
    }

    /// Get the user information
    pub fn user(&self) -> &User {
        &self.user
    }

    /// Get the PIN/UV authentication parameter if set
    pub fn pin_uv_auth(&self) -> Option<&PinUvAuth> {
        self.pin_uv_auth.as_ref()
    }

    /// Get the timeout in milliseconds
    pub fn timeout_ms(&self) -> i32 {
        self.timeout_ms
    }
}

/// Request for getting an assertion (authenticatorGetAssertion)
///
/// Use the builder pattern to construct requests with optional parameters.
#[derive(Debug)]
pub struct GetAssertionRequest {
    pub(crate) client_data_hash: ClientDataHash,
    pub(crate) rp_id: String,
    pub(crate) allow_list: Vec<CredentialDescriptor>,
    pub(crate) pin_uv_auth: Option<PinUvAuth>,
    pub(crate) timeout_ms: i32,
    pub(crate) user_verification: Option<bool>,
}

impl GetAssertionRequest {
    /// Create a new GetAssertionRequest with required parameters
    ///
    /// # Arguments
    ///
    /// * `client_data_hash` - SHA-256 hash of the WebAuthn client data
    /// * `rp_id` - Relying party identifier (domain)
    pub fn new(client_data_hash: ClientDataHash, rp_id: impl Into<String>) -> Self {
        Self {
            client_data_hash,
            rp_id: rp_id.into(),
            allow_list: Vec::new(),
            pin_uv_auth: None,
            timeout_ms: 30000, // 30 second default
            user_verification: None,
        }
    }

    /// Add a single credential to the allow list
    pub fn with_credential(mut self, credential: CredentialDescriptor) -> Self {
        self.allow_list.push(credential);
        self
    }

    /// Set the allow list to a specific set of credentials
    pub fn with_credentials(mut self, credentials: Vec<CredentialDescriptor>) -> Self {
        self.allow_list = credentials;
        self
    }

    /// Set the PIN/UV authentication parameter
    pub fn with_pin_uv_auth(mut self, auth: PinUvAuth) -> Self {
        self.pin_uv_auth = Some(auth);
        self
    }

    /// Set the timeout in milliseconds (default: 30000ms)
    pub fn with_timeout(mut self, timeout_ms: i32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set whether to require user verification
    pub fn with_user_verification(mut self, user_verification: bool) -> Self {
        self.user_verification = Some(user_verification);
        self
    }

    /// Get the client data hash
    pub fn client_data_hash(&self) -> &ClientDataHash {
        &self.client_data_hash
    }

    /// Get the relying party identifier
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Get the allow list of credentials
    pub fn allow_list(&self) -> &[CredentialDescriptor] {
        &self.allow_list
    }

    /// Get the PIN/UV authentication parameter if set
    pub fn pin_uv_auth(&self) -> Option<&PinUvAuth> {
        self.pin_uv_auth.as_ref()
    }

    /// Get the timeout in milliseconds
    pub fn timeout_ms(&self) -> i32 {
        self.timeout_ms
    }
}

/// PIN/UV auth token permissions
///
/// These correspond to the permission bits defined in FIDO 2.2 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Permission {
    /// Make credential permission (0x01)
    MakeCredential = 0x01,
    /// Get assertion permission (0x02)
    GetAssertion = 0x02,
    /// Credential management permission (0x04)
    CredentialManagement = 0x04,
    /// Bio enrollment permission (0x08)
    BioEnrollment = 0x08,
    /// Large blob write permission (0x10)
    LargeBlobWrite = 0x10,
    /// Authenticator configuration permission (0x20)
    AuthenticatorConfiguration = 0x20,
}

impl Permission {
    /// Convert to u8 bitmask value
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Request for credential management operations
#[derive(Debug, Clone)]
pub struct CredentialManagementRequest {
    pin_uv_auth: Option<PinUvAuth>,
}

impl CredentialManagementRequest {
    /// Create new credential management request
    ///
    /// # Arguments
    /// * `pin_uv_auth` - Optional PIN/UV auth token with CredentialManagement permission
    ///
    /// # Important
    /// For getCredsMetadata and enumerate RPs, the PIN/UV auth token MUST NOT
    /// have a permissions RP ID parameter when obtained from clientPIN.
    pub fn new(pin_uv_auth: Option<PinUvAuth>) -> Self {
        Self { pin_uv_auth }
    }

    /// Get the PIN/UV auth bundle
    pub fn pin_uv_auth(&self) -> Option<&PinUvAuth> {
        self.pin_uv_auth.as_ref()
    }
}

/// Request to enumerate credentials for a specific RP
#[derive(Debug, Clone)]
pub struct EnumerateCredentialsRequest {
    pin_uv_auth: Option<PinUvAuth>,
    rp_id_hash: [u8; 32],
}

impl EnumerateCredentialsRequest {
    /// Create new enumerate credentials request
    ///
    /// # Arguments
    /// * `pin_uv_auth` - Optional PIN/UV auth token with CredentialManagement permission
    /// * `rp_id_hash` - SHA-256 hash of RP ID
    pub fn new(pin_uv_auth: Option<PinUvAuth>, rp_id_hash: [u8; 32]) -> Self {
        Self {
            pin_uv_auth,
            rp_id_hash,
        }
    }

    /// Get the PIN/UV auth bundle
    pub fn pin_uv_auth(&self) -> Option<&PinUvAuth> {
        self.pin_uv_auth.as_ref()
    }

    /// Get the RP ID hash
    pub fn rp_id_hash(&self) -> &[u8; 32] {
        &self.rp_id_hash
    }
}

/// Request to delete a credential
#[derive(Debug, Clone)]
pub struct DeleteCredentialRequest {
    pin_uv_auth: Option<PinUvAuth>,
    credential_id: Vec<u8>,
}

impl DeleteCredentialRequest {
    /// Create new delete credential request
    ///
    /// # Arguments
    /// * `pin_uv_auth` - Optional PIN/UV auth token with CredentialManagement permission
    /// * `credential_id` - ID of credential to delete
    ///
    /// # Note
    /// Platforms SHOULD also delete any associated large blobs after successful deletion.
    pub fn new(pin_uv_auth: Option<PinUvAuth>, credential_id: Vec<u8>) -> Self {
        Self {
            pin_uv_auth,
            credential_id,
        }
    }

    /// Get the PIN/UV auth bundle
    pub fn pin_uv_auth(&self) -> Option<&PinUvAuth> {
        self.pin_uv_auth.as_ref()
    }

    /// Get the credential ID
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

/// Request to update user information
#[derive(Debug, Clone)]
pub struct UpdateUserRequest {
    pin_uv_auth: Option<PinUvAuth>,
    credential_id: Vec<u8>,
    user: User,
}

impl UpdateUserRequest {
    /// Create new update user information request
    ///
    /// # Arguments
    /// * `pin_uv_auth` - Optional PIN/UV auth token with CredentialManagement permission
    /// * `credential_id` - ID of credential to update
    /// * `user` - New user information
    ///
    /// # Important
    /// - The user.id field MUST match the existing credential's user ID
    /// - Empty fields in user parameter are removed from the credential
    /// - Only name and displayName are updated (id is not changed)
    pub fn new(pin_uv_auth: Option<PinUvAuth>, credential_id: Vec<u8>, user: User) -> Self {
        Self {
            pin_uv_auth,
            credential_id,
            user,
        }
    }

    /// Get the PIN/UV auth bundle
    pub fn pin_uv_auth(&self) -> Option<&PinUvAuth> {
        self.pin_uv_auth.as_ref()
    }

    /// Get the credential ID
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Get the user information
    pub fn user(&self) -> &User {
        &self.user
    }
}
