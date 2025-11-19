//! CTAP data types
//!
//! Core data structures used in CTAP protocol messages.
//! All types support CBOR serialization as required by the FIDO2 spec.

use serde::{Deserialize, Serialize};

/// Relying Party information
///
/// Represents a web service that uses FIDO2 for authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelyingParty {
    /// Relying party identifier (e.g., "example.com")
    pub id: String,

    /// Human-readable name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl RelyingParty {
    /// Create a new RelyingParty with just an ID
    pub fn new(id: String) -> Self {
        Self { id, name: None }
    }

    /// Create a new RelyingParty with ID and name
    pub fn with_name(id: String, name: String) -> Self {
        Self {
            id,
            name: Some(name),
        }
    }
}

/// User information
///
/// Represents the user account being registered or authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// User handle - opaque identifier for the user
    pub id: Vec<u8>,

    /// Human-readable username (optional in some contexts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Human-readable display name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}

impl User {
    /// Create a new User with just an ID
    pub fn new(id: Vec<u8>) -> Self {
        Self {
            id,
            name: None,
            display_name: None,
        }
    }

    /// Create a new User with all fields
    pub fn with_details(id: Vec<u8>, name: String, display_name: String) -> Self {
        Self {
            id,
            name: Some(name),
            display_name: Some(display_name),
        }
    }
}

/// Public key credential descriptor
///
/// Identifies a credential by its type and ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    /// Credential type (always "public-key" for FIDO2)
    #[serde(rename = "type")]
    pub cred_type: String,

    /// Credential ID
    pub id: Vec<u8>,

    /// Supported transports (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

impl PublicKeyCredentialDescriptor {
    /// Create a new public-key credential descriptor
    pub fn new(id: Vec<u8>) -> Self {
        Self {
            cred_type: "public-key".to_string(),
            id,
            transports: None,
        }
    }

    /// Create with specific transports
    pub fn with_transports(id: Vec<u8>, transports: Vec<String>) -> Self {
        Self {
            cred_type: "public-key".to_string(),
            id,
            transports: Some(transports),
        }
    }
}

/// Public key credential parameters
///
/// Specifies an acceptable credential type and algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,

    /// COSE algorithm identifier
    pub alg: i32,
}

impl PublicKeyCredentialParameters {
    /// ES256 algorithm (P-256 + SHA-256)
    pub fn es256() -> Self {
        Self {
            cred_type: "public-key".to_string(),
            alg: -7,
        }
    }

    /// Create new credential parameters
    pub fn new(cred_type: String, alg: i32) -> Self {
        Self { cred_type, alg }
    }
}

/// COSE algorithm identifiers
///
/// Common COSE algorithm identifiers used in FIDO2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CoseAlgorithm {
    /// ES256 (ECDSA with P-256 and SHA-256)
    ES256 = -7,
    /// EdDSA
    EdDSA = -8,
    /// ES384 (ECDSA with P-384 and SHA-384)
    ES384 = -35,
    /// ES512 (ECDSA with P-521 and SHA-512)
    ES512 = -36,
    /// RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
    RS256 = -257,
}

impl CoseAlgorithm {
    /// Convert to i32 value
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    /// Create from i32 value
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            -7 => Some(Self::ES256),
            -8 => Some(Self::EdDSA),
            -35 => Some(Self::ES384),
            -36 => Some(Self::ES512),
            -257 => Some(Self::RS256),
            _ => None,
        }
    }
}

/// Authenticator options
///
/// Boolean options that control authenticator behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorOptions {
    /// Resident key (discoverable credential)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,

    /// User presence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<bool>,

    /// User verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv: Option<bool>,
}

impl AuthenticatorOptions {
    /// Create new empty options
    pub fn new() -> Self {
        Self::default()
    }

    /// Set resident key option
    pub fn with_rk(mut self, rk: bool) -> Self {
        self.rk = Some(rk);
        self
    }

    /// Set user presence option
    pub fn with_up(mut self, up: bool) -> Self {
        self.up = Some(up);
        self
    }

    /// Set user verification option
    pub fn with_uv(mut self, uv: bool) -> Self {
        self.uv = Some(uv);
        self
    }
}

/// Credential protection policy
///
/// Defines the level of protection for a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CredProtect {
    /// User verification optional
    UserVerificationOptional = 0x01,
    /// User verification optional with credential ID list
    UserVerificationOptionalWithCredentialIdList = 0x02,
    /// User verification required
    UserVerificationRequired = 0x03,
}

impl CredProtect {
    /// Convert to u8 value
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Create from u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::UserVerificationOptional),
            0x02 => Some(Self::UserVerificationOptionalWithCredentialIdList),
            0x03 => Some(Self::UserVerificationRequired),
            _ => None,
        }
    }
}

/// Credential data stored by authenticator
///
/// Internal representation of a credential with all metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Credential ID
    pub id: Vec<u8>,

    /// Relying party identifier
    pub rp_id: String,

    /// Relying party name
    pub rp_name: Option<String>,

    /// User handle
    pub user_id: Vec<u8>,

    /// User name
    pub user_name: Option<String>,

    /// User display name
    pub user_display_name: Option<String>,

    /// Signature counter
    pub sign_count: u32,

    /// COSE algorithm identifier
    pub algorithm: i32,

    /// Private key (32 bytes for P-256)
    pub private_key: Vec<u8>,

    /// Creation timestamp (Unix timestamp)
    pub created: i64,

    /// Whether this is a discoverable credential
    pub discoverable: bool,

    /// Credential protection level
    pub cred_protect: u8,
}

impl Credential {
    /// Create a new credential
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Vec<u8>,
        rp_id: String,
        rp_name: Option<String>,
        user_id: Vec<u8>,
        user_name: Option<String>,
        user_display_name: Option<String>,
        algorithm: i32,
        private_key: Vec<u8>,
        discoverable: bool,
    ) -> Self {
        Self {
            id,
            rp_id,
            rp_name,
            user_id,
            user_name,
            user_display_name,
            sign_count: 0,
            algorithm,
            private_key,
            created: current_timestamp(),
            discoverable,
            cred_protect: CredProtect::UserVerificationOptional.to_u8(),
        }
    }

    /// Increment signature counter
    pub fn increment_counter(&mut self) -> u32 {
        self.sign_count = self.sign_count.wrapping_add(1);
        self.sign_count
    }
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Authenticator transport types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatorTransport {
    /// USB
    Usb,
    /// NFC
    Nfc,
    /// Bluetooth Low Energy
    Ble,
    /// Internal (platform authenticator)
    Internal,
}

impl AuthenticatorTransport {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Nfc => "nfc",
            Self::Ble => "ble",
            Self::Internal => "internal",
        }
    }

    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "usb" => Some(Self::Usb),
            "nfc" => Some(Self::Nfc),
            "ble" => Some(Self::Ble),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relying_party() {
        let rp = RelyingParty::new("example.com".to_string());
        assert_eq!(rp.id, "example.com");
        assert_eq!(rp.name, None);

        let rp = RelyingParty::with_name("example.com".to_string(), "Example".to_string());
        assert_eq!(rp.name, Some("Example".to_string()));
    }

    #[test]
    fn test_user() {
        let user = User::new(vec![1, 2, 3, 4]);
        assert_eq!(user.id, vec![1, 2, 3, 4]);
        assert_eq!(user.name, None);

        let user = User::with_details(
            vec![1, 2, 3, 4],
            "john@example.com".to_string(),
            "John Doe".to_string(),
        );
        assert_eq!(user.name, Some("john@example.com".to_string()));
        assert_eq!(user.display_name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_credential_descriptor() {
        let desc = PublicKeyCredentialDescriptor::new(vec![1, 2, 3]);
        assert_eq!(desc.cred_type, "public-key");
        assert_eq!(desc.id, vec![1, 2, 3]);
        assert_eq!(desc.transports, None);

        let desc =
            PublicKeyCredentialDescriptor::with_transports(vec![1, 2, 3], vec!["usb".to_string()]);
        assert_eq!(desc.transports, Some(vec!["usb".to_string()]));
    }

    #[test]
    fn test_cose_algorithm() {
        assert_eq!(CoseAlgorithm::ES256.to_i32(), -7);
        assert_eq!(CoseAlgorithm::from_i32(-7), Some(CoseAlgorithm::ES256));
        assert_eq!(CoseAlgorithm::from_i32(999), None);
    }

    #[test]
    fn test_cred_protect() {
        assert_eq!(CredProtect::UserVerificationRequired.to_u8(), 0x03);
        assert_eq!(
            CredProtect::from_u8(0x03),
            Some(CredProtect::UserVerificationRequired)
        );
        assert_eq!(CredProtect::from_u8(0xFF), None);
    }

    #[test]
    fn test_authenticator_options() {
        let opts = AuthenticatorOptions::new().with_rk(true).with_uv(true);
        assert_eq!(opts.rk, Some(true));
        assert_eq!(opts.uv, Some(true));
        assert_eq!(opts.up, None);
    }

    #[test]
    fn test_credential_creation() {
        let cred = Credential::new(
            vec![1, 2, 3],
            "example.com".to_string(),
            Some("Example".to_string()),
            vec![4, 5, 6],
            Some("user@example.com".to_string()),
            Some("User Name".to_string()),
            -7,
            vec![0u8; 32],
            true,
        );

        assert_eq!(cred.id, vec![1, 2, 3]);
        assert_eq!(cred.rp_id, "example.com");
        assert_eq!(cred.sign_count, 0);
        assert!(cred.discoverable);
    }

    #[test]
    fn test_credential_counter_increment() {
        let mut cred = Credential::new(
            vec![1],
            "example.com".to_string(),
            None,
            vec![2],
            None,
            None,
            -7,
            vec![0u8; 32],
            false,
        );

        assert_eq!(cred.increment_counter(), 1);
        assert_eq!(cred.increment_counter(), 2);
        assert_eq!(cred.sign_count, 2);
    }

    #[test]
    fn test_authenticator_transport() {
        assert_eq!(AuthenticatorTransport::Usb.as_str(), "usb");
        assert_eq!(
            AuthenticatorTransport::parse("usb"),
            Some(AuthenticatorTransport::Usb)
        );
        assert_eq!(AuthenticatorTransport::parse("invalid"), None);
    }

    #[test]
    fn test_cbor_serialization() {
        let rp = RelyingParty::with_name("example.com".to_string(), "Example".to_string());
        let mut buf = Vec::new();
        let result = crate::cbor::into_writer(&rp, &mut buf);
        assert!(result.is_ok());
    }
}
