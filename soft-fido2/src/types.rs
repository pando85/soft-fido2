//! Common types for FIDO2/WebAuthn operations

use crate::error::{Error, Result};

use serde::{Deserialize, Serialize};

/// Relying party information
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RelyingParty {
    /// RP ID (max 128 bytes)
    pub id: String,
    /// RP name (optional)
    pub name: Option<String>,
}

/// User information
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct User {
    /// User handle (max 64 bytes)
    pub id: Vec<u8>,
    /// User name (email or username)
    pub name: Option<String>,
    /// User display name (friendly name)
    pub display_name: Option<String>,
}

/// Credential extension data
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Extensions {
    /// Credential protection level
    pub cred_protect: Option<u8>,
    /// HMAC secret extension
    pub hmac_secret: Option<bool>,
}

/// Owned representation of a FIDO2 credential
///
/// This is the unified credential type used by both implementations.
/// It matches the zig-ffi structure exactly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Credential {
    /// Credential ID (max 64 bytes)
    pub id: Vec<u8>,
    /// Relying party information
    pub rp: RelyingParty,
    /// User information
    pub user: User,
    /// Signature counter
    pub sign_count: u32,
    /// Algorithm (-7 for ES256)
    pub alg: i32,
    /// Private key bytes (32 bytes for ES256)
    pub private_key: Vec<u8>,
    /// Creation timestamp
    pub created: i64,
    /// Is resident key
    pub discoverable: bool,
    /// Extension data
    pub extensions: Extensions,
}

/// Borrowed (zero-copy) representation of a FIDO2 credential
///
/// This type is used for FFI callbacks to avoid heap allocations.
/// All fields are borrowed and have no ownership.
#[derive(Clone, Copy, Debug)]
pub struct CredentialRef<'a> {
    /// Credential ID (max 64 bytes)
    pub id: &'a [u8],
    /// Relying party ID (max 128 bytes)
    pub rp_id: &'a str,
    /// Relying party name (optional, max 64 bytes)
    pub rp_name: Option<&'a str>,
    /// User ID (max 64 bytes)
    pub user_id: &'a [u8],
    /// User name
    pub user_name: Option<&'a str>,
    /// User display name (optional)
    pub user_display_name: Option<&'a str>,
    /// Signature counter
    pub sign_count: u32,
    /// Algorithm (-7 for ES256)
    pub alg: i32,
    /// Private key bytes (32 bytes for ES256)
    pub private_key: &'a [u8],
    /// Creation timestamp
    pub created: i64,
    /// Is resident key
    pub discoverable: bool,
    /// Credential protection level
    pub cred_protect: Option<u8>,
}

impl<'a> CredentialRef<'a> {
    /// Convert borrowed credential to owned Credential
    pub fn to_owned(&self) -> Credential {
        Credential {
            id: self.id.to_vec(),
            rp: RelyingParty {
                id: self.rp_id.to_string(),
                name: self.rp_name.map(|s| s.to_string()),
            },
            user: User {
                id: self.user_id.to_vec(),
                name: self.user_name.map(|s| s.to_string()),
                display_name: self.user_display_name.map(|s| s.to_string()),
            },
            sign_count: self.sign_count,
            alg: self.alg,
            private_key: self.private_key.to_vec(),
            created: self.created,
            discoverable: self.discoverable,
            extensions: Extensions {
                cred_protect: self.cred_protect,
                hmac_secret: None,
            },
        }
    }

    /// Serialize credential to bytes (CBOR)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let owned = self.to_owned();
        let mut buf = Vec::new();
        soft_fido2_ctap::cbor::into_writer(&owned, &mut buf).map_err(|_| Error::Other)?;
        Ok(buf)
    }
}

impl Credential {
    /// Serialize credential to bytes (CBOR)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        soft_fido2_ctap::cbor::into_writer(self, &mut buf).map_err(|_| Error::Other)?;
        Ok(buf)
    }

    /// Deserialize credential from bytes (CBOR)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        soft_fido2_ctap::cbor::decode(data).map_err(|_| Error::Other)
    }
}

// Conversion from keylib-ctap credential type (pure Rust implementation)
impl From<soft_fido2_ctap::types::Credential> for Credential {
    fn from(cred: soft_fido2_ctap::types::Credential) -> Self {
        Credential {
            id: cred.id,
            rp: RelyingParty {
                id: cred.rp_id,
                name: cred.rp_name,
            },
            user: User {
                id: cred.user_id,
                name: cred.user_name,
                display_name: cred.user_display_name,
            },
            sign_count: cred.sign_count,
            alg: cred.algorithm,
            private_key: cred.private_key,
            created: cred.created,
            discoverable: cred.discoverable,
            extensions: Extensions {
                cred_protect: Some(cred.cred_protect),
                hmac_secret: None,
            },
        }
    }
}

// Conversion to keylib-ctap credential type (pure Rust implementation)
impl From<Credential> for soft_fido2_ctap::types::Credential {
    fn from(cred: Credential) -> Self {
        soft_fido2_ctap::types::Credential {
            id: cred.id,
            rp_id: cred.rp.id,
            rp_name: cred.rp.name,
            user_id: cred.user.id,
            user_name: cred.user.name,
            user_display_name: cred.user.display_name,
            sign_count: cred.sign_count,
            algorithm: cred.alg,
            private_key: cred.private_key,
            created: cred.created,
            discoverable: cred.discoverable,
            cred_protect: cred.extensions.cred_protect.unwrap_or(1),
        }
    }
}
