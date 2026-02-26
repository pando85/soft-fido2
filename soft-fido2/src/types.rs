//! High-level types for FIDO2/WebAuthn credentials
//!
//! This module provides ergonomic types for working with FIDO2 credentials at the
//! application level. The main difference from the CTAP protocol layer is the use
//! of grouped structures for better API usability:
//!
//! ```rust
//! use soft_fido2::types::Credential;
//!
//! # let credential = Credential {
//! #     id: vec![1, 2, 3],
//! #     rp: soft_fido2::RelyingParty::new("example.com".into()),
//! #     user: soft_fido2::User::new(vec![1, 2, 3]),
//! #     sign_count: 0,
//! #     alg: -7,
//! #     private_key: soft_fido2_ctap::SecBytes::new(vec![0u8; 32]),
//! #     created: 0,
//! #     discoverable: false,
//! #     extensions: soft_fido2::Extensions::default(),
//! # };
//! // Grouped fields for ergonomics
//! println!("RP: {}", credential.rp.id);
//! println!("User: {}", credential.user.id[0]);
//! ```
//!
//! ## Type Organization
//!
//! - **[`RelyingParty`]** and **[`User`]**: Basic WebAuthn entities (from CTAP layer)
//! - **[`Credential`]**: Owned credential with grouped fields for API ergonomics
//! - **[`CredentialRef`]**: Zero-copy borrowed credential for callback interfaces
//! - **[`Extensions`]**: WebAuthn extension data (credProtect, hmac-secret)
//!
//! ## Converting Between Layers
//!
//! Use [`From`] trait to convert between high-level and CTAP protocol representations:
//!
//! ```rust
//! # use soft_fido2::types::Credential;
//! # let high_level_cred = Credential {
//! #     id: vec![1, 2, 3],
//! #     rp: soft_fido2::RelyingParty::new("example.com".into()),
//! #     user: soft_fido2::User::new(vec![1, 2, 3]),
//! #     sign_count: 0,
//! #     alg: -7,
//! #     private_key: soft_fido2_ctap::SecBytes::new(vec![0u8; 32]),
//! #     created: 0,
//! #     discoverable: false,
//! #     extensions: soft_fido2::Extensions::default(),
//! # };
//! // Convert to CTAP protocol format (flat structure)
//! let ctap_cred: soft_fido2_ctap::types::Credential = high_level_cred.into();
//! ```

use crate::error::{Error, Result};

use soft_fido2_ctap::SecBytes;

use alloc::borrow::ToOwned;
use alloc::string::ToString;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

pub use soft_fido2_ctap::types::{RelyingParty, User};

/// Credential extension data
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Extensions {
    /// Credential protection level
    pub cred_protect: Option<u8>,
    /// HMAC secret extension
    pub hmac_secret: Option<bool>,
    /// HMAC secret credential random (32 bytes)
    /// Used to compute HMAC outputs for the hmac-secret extension
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_random: Option<soft_fido2_ctap::SecBytes>,
}

/// Owned representation of a FIDO2 credential
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
    ///
    /// # Security
    ///
    /// - **With `std` feature** (default): Protected using `SecVec` which:
    ///   - Zeros memory on drop using `mlock`
    ///   - Prevents swapping to disk
    ///   - Uses constant-time equality
    /// - **Without `std` (no_std)**: Stored as plain `Vec<u8>` for compatibility.
    ///   No memory protection is provided in no_std environments.
    ///
    /// The storage boundary (this field) is the primary protection point for
    /// long-term credential storage.
    pub private_key: SecBytes,
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
    pub sign_count: &'a u32,
    /// Algorithm (-7 for ES256)
    pub alg: &'a i32,
    /// Private key bytes (32 bytes for ES256)
    pub private_key: &'a SecBytes,
    /// Creation timestamp
    pub created: &'a i64,
    /// Is resident key
    pub discoverable: &'a bool,
    /// Credential protection level
    pub cred_protect: Option<&'a u8>,
    /// Credential random for hmac-secret extension (32 bytes)
    pub cred_random: Option<&'a SecBytes>,
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
            sign_count: self.sign_count.to_owned(),
            alg: self.alg.to_owned(),
            private_key: self.private_key.to_owned(),
            created: self.created.to_owned(),
            discoverable: self.discoverable.to_owned(),
            extensions: Extensions {
                cred_protect: self.cred_protect.copied(),
                hmac_secret: None,
                cred_random: self.cred_random.cloned(),
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
                hmac_secret: cred.cred_random.is_some().then_some(true),
                cred_random: cred.cred_random,
            },
        }
    }
}

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
            cred_random: cred.extensions.cred_random,
        }
    }
}
