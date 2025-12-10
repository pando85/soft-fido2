//! Response types for CTAP client operations
//!
//! Fully decoded, type-safe response structures for credential management commands.

use crate::error::{Error, Result};

use soft_fido2_ctap::cbor::{MapParser, Value};
use soft_fido2_ctap::types::{PublicKeyCredentialDescriptor, User};

use alloc::string::String;
use alloc::vec::Vec;

/// Response from authenticatorCredentialManagement - getCredsMetadata (0x01)
///
/// Returns metadata about credential storage on the authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialsMetadata {
    /// Number of existing discoverable credentials on the authenticator
    pub existing_resident_credentials_count: u32,

    /// Maximum number of additional discoverable credentials that can be created
    ///
    /// Note: This is an estimate. Actual space depends on algorithm choice,
    /// user entity information, etc.
    pub max_possible_remaining_resident_credentials_count: u32,
}

impl CredentialsMetadata {
    /// Parse from CBOR response bytes
    ///
    /// Expected format:
    /// ```cbor
    /// {
    ///   0x01: existingResidentCredentialsCount (unsigned int),
    ///   0x02: maxPossibleRemainingResidentCredentialsCount (unsigned int)
    /// }
    /// ```
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let parser = MapParser::from_bytes(bytes).map_err(|_| Error::Other)?;

        let existing: i32 = parser.get(0x01).map_err(|_| Error::Other)?;
        let remaining: i32 = parser.get(0x02).map_err(|_| Error::Other)?;

        Ok(Self {
            existing_resident_credentials_count: existing as u32,
            max_possible_remaining_resident_credentials_count: remaining as u32,
        })
    }
}

/// Relying party information
///
/// Note: The RP ID may be truncated to 32 bytes per FIDO 2.2 spec §6.8.7.
/// Truncated IDs contain "…" (U+2026) ellipsis and preserve protocol prefix if present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpInfo {
    /// RP ID (may be truncated to 32 bytes with ellipsis)
    pub id: String,

    /// RP name (optional)
    pub name: Option<String>,

    /// RP ID SHA-256 hash (32 bytes)
    pub rp_id_hash: [u8; 32],
}

impl RpInfo {
    /// Parse from CBOR response components
    ///
    /// # Arguments
    /// * `rp_value` - CBOR map with "id" (text) and optional "name" (text)
    /// * `rp_id_hash` - 32-byte SHA-256 hash of RP ID
    pub fn from_cbor_value(rp_value: &Value, rp_id_hash: [u8; 32]) -> Result<Self> {
        let Value::Map(map) = rp_value else {
            return Err(Error::Other);
        };

        let mut id = None;
        let mut name = None;

        for (k, v) in map {
            if let Value::Text(key) = k {
                match key.as_str() {
                    "id" => {
                        if let Value::Text(val) = v {
                            id = Some(val.clone());
                        }
                    }
                    "name" => {
                        if let Value::Text(val) = v {
                            name = Some(val.clone());
                        }
                    }
                    _ => {} // Ignore unknown fields
                }
            }
        }

        let id = id.ok_or(Error::Other)?;

        Ok(Self {
            id,
            name,
            rp_id_hash,
        })
    }
}

/// Response from enumerateRPsBegin (0x02)
///
/// Contains first RP information and total count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpEnumerationBeginResponse {
    /// First RP information
    pub rp: RpInfo,

    /// Total number of RPs on the authenticator
    pub total_rps: u32,
}

impl RpEnumerationBeginResponse {
    /// Parse from CBOR response bytes
    ///
    /// Expected format:
    /// ```cbor
    /// {
    ///   0x03: rp (PublicKeyCredentialRpEntity),
    ///   0x04: rpIDHash (byte string, 32 bytes),
    ///   0x05: totalRPs (unsigned int)
    /// }
    /// ```
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let parser = MapParser::from_bytes(bytes).map_err(|_| Error::Other)?;

        let rp_value: Value = parser.get(0x03).map_err(|_| Error::Other)?;
        let rp_id_hash_vec: Vec<u8> = parser.get_bytes(0x04).map_err(|_| Error::Other)?;
        let total: i32 = parser.get(0x05).map_err(|_| Error::Other)?;

        let mut rp_id_hash = [0u8; 32];
        if rp_id_hash_vec.len() != 32 {
            return Err(Error::Other);
        }
        rp_id_hash.copy_from_slice(&rp_id_hash_vec);

        let rp = RpInfo::from_cbor_value(&rp_value, rp_id_hash)?;

        Ok(Self {
            rp,
            total_rps: total as u32,
        })
    }
}

/// Response from enumerateRPsGetNextRP (0x03)
///
/// Contains next RP in the enumeration sequence.
pub type RpEnumerationNextResponse = RpInfo;

impl RpEnumerationNextResponse {
    /// Parse from CBOR response bytes
    ///
    /// Expected format:
    /// ```cbor
    /// {
    ///   0x03: rp (PublicKeyCredentialRpEntity),
    ///   0x04: rpIDHash (byte string, 32 bytes)
    /// }
    /// ```
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let parser = MapParser::from_bytes(bytes).map_err(|_| Error::Other)?;

        let rp_value: Value = parser.get(0x03).map_err(|_| Error::Other)?;
        let rp_id_hash_vec: Vec<u8> = parser.get_bytes(0x04).map_err(|_| Error::Other)?;

        let mut rp_id_hash = [0u8; 32];
        if rp_id_hash_vec.len() != 32 {
            return Err(Error::Other);
        }
        rp_id_hash.copy_from_slice(&rp_id_hash_vec);

        RpInfo::from_cbor_value(&rp_value, rp_id_hash)
    }
}

/// Credential information from enumeration
///
/// Returned when enumerating credentials for a specific RP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialInfo {
    /// User information
    pub user: User,

    /// Credential ID descriptor
    pub credential_id: PublicKeyCredentialDescriptor,

    /// Public key in COSE_Key format (raw CBOR bytes)
    ///
    /// Only present in first credential from enumerateCredentialsBegin.
    /// Subsequent calls to enumerateCredentialsGetNextCredential omit this field.
    pub public_key: Option<Vec<u8>>,

    /// Credential protection policy
    ///
    /// Values:
    /// - 0x01: userVerificationOptional
    /// - 0x02: userVerificationOptionalWithCredentialIdList
    /// - 0x03: userVerificationRequired
    pub cred_protect: Option<u8>,

    /// Large blob encryption key (32 bytes)
    pub large_blob_key: Option<Vec<u8>>,

    /// Whether credential is third-party payment enabled
    ///
    /// Only present if authenticator supports thirdPartyPayment extension.
    pub third_party_payment: Option<bool>,
}

impl CredentialInfo {
    /// Parse from CBOR response components
    fn from_parser(parser: &MapParser) -> Result<Self> {
        // 0x06: user (required) - Use soft_fido2_ctap::types::User which has correct serde attributes
        let user: User = parser.get(0x06).map_err(|_| Error::Other)?;

        // 0x07: credentialID (required)
        let cred_id_value: Value = parser.get(0x07).map_err(|_| Error::Other)?;
        let credential_id = parse_credential_descriptor(&cred_id_value)?;

        // 0x08: publicKey (optional)
        let public_key = parser.get_opt::<Vec<u8>>(0x08).ok().flatten();

        // 0x0A: credProtect (optional)
        let cred_protect = parser.get_opt::<u8>(0x0A).ok().flatten();

        // 0x0B: largeBlobKey (optional)
        let large_blob_key = if parser.get_raw(0x0B).is_some() {
            parser.get_bytes(0x0B).ok()
        } else {
            None
        };

        // 0x0C: thirdPartyPayment (optional)
        let third_party_payment = parser.get_opt::<bool>(0x0C).ok().flatten();

        Ok(Self {
            user,
            credential_id,
            public_key,
            cred_protect,
            large_blob_key,
            third_party_payment,
        })
    }
}

/// Response from enumerateCredentialsBegin (0x04)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialEnumerationBeginResponse {
    /// First credential information
    pub credential: CredentialInfo,

    /// Total number of credentials for this RP
    pub total_credentials: u32,
}

impl CredentialEnumerationBeginResponse {
    /// Parse from CBOR response bytes
    ///
    /// Expected format:
    /// ```cbor
    /// {
    ///   0x06: user,
    ///   0x07: credentialID,
    ///   0x08: publicKey (optional),
    ///   0x09: totalCredentials,
    ///   0x0A: credProtect (optional),
    ///   0x0B: largeBlobKey (optional),
    ///   0x0C: thirdPartyPayment (optional)
    /// }
    /// ```
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let parser = MapParser::from_bytes(bytes).map_err(|_| Error::Other)?;

        let credential = CredentialInfo::from_parser(&parser)?;
        let total: i32 = parser.get(0x09).map_err(|_| Error::Other)?;

        Ok(Self {
            credential,
            total_credentials: total as u32,
        })
    }
}

/// Response from enumerateCredentialsGetNextCredential (0x05)
pub type CredentialEnumerationNextResponse = CredentialInfo;

impl CredentialEnumerationNextResponse {
    /// Parse from CBOR response bytes
    ///
    /// Expected format (same as begin but without totalCredentials):
    /// ```cbor
    /// {
    ///   0x06: user,
    ///   0x07: credentialID,
    ///   0x0A: credProtect (optional),
    ///   0x0B: largeBlobKey (optional),
    ///   0x0C: thirdPartyPayment (optional)
    /// }
    /// ```
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let parser = MapParser::from_bytes(bytes).map_err(|_| Error::Other)?;
        CredentialInfo::from_parser(&parser)
    }
}

/// Helper: Parse PublicKeyCredentialDescriptor from CBOR Value
///
/// Expected format:
/// ```cbor
/// {
///   "id": credential_id (bytes),
///   "type": "public-key" (text)
/// }
/// ```
fn parse_credential_descriptor(value: &Value) -> Result<PublicKeyCredentialDescriptor> {
    let Value::Map(map) = value else {
        return Err(Error::Other);
    };

    let mut id = None;
    let mut cred_type = None;

    for (k, v) in map {
        if let Value::Text(key) = k {
            match key.as_str() {
                "id" => {
                    if let Value::Bytes(bytes) = v {
                        id = Some(bytes.clone());
                    }
                }
                "type" => {
                    if let Value::Text(t) = v {
                        cred_type = Some(t.clone());
                    }
                }
                _ => {}
            }
        }
    }

    let id = id.ok_or(Error::Other)?;
    let r#type = cred_type.ok_or(Error::Other)?;

    Ok(PublicKeyCredentialDescriptor {
        id,
        r#type,
        transports: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_metadata_parsing() {
        // CBOR: {0x01: 10, 0x02: 50}
        let cbor = vec![0xa2, 0x01, 0x0a, 0x02, 0x18, 0x32];
        let metadata = CredentialsMetadata::from_cbor(&cbor).unwrap();
        assert_eq!(metadata.existing_resident_credentials_count, 10);
        assert_eq!(
            metadata.max_possible_remaining_resident_credentials_count,
            50
        );
    }

    #[test]
    fn test_rp_info_parsing_with_name() {
        let rp_value = Value::Map(vec![
            (
                Value::Text("id".to_string()),
                Value::Text("example.com".to_string()),
            ),
            (
                Value::Text("name".to_string()),
                Value::Text("Example".to_string()),
            ),
        ]);
        let hash = [1u8; 32];

        let rp = RpInfo::from_cbor_value(&rp_value, hash).unwrap();
        assert_eq!(rp.id, "example.com");
        assert_eq!(rp.name, Some("Example".to_string()));
        assert_eq!(rp.rp_id_hash, hash);
    }

    #[test]
    fn test_rp_info_parsing_without_name() {
        let rp_value = Value::Map(vec![(
            Value::Text("id".to_string()),
            Value::Text("example.com".to_string()),
        )]);
        let hash = [2u8; 32];

        let rp = RpInfo::from_cbor_value(&rp_value, hash).unwrap();
        assert_eq!(rp.id, "example.com");
        assert_eq!(rp.name, None);
    }

    #[test]
    fn test_parse_credential_descriptor() {
        let desc_value = Value::Map(vec![
            (Value::Text("id".to_string()), Value::Bytes(vec![1, 2, 3])),
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
        ]);

        let desc = parse_credential_descriptor(&desc_value).unwrap();
        assert_eq!(desc.id, vec![1, 2, 3]);
        assert_eq!(desc.r#type, "public-key");
    }
}
