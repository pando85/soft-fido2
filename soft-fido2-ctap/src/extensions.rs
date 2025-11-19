//! CTAP Extension Processing
//!
//! Implements CTAP extensions for enhanced functionality:
//! - credProtect: Credential protection policy
//! - hmac-secret: HMAC-based secrets for credentials
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-extensions>

use crate::status::Result;
use serde::{Deserialize, Serialize};

/// Extension identifiers
pub mod ext_ids {
    pub const CRED_PROTECT: &str = "credProtect";
    pub const HMAC_SECRET: &str = "hmac-secret";
    pub const CRED_BLOB: &str = "credBlob";
    pub const LARGE_BLOB_KEY: &str = "largeBlobKey";
    pub const MIN_PIN_LENGTH: &str = "minPinLength";
}

/// Credential protection policy levels
///
/// Defines how a credential should be protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CredProtectPolicy {
    /// User verification optional (UV not required)
    UserVerificationOptional = 0x01,

    /// User verification optional with credential ID list
    /// UV required when credential is not in allow list
    UserVerificationOptionalWithCredentialIdList = 0x02,

    /// User verification required (always require UV)
    UserVerificationRequired = 0x03,
}

impl CredProtectPolicy {
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

    /// Get default policy
    pub fn default_policy() -> Self {
        Self::UserVerificationOptional
    }
}

impl Default for CredProtectPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

/// Extension input during makeCredential
#[derive(Debug, Clone, Default)]
pub struct MakeCredentialExtensions {
    /// Credential protection policy
    pub cred_protect: Option<CredProtectPolicy>,

    /// Enable hmac-secret extension
    pub hmac_secret: Option<bool>,

    /// Credential blob (opaque data)
    pub cred_blob: Option<Vec<u8>>,

    /// Request large blob key
    pub large_blob_key: Option<bool>,

    /// Minimum PIN length
    pub min_pin_length: Option<usize>,
}

impl MakeCredentialExtensions {
    /// Create new empty extensions
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse extensions from CBOR value
    pub fn from_cbor(value: &crate::cbor::Value) -> Result<Self> {
        let mut exts = Self::new();

        let map = match value {
            crate::cbor::Value::Map(m) => m,
            _ => return Ok(exts), // No extensions is valid
        };

        for (key, val) in map {
            if let crate::cbor::Value::Text(ext_name) = key {
                match ext_name.as_str() {
                    ext_ids::CRED_PROTECT => {
                        if let crate::cbor::Value::Integer(i) = val {
                            let policy_val: i128 = *i;
                            if let Ok(policy_u8) = u8::try_from(policy_val) {
                                exts.cred_protect = CredProtectPolicy::from_u8(policy_u8);
                            }
                        }
                    }
                    ext_ids::HMAC_SECRET => {
                        if let crate::cbor::Value::Bool(b) = val {
                            exts.hmac_secret = Some(*b);
                        }
                    }
                    ext_ids::CRED_BLOB => {
                        if let crate::cbor::Value::Bytes(b) = val {
                            exts.cred_blob = Some(b.clone());
                        }
                    }
                    ext_ids::LARGE_BLOB_KEY => {
                        if let crate::cbor::Value::Bool(b) = val {
                            exts.large_blob_key = Some(*b);
                        }
                    }
                    ext_ids::MIN_PIN_LENGTH => {
                        if let crate::cbor::Value::Bool(b) = val
                            && *b
                        {
                            // Request to include min PIN length in response
                            exts.min_pin_length = Some(4); // Will be filled by authenticator
                        }
                    }
                    _ => {} // Ignore unknown extensions
                }
            }
        }

        Ok(exts)
    }

    /// Build extension outputs for makeCredential response
    pub fn build_outputs(
        &self,
        actual_min_pin_length: Option<usize>,
    ) -> Option<crate::cbor::Value> {
        let mut outputs = Vec::new();

        // credProtect - return the policy that was set
        if let Some(policy) = self.cred_protect {
            outputs.push((
                crate::cbor::Value::Text(ext_ids::CRED_PROTECT.to_string()),
                crate::cbor::Value::Integer(policy.to_u8().into()),
            ));
        }

        // hmac-secret - return true if enabled
        if let Some(true) = self.hmac_secret {
            outputs.push((
                crate::cbor::Value::Text(ext_ids::HMAC_SECRET.to_string()),
                crate::cbor::Value::Bool(true),
            ));
        }

        // credBlob - return true if credential blob was stored
        if self.cred_blob.is_some() {
            outputs.push((
                crate::cbor::Value::Text(ext_ids::CRED_BLOB.to_string()),
                crate::cbor::Value::Bool(true),
            ));
        }

        // largeBlobKey - return the generated key (32 random bytes)
        if let Some(true) = self.large_blob_key {
            // Generate random 32-byte key
            use rand::RngCore;
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);

            outputs.push((
                crate::cbor::Value::Text(ext_ids::LARGE_BLOB_KEY.to_string()),
                crate::cbor::Value::Bytes(key),
            ));
        }

        // minPinLength - return actual minimum PIN length
        if self.min_pin_length.is_some()
            && let Some(len) = actual_min_pin_length
        {
            outputs.push((
                crate::cbor::Value::Text(ext_ids::MIN_PIN_LENGTH.to_string()),
                crate::cbor::Value::Integer((len as i32).into()),
            ));
        }

        if outputs.is_empty() {
            None
        } else {
            Some(crate::cbor::Value::Map(outputs))
        }
    }
}

/// Extension input during getAssertion
#[derive(Debug, Clone, Default)]
pub struct GetAssertionExtensions {
    /// HMAC-secret extension inputs
    pub hmac_secret: Option<HmacSecretInput>,

    /// Request credential blob
    pub get_cred_blob: Option<bool>,

    /// Large blob read/write
    pub large_blob_key: Option<bool>,
}

/// HMAC-secret extension input
#[derive(Debug, Clone)]
pub struct HmacSecretInput {
    /// Key agreement (COSE_Key)
    pub key_agreement: Vec<u8>,

    /// Salt (encrypted)
    pub salt_enc: Vec<u8>,

    /// Salt authentication
    pub salt_auth: Vec<u8>,

    /// PIN/UV auth protocol version
    pub pin_uv_auth_protocol: u8,
}

impl GetAssertionExtensions {
    /// Create new empty extensions
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse extensions from CBOR value
    pub fn from_cbor(_value: &crate::cbor::Value) -> Result<Self> {
        // TODO: Implement hmac-secret parsing
        // For now, return empty extensions
        Ok(Self::new())
    }

    /// Build extension outputs for getAssertion response
    pub fn build_outputs(&self) -> Option<crate::cbor::Value> {
        // TODO: Implement extension outputs for getAssertion
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cred_protect_policy() {
        assert_eq!(CredProtectPolicy::UserVerificationOptional.to_u8(), 0x01);
        assert_eq!(
            CredProtectPolicy::from_u8(0x01),
            Some(CredProtectPolicy::UserVerificationOptional)
        );
        assert_eq!(CredProtectPolicy::from_u8(0xFF), None);
    }

    #[test]
    fn test_cred_protect_default() {
        let policy = CredProtectPolicy::default();
        assert_eq!(policy, CredProtectPolicy::UserVerificationOptional);
    }

    #[test]
    fn test_parse_cred_protect_extension() {
        let ext_map = crate::cbor::Value::Map(vec![(
            crate::cbor::Value::Text("credProtect".to_string()),
            crate::cbor::Value::Integer(0x03.into()),
        )]);

        let exts = MakeCredentialExtensions::from_cbor(&ext_map).unwrap();
        assert_eq!(
            exts.cred_protect,
            Some(CredProtectPolicy::UserVerificationRequired)
        );
    }

    #[test]
    fn test_parse_hmac_secret_extension() {
        let ext_map = crate::cbor::Value::Map(vec![(
            crate::cbor::Value::Text("hmac-secret".to_string()),
            crate::cbor::Value::Bool(true),
        )]);

        let exts = MakeCredentialExtensions::from_cbor(&ext_map).unwrap();
        assert_eq!(exts.hmac_secret, Some(true));
    }

    #[test]
    fn test_parse_multiple_extensions() {
        let ext_map = crate::cbor::Value::Map(vec![
            (
                crate::cbor::Value::Text("credProtect".to_string()),
                crate::cbor::Value::Integer(0x02.into()),
            ),
            (
                crate::cbor::Value::Text("hmac-secret".to_string()),
                crate::cbor::Value::Bool(true),
            ),
        ]);

        let exts = MakeCredentialExtensions::from_cbor(&ext_map).unwrap();
        assert_eq!(
            exts.cred_protect,
            Some(CredProtectPolicy::UserVerificationOptionalWithCredentialIdList)
        );
        assert_eq!(exts.hmac_secret, Some(true));
    }

    #[test]
    fn test_build_extension_outputs() {
        let mut exts = MakeCredentialExtensions::new();
        exts.cred_protect = Some(CredProtectPolicy::UserVerificationRequired);
        exts.hmac_secret = Some(true);

        let outputs = exts.build_outputs(Some(6));
        assert!(outputs.is_some());

        if let Some(crate::cbor::Value::Map(m)) = outputs {
            assert!(m.len() >= 2);

            // Check credProtect is present
            let has_cred_protect = m.iter().any(|(k, v)| {
                if let (crate::cbor::Value::Text(name), crate::cbor::Value::Integer(val)) = (k, v) {
                    name == "credProtect" && {
                        let i: i128 = *val;
                        i == 0x03
                    }
                } else {
                    false
                }
            });
            assert!(has_cred_protect);

            // Check hmac-secret is present
            let has_hmac = m.iter().any(|(k, v)| {
                if let (crate::cbor::Value::Text(name), crate::cbor::Value::Bool(b)) = (k, v) {
                    name == "hmac-secret" && *b
                } else {
                    false
                }
            });
            assert!(has_hmac);
        } else {
            panic!("Expected Map output");
        }
    }

    #[test]
    fn test_empty_extensions() {
        let exts = MakeCredentialExtensions::new();
        let outputs = exts.build_outputs(None);
        assert!(outputs.is_none());
    }

    #[test]
    fn test_parse_empty_extensions() {
        let empty = crate::cbor::Value::Map(vec![]);
        let exts = MakeCredentialExtensions::from_cbor(&empty).unwrap();
        assert!(exts.cred_protect.is_none());
        assert!(exts.hmac_secret.is_none());
    }

    #[test]
    fn test_large_blob_key_generation() {
        let mut exts = MakeCredentialExtensions::new();
        exts.large_blob_key = Some(true);

        let outputs = exts.build_outputs(None);
        assert!(outputs.is_some());

        if let Some(crate::cbor::Value::Map(m)) = outputs {
            let key = m.iter().find_map(|(k, v)| {
                if let (crate::cbor::Value::Text(name), crate::cbor::Value::Bytes(bytes)) = (k, v)
                    && name == "largeBlobKey"
                {
                    return Some(bytes);
                }
                None
            });

            assert!(key.is_some());
            assert_eq!(key.unwrap().len(), 32);
        }
    }
}
