//! Credential key provider abstraction
//!
//! Allows credential signing keys to be managed by external providers (TPM, HSM, etc.)
//! rather than requiring exportable private key bytes.

use crate::sec_bytes::SecBytes;

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

pub const SOFTWARE_PROVIDER_ID: u32 = 0;
pub const SOFTWARE_FORMAT_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialKeyProviderId(pub u32);

impl CredentialKeyProviderId {
    pub fn software() -> Self {
        Self(SOFTWARE_PROVIDER_ID)
    }

    pub fn is_software(&self) -> bool {
        self.0 == SOFTWARE_PROVIDER_ID
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialKey {
    pub provider: CredentialKeyProviderId,
    pub format_version: u16,
    #[serde(with = "serde_bytes")]
    pub material: Vec<u8>,
}

impl CredentialKey {
    pub fn software(material: Vec<u8>) -> Self {
        Self {
            provider: CredentialKeyProviderId::software(),
            format_version: SOFTWARE_FORMAT_VERSION,
            material,
        }
    }

    pub fn from_sec_bytes(key_bytes: &SecBytes) -> Self {
        Self::software(key_bytes.as_slice().to_vec())
    }

    pub fn to_sec_bytes(&self) -> SecBytes {
        SecBytes::from_slice(&self.material)
    }

    pub fn is_software(&self) -> bool {
        self.provider.is_software()
    }
}

#[derive(Debug)]
pub struct GeneratedCredentialKey {
    pub key: CredentialKey,
    pub cose_public_key: Vec<u8>,
}

#[derive(Debug)]
pub enum CredentialKeyError {
    UnsupportedAlgorithm,
    UnsupportedProvider,
    UnsupportedFormatVersion,
    InvalidKeyMaterial,
    KeyNotFound,
    AuthorizationDenied,
    Timeout,
    TransientFailure,
    PermanentFailure,
    CryptoError(soft_fido2_crypto::CryptoError),
}

impl From<soft_fido2_crypto::CryptoError> for CredentialKeyError {
    fn from(e: soft_fido2_crypto::CryptoError) -> Self {
        Self::CryptoError(e)
    }
}

pub trait CredentialKeyProvider: Send + Sync {
    fn provider_id(&self) -> CredentialKeyProviderId;

    fn supports_algorithm(&self, algorithm: i32) -> bool;

    fn generate(&self, algorithm: i32) -> Result<GeneratedCredentialKey, CredentialKeyError>;

    fn sign(
        &self,
        key: &CredentialKey,
        algorithm: i32,
        message: &[u8],
    ) -> Result<Vec<u8>, CredentialKeyError>;

    fn delete(&self, _key: &CredentialKey) -> Result<(), CredentialKeyError> {
        Ok(())
    }
}

pub struct SoftwareCredentialKeyProvider;

impl SoftwareCredentialKeyProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SoftwareCredentialKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialKeyProvider for SoftwareCredentialKeyProvider {
    fn provider_id(&self) -> CredentialKeyProviderId {
        CredentialKeyProviderId::software()
    }

    fn supports_algorithm(&self, algorithm: i32) -> bool {
        matches!(algorithm, -7 | -8 | -19)
    }

    fn generate(&self, algorithm: i32) -> Result<GeneratedCredentialKey, CredentialKeyError> {
        match algorithm {
            -8 | -19 => {
                let (sk, pk) = soft_fido2_crypto::eddsa::generate_keypair();
                Ok(GeneratedCredentialKey {
                    key: CredentialKey::software(sk.to_vec()),
                    cose_public_key: pk,
                })
            }
            _ => {
                let (sk, pk) = soft_fido2_crypto::ecdsa::generate_keypair();
                Ok(GeneratedCredentialKey {
                    key: CredentialKey::software(sk.to_vec()),
                    cose_public_key: pk,
                })
            }
        }
    }

    fn sign(
        &self,
        key: &CredentialKey,
        algorithm: i32,
        message: &[u8],
    ) -> Result<Vec<u8>, CredentialKeyError> {
        if !key.provider.is_software() {
            return Err(CredentialKeyError::UnsupportedProvider);
        }

        let key_bytes = &key.material;
        if key_bytes.len() != 32 {
            return Err(CredentialKeyError::InvalidKeyMaterial);
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(key_bytes);
        let priv_key = zeroize::Zeroizing::new(arr);

        match algorithm {
            -8 | -19 => soft_fido2_crypto::eddsa::sign(&priv_key, message)
                .map_err(CredentialKeyError::CryptoError),
            _ => soft_fido2_crypto::ecdsa::sign(&priv_key, message)
                .map_err(CredentialKeyError::CryptoError),
        }
    }
}

impl From<CredentialKeyError> for crate::status::StatusCode {
    fn from(err: CredentialKeyError) -> Self {
        match err {
            CredentialKeyError::UnsupportedAlgorithm => {
                crate::status::StatusCode::UnsupportedAlgorithm
            }
            CredentialKeyError::UnsupportedProvider => crate::status::StatusCode::InvalidCredential,
            CredentialKeyError::UnsupportedFormatVersion => {
                crate::status::StatusCode::InvalidCredential
            }
            CredentialKeyError::InvalidKeyMaterial => crate::status::StatusCode::InvalidCredential,
            CredentialKeyError::KeyNotFound => crate::status::StatusCode::NoCredentials,
            CredentialKeyError::AuthorizationDenied => crate::status::StatusCode::OperationDenied,
            CredentialKeyError::Timeout => crate::status::StatusCode::UserActionTimeout,
            CredentialKeyError::TransientFailure => crate::status::StatusCode::Other,
            CredentialKeyError::PermanentFailure => crate::status::StatusCode::Other,
            CredentialKeyError::CryptoError(_) => crate::status::StatusCode::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_provider_es256() {
        let provider = SoftwareCredentialKeyProvider::new();
        assert!(provider.supports_algorithm(-7));
        assert!(provider.supports_algorithm(-8));

        let generated = provider.generate(-7).unwrap();
        assert_eq!(generated.key.material.len(), 32);
        assert!(generated.key.is_software());
        assert_eq!(generated.cose_public_key.len(), 65);

        let message = b"test message";
        let sig = provider.sign(&generated.key, -7, message).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_software_provider_eddsa() {
        let provider = SoftwareCredentialKeyProvider::new();
        let generated = provider.generate(-8).unwrap();
        assert_eq!(generated.key.material.len(), 32);
        assert_eq!(generated.cose_public_key.len(), 32);

        let message = b"test message";
        let sig = provider.sign(&generated.key, -8, message).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_provider_id_mismatch() {
        let provider = SoftwareCredentialKeyProvider::new();
        let foreign_key = CredentialKey {
            provider: CredentialKeyProviderId(999),
            format_version: 1,
            material: vec![0u8; 32],
        };
        let result = provider.sign(&foreign_key, -7, b"test");
        assert!(matches!(
            result,
            Err(CredentialKeyError::UnsupportedProvider)
        ));
    }

    #[test]
    fn test_credential_key_software() {
        let key = CredentialKey::software(vec![1, 2, 3]);
        assert!(key.is_software());
        assert_eq!(key.provider, CredentialKeyProviderId::software());
    }

    #[test]
    fn test_credential_key_serde_roundtrip() {
        let key = CredentialKey {
            provider: CredentialKeyProviderId(42),
            format_version: 3,
            material: vec![10, 20, 30, 40],
        };
        let mut buf = Vec::new();
        crate::cbor::into_writer(&key, &mut buf).unwrap();
        let restored: CredentialKey = crate::cbor::decode(&buf).unwrap();
        assert_eq!(restored.provider.0, 42);
        assert_eq!(restored.format_version, 3);
        assert_eq!(restored.material, vec![10, 20, 30, 40]);
    }
}
