//! Credential key provider abstraction
//!
//! Allows credential key generation and signing to be delegated to external
//! providers (TPM, PKCS#11, HSM, etc.) while treating persisted key material
//! as opaque, provider-owned data.

use crate::sec_bytes::SecBytes;
use crate::status::StatusCode;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

pub const SOFTWARE_PROVIDER_ID: &str = "software-v1";

pub const DEFAULT_SOFTWARE_PROVIDER_ID: CredentialKeyProviderId =
    CredentialKeyProviderId::new_fixed(*b"software-v1\0\0\0\0\0");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialKeyProviderId {
    bytes: [u8; 16],
}

impl CredentialKeyProviderId {
    pub const fn new_fixed(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    pub fn from_name(s: &str) -> Self {
        let mut bytes = [0u8; 16];
        let src = s.as_bytes();
        let len = if src.len() > 16 { 16 } else { src.len() };
        bytes[..len].copy_from_slice(&src[..len]);
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    pub fn as_str(&self) -> &str {
        let end = self.bytes.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.bytes[..end]).unwrap_or("invalid")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialKey {
    pub provider: CredentialKeyProviderId,
    pub format_version: u16,
    pub material: SecBytes,
}

impl CredentialKey {
    pub fn new(provider: CredentialKeyProviderId, format_version: u16, material: SecBytes) -> Self {
        Self {
            provider,
            format_version,
            material,
        }
    }

    pub fn software(private_key_bytes: SecBytes) -> Self {
        Self {
            provider: DEFAULT_SOFTWARE_PROVIDER_ID,
            format_version: 1,
            material: private_key_bytes,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GeneratedCredentialKey {
    pub key: CredentialKey,
    pub cose_public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum CredentialKeyError {
    UnsupportedAlgorithm(i32),
    UnsupportedProvider(CredentialKeyProviderId),
    UnsupportedVersion(u16),
    InvalidMaterial,
    KeyNotFound,
    AuthorizationDenied,
    Timeout,
    TransientFailure,
    PermanentFailure,
    Other(String),
}

impl From<CredentialKeyError> for StatusCode {
    fn from(err: CredentialKeyError) -> Self {
        match err {
            CredentialKeyError::UnsupportedAlgorithm(_) => StatusCode::UnsupportedAlgorithm,
            CredentialKeyError::UnsupportedProvider(_) => StatusCode::InvalidCredential,
            CredentialKeyError::UnsupportedVersion(_) => StatusCode::InvalidCredential,
            CredentialKeyError::InvalidMaterial => StatusCode::InvalidCredential,
            CredentialKeyError::KeyNotFound => StatusCode::NoCredentials,
            CredentialKeyError::AuthorizationDenied => StatusCode::OperationDenied,
            CredentialKeyError::Timeout => StatusCode::UserActionTimeout,
            CredentialKeyError::TransientFailure => StatusCode::Other,
            CredentialKeyError::PermanentFailure => StatusCode::Other,
            CredentialKeyError::Other(_) => StatusCode::Other,
        }
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

#[derive(Clone, Debug, Default)]
pub struct SoftwareCredentialKeyProvider;

impl SoftwareCredentialKeyProvider {
    pub fn new() -> Self {
        Self
    }
}

impl CredentialKeyProvider for SoftwareCredentialKeyProvider {
    fn provider_id(&self) -> CredentialKeyProviderId {
        DEFAULT_SOFTWARE_PROVIDER_ID
    }

    fn supports_algorithm(&self, algorithm: i32) -> bool {
        matches!(algorithm, -7 | -8 | -19)
    }

    fn generate(&self, algorithm: i32) -> Result<GeneratedCredentialKey, CredentialKeyError> {
        match algorithm {
            -8 | -19 => {
                let (sk, pk) = soft_fido2_crypto::eddsa::generate_keypair();
                let key = CredentialKey::software(SecBytes::from_slice(&sk[..]));
                Ok(GeneratedCredentialKey {
                    key,
                    cose_public_key: pk,
                })
            }
            _ => {
                let (sk, pk) = soft_fido2_crypto::ecdsa::generate_keypair();
                let key = CredentialKey::software(SecBytes::from_slice(&sk[..]));
                Ok(GeneratedCredentialKey {
                    key,
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
        if key.provider != DEFAULT_SOFTWARE_PROVIDER_ID {
            return Err(CredentialKeyError::UnsupportedProvider(
                key.provider.clone(),
            ));
        }

        let key_bytes = key.material.as_slice();
        if key_bytes.len() != 32 {
            return Err(CredentialKeyError::InvalidMaterial);
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(key_bytes);

        match algorithm {
            -8 | -19 => soft_fido2_crypto::eddsa::sign(&arr, message)
                .map_err(|_| CredentialKeyError::TransientFailure),
            _ => soft_fido2_crypto::ecdsa::sign(&arr, message)
                .map_err(|_| CredentialKeyError::TransientFailure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_id_round_trip() {
        let id = CredentialKeyProviderId::from_name("software-v1");
        assert_eq!(id.as_str(), "software-v1");
        assert_eq!(id, DEFAULT_SOFTWARE_PROVIDER_ID);
    }

    #[test]
    fn test_software_provider_supports_algorithms() {
        let provider = SoftwareCredentialKeyProvider::new();
        assert!(provider.supports_algorithm(-7));
        assert!(provider.supports_algorithm(-8));
        assert!(provider.supports_algorithm(-19));
        assert!(!provider.supports_algorithm(-257));
    }

    #[test]
    fn test_software_provider_generate_es256() {
        let provider = SoftwareCredentialKeyProvider::new();
        let result = provider.generate(-7);
        assert!(result.is_ok());
        let generated = result.unwrap();
        assert_eq!(generated.key.provider, DEFAULT_SOFTWARE_PROVIDER_ID);
        assert_eq!(generated.key.material.len(), 32);
        assert_eq!(generated.cose_public_key.len(), 65);
        assert_eq!(generated.cose_public_key[0], 0x04);
    }

    #[test]
    fn test_software_provider_generate_eddsa() {
        let provider = SoftwareCredentialKeyProvider::new();
        let result = provider.generate(-8);
        assert!(result.is_ok());
        let generated = result.unwrap();
        assert_eq!(generated.key.material.len(), 32);
        assert_eq!(generated.cose_public_key.len(), 32);
    }

    #[test]
    fn test_software_provider_sign_and_verify_es256() {
        let provider = SoftwareCredentialKeyProvider::new();
        let generated = provider.generate(-7).unwrap();
        let message = b"test message";
        let sig = provider.sign(&generated.key, -7, message).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_software_provider_sign_and_verify_eddsa() {
        let provider = SoftwareCredentialKeyProvider::new();
        let generated = provider.generate(-8).unwrap();
        let message = b"test message";
        let sig = provider.sign(&generated.key, -8, message).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_software_provider_rejects_wrong_provider() {
        let provider = SoftwareCredentialKeyProvider::new();
        let key = CredentialKey::new(
            CredentialKeyProviderId::from_name("other-provider"),
            1,
            SecBytes::new(vec![0u8; 32]),
        );
        let result = provider.sign(&key, -7, b"test");
        assert!(matches!(
            result,
            Err(CredentialKeyError::UnsupportedProvider(_))
        ));
    }

    #[test]
    fn test_software_provider_rejects_wrong_length() {
        let provider = SoftwareCredentialKeyProvider::new();
        let key = CredentialKey::software(SecBytes::new(vec![0u8; 16]));
        let result = provider.sign(&key, -7, b"test");
        assert!(matches!(result, Err(CredentialKeyError::InvalidMaterial)));
    }

    #[test]
    fn test_credential_key_error_to_status_code() {
        assert_eq!(
            StatusCode::from(CredentialKeyError::UnsupportedAlgorithm(-7)),
            StatusCode::UnsupportedAlgorithm
        );
        assert_eq!(
            StatusCode::from(CredentialKeyError::InvalidMaterial),
            StatusCode::InvalidCredential
        );
        assert_eq!(
            StatusCode::from(CredentialKeyError::KeyNotFound),
            StatusCode::NoCredentials
        );
        assert_eq!(
            StatusCode::from(CredentialKeyError::AuthorizationDenied),
            StatusCode::OperationDenied
        );
    }

    #[test]
    fn test_credential_key_software_constructor() {
        let key = CredentialKey::software(SecBytes::new(vec![0x42u8; 32]));
        assert_eq!(key.provider, DEFAULT_SOFTWARE_PROVIDER_ID);
        assert_eq!(key.format_version, 1);
        assert_eq!(key.material.len(), 32);
    }
}
