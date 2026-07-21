//! Credential key provider abstraction
//!
//! Allows credential signing keys to be generated and used by external providers
//! (TPM, PKCS#11, secure elements, etc.) without exposing private key material
//! to the CTAP core.

use crate::SecBytes;
use crate::status::StatusCode;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Software provider identifier
pub const SOFTWARE_PROVIDER_ID: &[u8; 11] = b"software-v1";

/// Maximum provider ID length
pub const MAX_PROVIDER_ID_LENGTH: usize = 64;

/// Stable provider identifier used in serialized credential keys
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CredentialKeyProviderId(Vec<u8>);

impl CredentialKeyProviderId {
    pub fn new(id: &[u8]) -> Self {
        debug_assert!(
            id.len() <= MAX_PROVIDER_ID_LENGTH,
            "provider ID exceeds MAX_PROVIDER_ID_LENGTH ({MAX_PROVIDER_ID_LENGTH} bytes)"
        );
        Self(id.to_vec())
    }

    pub fn software() -> Self {
        Self(SOFTWARE_PROVIDER_ID.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_software(&self) -> bool {
        self.0 == SOFTWARE_PROVIDER_ID.as_slice()
    }
}

impl Serialize for CredentialKeyProviderId {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for CredentialKeyProviderId {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        if bytes.len() > MAX_PROVIDER_ID_LENGTH {
            return Err(serde::de::Error::custom(alloc::format!(
                "provider ID exceeds MAX_PROVIDER_ID_LENGTH ({} bytes)",
                MAX_PROVIDER_ID_LENGTH
            )));
        }
        Ok(Self(bytes))
    }
}

/// Opaque credential key record owned by a provider
///
/// The CTAP core treats this as opaque data. It never inspects or interprets
/// the `material` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialKey {
    /// Stable provider identifier
    pub provider: CredentialKeyProviderId,

    /// Version of the provider-owned opaque encoding
    pub format_version: u16,

    /// Opaque provider material
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

    pub fn software(material: SecBytes) -> Self {
        Self {
            provider: CredentialKeyProviderId::software(),
            format_version: 1,
            material,
        }
    }
}

impl Serialize for CredentialKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("provider", &self.provider)?;
        map.serialize_entry("format_version", &self.format_version)?;
        map.serialize_entry(
            "material",
            &serde_bytes::Bytes::new(self.material.as_slice()),
        )?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for CredentialKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = crate::cbor::Value::deserialize(deserializer)?;
        let map = match value {
            crate::cbor::Value::Map(m) => m,
            _ => return Err(serde::de::Error::custom("expected map")),
        };

        let mut provider: Option<CredentialKeyProviderId> = None;
        let mut format_version: Option<u16> = None;
        let mut material: Option<SecBytes> = None;

        for (k, v) in map {
            let key_str = match k {
                crate::cbor::Value::Text(s) => s,
                _ => continue,
            };
            match key_str.as_str() {
                "provider" => {
                    let p: CredentialKeyProviderId =
                        crate::cbor::from_value(&v).map_err(serde::de::Error::custom)?;
                    provider = Some(p);
                }
                "format_version" => {
                    if let crate::cbor::Value::Integer(i) = v {
                        if i < 0 || i > u16::MAX as i128 {
                            return Err(serde::de::Error::custom(
                                "format_version out of range for u16",
                            ));
                        }
                        format_version = Some(i as u16);
                    }
                }
                "material" => {
                    if let crate::cbor::Value::Bytes(b) = v {
                        material = Some(SecBytes::from_slice(&b));
                    }
                }
                _ => {}
            }
        }

        Ok(CredentialKey {
            provider: provider.ok_or_else(|| serde::de::Error::missing_field("provider"))?,
            format_version: format_version
                .ok_or_else(|| serde::de::Error::missing_field("format_version"))?,
            material: material.ok_or_else(|| serde::de::Error::missing_field("material"))?,
        })
    }
}

/// Result of key generation by a provider
#[derive(Debug, PartialEq, Eq)]
pub struct GeneratedCredentialKey {
    /// The opaque credential key
    pub key: CredentialKey,

    /// COSE-encoded public key bytes
    pub cose_public_key: Vec<u8>,
}

/// Errors from credential key provider operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKeyError {
    UnsupportedAlgorithm,
    UnsupportedProvider,
    UnsupportedFormatVersion,
    InvalidKeyMaterial,
    KeyNotFound,
    AuthorizationDenied,
    Timeout,
    TransientFailure(String),
    PermanentFailure(String),
}

impl From<CredentialKeyError> for StatusCode {
    fn from(err: CredentialKeyError) -> Self {
        match err {
            CredentialKeyError::UnsupportedAlgorithm => StatusCode::UnsupportedAlgorithm,
            CredentialKeyError::UnsupportedProvider => StatusCode::InvalidCredential,
            CredentialKeyError::UnsupportedFormatVersion => StatusCode::InvalidCredential,
            CredentialKeyError::InvalidKeyMaterial => StatusCode::InvalidCredential,
            CredentialKeyError::KeyNotFound => StatusCode::NoCredentials,
            CredentialKeyError::AuthorizationDenied => StatusCode::OperationDenied,
            CredentialKeyError::Timeout => StatusCode::UserActionTimeout,
            CredentialKeyError::TransientFailure(_) => StatusCode::Other,
            CredentialKeyError::PermanentFailure(_) => StatusCode::Other,
        }
    }
}

/// Trait for credential key providers
///
/// Providers own key generation and signing operations. The CTAP core
/// delegates these operations to the configured provider and treats
/// key material as opaque.
pub trait CredentialKeyProvider {
    /// Stable ID used in serialized CredentialKey values
    fn provider_id(&self) -> CredentialKeyProviderId;

    /// Whether this provider can generate and sign with the COSE algorithm
    fn supports_algorithm(&self, algorithm: i32) -> bool;

    /// Generate a new credential key and its COSE public key
    fn generate(
        &self,
        algorithm: i32,
    ) -> core::result::Result<GeneratedCredentialKey, CredentialKeyError>;

    /// Sign the exact WebAuthn message supplied by the CTAP implementation
    fn sign(
        &self,
        key: &CredentialKey,
        algorithm: i32,
        message: &[u8],
    ) -> core::result::Result<Vec<u8>, CredentialKeyError>;

    /// Optional lifecycle hook for providers that allocate persistent external objects
    fn delete(&self, _key: &CredentialKey) -> core::result::Result<(), CredentialKeyError> {
        Ok(())
    }
}

/// Default software credential key provider
///
/// Uses the built-in ES256 (P-256) and EdDSA (Ed25519) implementations.
/// Opaque material is the raw 32-byte private key.
pub struct SoftwareCredentialKeyProvider;

impl CredentialKeyProvider for SoftwareCredentialKeyProvider {
    fn provider_id(&self) -> CredentialKeyProviderId {
        CredentialKeyProviderId::software()
    }

    fn supports_algorithm(&self, algorithm: i32) -> bool {
        matches!(algorithm, -7 | -8 | -19)
    }

    fn generate(
        &self,
        algorithm: i32,
    ) -> core::result::Result<GeneratedCredentialKey, CredentialKeyError> {
        if !self.supports_algorithm(algorithm) {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }

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
    ) -> core::result::Result<Vec<u8>, CredentialKeyError> {
        if !key.provider.is_software() {
            return Err(CredentialKeyError::UnsupportedProvider);
        }

        let key_bytes = key.material.as_slice();
        if key_bytes.len() != 32 {
            return Err(CredentialKeyError::InvalidKeyMaterial);
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(key_bytes);
        let priv_key = zeroize::Zeroizing::new(arr);

        match algorithm {
            -8 | -19 => soft_fido2_crypto::eddsa::sign(&priv_key, message)
                .map_err(|e| CredentialKeyError::TransientFailure(alloc::format!("{:?}", e))),
            _ => soft_fido2_crypto::ecdsa::sign(&priv_key, message)
                .map_err(|e| CredentialKeyError::TransientFailure(alloc::format!("{:?}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_provider_id() {
        let id = CredentialKeyProviderId::software();
        assert!(id.is_software());
        assert_eq!(id.as_bytes(), SOFTWARE_PROVIDER_ID.as_slice());
    }

    #[test]
    fn test_custom_provider_id() {
        let id = CredentialKeyProviderId::new(b"tpm-v1");
        assert!(!id.is_software());
    }

    #[test]
    fn test_software_generate_es256() {
        let provider = SoftwareCredentialKeyProvider;
        let result = provider.generate(-7).unwrap();
        assert!(result.key.provider.is_software());
        assert_eq!(result.key.material.as_slice().len(), 32);
        assert_eq!(result.cose_public_key.len(), 65);
        assert_eq!(result.cose_public_key[0], 0x04);
    }

    #[test]
    fn test_software_generate_eddsa() {
        let provider = SoftwareCredentialKeyProvider;
        let result = provider.generate(-8).unwrap();
        assert!(result.key.provider.is_software());
        assert_eq!(result.key.material.as_slice().len(), 32);
        assert_eq!(result.cose_public_key.len(), 32);
    }

    #[test]
    fn test_software_sign_and_verify_es256() {
        let provider = SoftwareCredentialKeyProvider;
        let generated = provider.generate(-7).unwrap();
        let message = b"test message";
        let signature = provider.sign(&generated.key, -7, message).unwrap();

        assert!(
            soft_fido2_crypto::ecdsa::verify(&generated.cose_public_key, message, &signature)
                .is_ok()
        );
    }

    #[test]
    fn test_software_sign_and_verify_eddsa() {
        let provider = SoftwareCredentialKeyProvider;
        let generated = provider.generate(-8).unwrap();
        let message = b"test message";
        let signature = provider.sign(&generated.key, -8, message).unwrap();

        assert!(
            soft_fido2_crypto::eddsa::verify(&generated.cose_public_key, message, &signature)
                .is_ok()
        );
    }

    #[test]
    fn test_software_sign_rejects_non_software_key() {
        let provider = SoftwareCredentialKeyProvider;
        let key = CredentialKey::new(
            CredentialKeyProviderId::new(b"other"),
            1,
            SecBytes::new(vec![0u8; 32]),
        );
        let result = provider.sign(&key, -7, b"test");
        assert_eq!(result, Err(CredentialKeyError::UnsupportedProvider));
    }

    #[test]
    fn test_software_sign_rejects_wrong_length() {
        let provider = SoftwareCredentialKeyProvider;
        let key = CredentialKey::software(SecBytes::new(vec![0u8; 16]));
        let result = provider.sign(&key, -7, b"test");
        assert_eq!(result, Err(CredentialKeyError::InvalidKeyMaterial));
    }

    #[test]
    fn test_software_supports_algorithm() {
        let provider = SoftwareCredentialKeyProvider;
        assert!(provider.supports_algorithm(-7));
        assert!(provider.supports_algorithm(-8));
        assert!(provider.supports_algorithm(-19));
        assert!(!provider.supports_algorithm(-257));
    }

    #[test]
    fn test_credential_key_error_to_status_code() {
        assert_eq!(
            StatusCode::from(CredentialKeyError::UnsupportedAlgorithm),
            StatusCode::UnsupportedAlgorithm
        );
        assert_eq!(
            StatusCode::from(CredentialKeyError::InvalidKeyMaterial),
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
        let key = CredentialKey::software(SecBytes::new(vec![0u8; 32]));
        assert!(key.provider.is_software());
        assert_eq!(key.format_version, 1);
    }

    #[test]
    fn test_credential_key_serde_roundtrip() {
        let key = CredentialKey::software(SecBytes::new(vec![42u8; 32]));
        let mut buf = Vec::new();
        crate::cbor::into_writer(&key, &mut buf).unwrap();
        let restored: CredentialKey = crate::cbor::decode(&buf).unwrap();
        assert_eq!(restored.provider, key.provider);
        assert_eq!(restored.format_version, key.format_version);
        assert_eq!(restored.material.as_slice(), key.material.as_slice());
    }

    #[test]
    fn test_software_generate_rejects_unsupported_algorithm() {
        let provider = SoftwareCredentialKeyProvider;
        let result = provider.generate(-257);
        assert_eq!(result, Err(CredentialKeyError::UnsupportedAlgorithm));
    }

    #[test]
    fn test_provider_id_deserialization_rejects_oversized() {
        use crate::cbor::Value;

        let oversized = Value::Bytes(vec![0u8; MAX_PROVIDER_ID_LENGTH + 1]);
        let mut buf = Vec::new();
        crate::cbor::into_writer(&oversized, &mut buf).unwrap();
        let result: core::result::Result<CredentialKeyProviderId, _> = crate::cbor::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_key_deserialization_rejects_out_of_range_format_version() {
        use crate::cbor::Value;

        let map = Value::Map(vec![
            (
                Value::Text("provider".to_string()),
                Value::Bytes(b"software-v1".to_vec()),
            ),
            (
                Value::Text("format_version".to_string()),
                Value::Integer(u16::MAX as i128 + 1),
            ),
            (
                Value::Text("material".to_string()),
                Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        let mut buf = Vec::new();
        crate::cbor::into_writer(&map, &mut buf).unwrap();
        let result: core::result::Result<CredentialKey, _> = crate::cbor::decode(&buf);
        assert!(result.is_err());
    }

    #[cfg(test)]
    mod mock_external_provider {
        use super::*;
        use alloc::collections::BTreeMap;

        #[cfg(feature = "std")]
        use std::sync::Mutex;

        #[cfg(not(feature = "std"))]
        use spin::Mutex;

        struct MockExternalProvider {
            #[allow(clippy::type_complexity)]
            keys: Mutex<BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)>>,
            next_handle: Mutex<u64>,
        }

        impl MockExternalProvider {
            fn new() -> Self {
                Self {
                    keys: Mutex::new(BTreeMap::new()),
                    next_handle: Mutex::new(1),
                }
            }
        }

        impl CredentialKeyProvider for MockExternalProvider {
            fn provider_id(&self) -> CredentialKeyProviderId {
                CredentialKeyProviderId::new(b"mock-external-v1")
            }

            fn supports_algorithm(&self, algorithm: i32) -> bool {
                algorithm == -7
            }

            fn generate(
                &self,
                algorithm: i32,
            ) -> core::result::Result<GeneratedCredentialKey, CredentialKeyError> {
                if algorithm != -7 {
                    return Err(CredentialKeyError::UnsupportedAlgorithm);
                }

                let (sk, pk) = soft_fido2_crypto::ecdsa::generate_keypair();

                let handle = {
                    let mut h = self.next_handle.lock().unwrap();
                    let val = *h;
                    *h += 1;
                    val
                };

                let opaque_handle = handle.to_be_bytes().to_vec();

                #[cfg(feature = "std")]
                self.keys
                    .lock()
                    .unwrap()
                    .insert(opaque_handle.clone(), (sk.to_vec(), pk.clone()));

                #[cfg(not(feature = "std"))]
                self.keys
                    .lock()
                    .insert(opaque_handle.clone(), (sk.to_vec(), pk.clone()));

                let key =
                    CredentialKey::new(self.provider_id(), 1, SecBytes::from_slice(&opaque_handle));

                Ok(GeneratedCredentialKey {
                    key,
                    cose_public_key: pk,
                })
            }

            fn sign(
                &self,
                key: &CredentialKey,
                algorithm: i32,
                message: &[u8],
            ) -> core::result::Result<Vec<u8>, CredentialKeyError> {
                if key.provider != self.provider_id() {
                    return Err(CredentialKeyError::UnsupportedProvider);
                }

                if key.material.as_slice().len() != 8 {
                    return Err(CredentialKeyError::InvalidKeyMaterial);
                }

                let handle = key.material.as_slice().to_vec();

                #[cfg(feature = "std")]
                let keys = self.keys.lock().unwrap();
                #[cfg(not(feature = "std"))]
                let keys = self.keys.lock();

                let (sk_bytes, _) = keys.get(&handle).ok_or(CredentialKeyError::KeyNotFound)?;

                if sk_bytes.len() != 32 {
                    return Err(CredentialKeyError::InvalidKeyMaterial);
                }

                let mut arr = [0u8; 32];
                arr.copy_from_slice(sk_bytes);
                let priv_key = zeroize::Zeroizing::new(arr);

                match algorithm {
                    -7 => soft_fido2_crypto::ecdsa::sign(&priv_key, message).map_err(|e| {
                        CredentialKeyError::TransientFailure(alloc::format!("{:?}", e))
                    }),
                    _ => Err(CredentialKeyError::UnsupportedAlgorithm),
                }
            }
        }

        #[test]
        fn test_mock_provider_generate_returns_opaque_handle() {
            let provider = MockExternalProvider::new();
            let generated = provider.generate(-7).unwrap();

            assert!(!generated.key.provider.is_software());
            assert_eq!(generated.key.provider.as_bytes(), b"mock-external-v1");
            assert_ne!(generated.key.material.as_slice().len(), 32);
            assert_eq!(generated.key.material.as_slice().len(), 8);
            assert_eq!(generated.cose_public_key.len(), 65);
        }

        #[test]
        fn test_mock_provider_sign_and_verify() {
            let provider = MockExternalProvider::new();
            let generated = provider.generate(-7).unwrap();
            let message = b"test message for mock provider";
            let signature = provider.sign(&generated.key, -7, message).unwrap();

            assert!(
                soft_fido2_crypto::ecdsa::verify(&generated.cose_public_key, message, &signature)
                    .is_ok()
            );
        }

        #[test]
        fn test_mock_provider_rejects_unsupported_algorithm() {
            let provider = MockExternalProvider::new();
            let result = provider.generate(-8);
            assert_eq!(result, Err(CredentialKeyError::UnsupportedAlgorithm));
        }

        #[test]
        fn test_mock_provider_rejects_wrong_provider_id() {
            let provider = MockExternalProvider::new();
            let key = CredentialKey::new(
                CredentialKeyProviderId::new(b"wrong-provider"),
                1,
                SecBytes::new(vec![0u8; 8]),
            );
            let result = provider.sign(&key, -7, b"test");
            assert_eq!(result, Err(CredentialKeyError::UnsupportedProvider));
        }

        #[test]
        fn test_mock_provider_rejects_invalid_handle_length() {
            let provider = MockExternalProvider::new();
            let key = CredentialKey::new(provider.provider_id(), 1, SecBytes::new(vec![0u8; 16]));
            let result = provider.sign(&key, -7, b"test");
            assert_eq!(result, Err(CredentialKeyError::InvalidKeyMaterial));
        }

        #[test]
        fn test_mock_provider_rejects_unknown_handle() {
            let provider = MockExternalProvider::new();
            let key = CredentialKey::new(provider.provider_id(), 1, SecBytes::new(vec![0xFFu8; 8]));
            let result = provider.sign(&key, -7, b"test");
            assert_eq!(result, Err(CredentialKeyError::KeyNotFound));
        }

        #[test]
        fn test_mock_provider_multiple_keys() {
            let provider = MockExternalProvider::new();

            let gen1 = provider.generate(-7).unwrap();
            let gen2 = provider.generate(-7).unwrap();

            assert_ne!(gen1.key.material.as_slice(), gen2.key.material.as_slice());

            let msg1 = b"message 1";
            let msg2 = b"message 2";

            let sig1 = provider.sign(&gen1.key, -7, msg1).unwrap();
            let sig2 = provider.sign(&gen2.key, -7, msg2).unwrap();

            assert!(soft_fido2_crypto::ecdsa::verify(&gen1.cose_public_key, msg1, &sig1).is_ok());
            assert!(soft_fido2_crypto::ecdsa::verify(&gen2.cose_public_key, msg2, &sig2).is_ok());

            assert!(soft_fido2_crypto::ecdsa::verify(&gen1.cose_public_key, msg2, &sig1).is_err());
        }

        #[test]
        fn test_mock_provider_with_authenticator() {
            use crate::authenticator::{Authenticator, AuthenticatorConfig};
            use crate::test_utils::MockCallbacks;

            let provider = MockExternalProvider::new();
            let config = AuthenticatorConfig::new();
            let auth = Authenticator::new_with_key_provider(config, MockCallbacks, provider);

            assert_eq!(
                auth.key_provider().provider_id().as_bytes(),
                b"mock-external-v1"
            );
            assert!(auth.key_provider().supports_algorithm(-7));
            assert!(!auth.key_provider().supports_algorithm(-8));
        }
    }
}
