//! Error types for cryptographic operations

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(not(feature = "std"))]
use core::fmt;

/// Cryptographic operation errors
#[cfg(feature = "std")]
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid public key provided
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid private key provided
    #[error("Invalid private key")]
    InvalidPrivateKey,

    /// Invalid signature format
    #[error("Invalid signature")]
    InvalidSignature,

    /// Decryption failed
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Encryption failed
    #[error("Encryption failed")]
    EncryptionFailed,

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// ECDH key agreement failed
    #[error("ECDH key agreement failed")]
    KeyAgreementFailed,

    /// Invalid COSE key format
    #[error("Invalid COSE key format")]
    InvalidCoseKey,
}

/// Cryptographic operation errors (no_std version)
#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub enum CryptoError {
    /// Invalid public key provided
    InvalidPublicKey,

    /// Invalid private key provided
    InvalidPrivateKey,

    /// Invalid signature format
    InvalidSignature,

    /// Decryption failed
    DecryptionFailed,

    /// Encryption failed
    EncryptionFailed,

    /// Invalid key length
    InvalidKeyLength { expected: usize, actual: usize },

    /// ECDH key agreement failed
    KeyAgreementFailed,

    /// Invalid COSE key format
    InvalidCoseKey,
}

// Manual Display implementation for no_std
#[cfg(not(feature = "std"))]
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::InvalidPrivateKey => write!(f, "Invalid private key"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid key length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::KeyAgreementFailed => write!(f, "ECDH key agreement failed"),
            Self::InvalidCoseKey => write!(f, "Invalid COSE key format"),
        }
    }
}

/// Result type alias for cryptographic operations
pub type Result<T> = core::result::Result<T, CryptoError>;
