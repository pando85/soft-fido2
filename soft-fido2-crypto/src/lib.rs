//! Pure Rust cryptographic primitives for FIDO2/CTAP
//!
//! This crate provides the cryptographic operations required by the CTAP protocol:
//!
//! - **ECDH**: P-256 key agreement for PIN protocol
//! - **ECDSA**: ES256 signatures for attestation and assertions
//! - **PIN Protocols**: V1 (AES-256-CBC + HMAC) and V2 (HMAC-only)
//! - **HMAC-SHA256**: For hmac-secret extension
//!
//! All implementations follow the FIDO2 specification:
//! <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html>

#![cfg_attr(not(feature = "std"), no_std)]

pub mod ecdh;
pub mod ecdsa;
pub mod error;
pub mod pin_protocol;

// Re-export commonly used types
pub use error::{CryptoError, Result};

// Re-export zeroize for callers to use with sensitive data
pub use zeroize::Zeroizing;

/// Compute HMAC-SHA-256
///
/// Used by the hmac-secret extension to derive secrets from credentials.
///
/// # Arguments
/// * `key` - The HMAC key (e.g., credential random)
/// * `data` - The data to authenticate (e.g., salt)
///
/// # Returns
/// 32-byte HMAC-SHA-256 output
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}
