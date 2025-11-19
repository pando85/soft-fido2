//! P-256 ECDSA (ES256) signatures for CTAP attestation and assertions
//!
//! COSE algorithm identifier: -7 (ES256)
//! Spec: <https://www.rfc-editor.org/rfc/rfc8152.html#section-8.1>
//!
//! ES256 uses:
//! - Curve: P-256 (secp256r1 / prime256v1)
//! - Hash: SHA-256
//! - Signature format: DER-encoded or raw (r || s)

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{CryptoError, Result};

use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use rand::rngs::OsRng;

/// Generate new random ES256 key pair
///
/// Returns (private_key, public_key) where:
/// - private_key: 32-byte scalar
/// - public_key: 65-byte uncompressed SEC1 format (0x04 || x || y)
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::ecdsa;
///
/// let (private_key, public_key) = ecdsa::generate_keypair();
/// assert_eq!(private_key.len(), 32);
/// assert_eq!(public_key.len(), 65);
/// assert_eq!(public_key[0], 0x04);
/// ```
pub fn generate_keypair() -> ([u8; 32], Vec<u8>) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_key: [u8; 32] = signing_key.to_bytes().into();

    // Public key in uncompressed SEC1 format
    let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    (private_key, public_key)
}

/// Sign data with ES256 (P-256 + SHA-256)
///
/// The data is hashed with SHA-256 internally by the signing operation.
/// Returns DER-encoded signature.
///
/// # Arguments
///
/// * `private_key` - 32-byte private scalar
/// * `data` - Data to sign
///
/// # Returns
///
/// DER-encoded ECDSA signature (typically 70-72 bytes)
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::ecdsa;
///
/// let (private_key, _) = ecdsa::generate_keypair();
/// let message = b"Hello, FIDO2!";
///
/// let signature = ecdsa::sign(&private_key, message).unwrap();
/// assert!(signature.len() >= 70 && signature.len() <= 72);
/// ```
pub fn sign(private_key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let signing_key =
        SigningKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidPrivateKey)?;

    let signature: Signature = signing_key.sign(data);

    // Return DER-encoded signature
    Ok(signature.to_der().to_bytes().to_vec())
}

/// Sign data and return raw signature (r || s format)
///
/// Returns 64-byte signature in raw format: r (32 bytes) || s (32 bytes).
/// This format is used in some CTAP contexts.
///
/// # Arguments
///
/// * `private_key` - 32-byte private scalar
/// * `data` - Data to sign
///
/// # Returns
///
/// 64-byte raw signature (r || s)
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::ecdsa;
///
/// let (private_key, _) = ecdsa::generate_keypair();
/// let message = b"Hello, FIDO2!";
///
/// let signature = ecdsa::sign_raw(&private_key, message).unwrap();
/// assert_eq!(signature.len(), 64);
/// ```
pub fn sign_raw(private_key: &[u8; 32], data: &[u8]) -> Result<[u8; 64]> {
    let signing_key =
        SigningKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidPrivateKey)?;

    let signature: Signature = signing_key.sign(data);

    // Return raw signature bytes (r || s)
    Ok(signature.to_bytes().into())
}

/// Verify ES256 signature
///
/// Verifies a DER-encoded signature against data and public key.
///
/// # Arguments
///
/// * `public_key` - 65-byte uncompressed SEC1 format (0x04 || x || y)
/// * `data` - Data that was signed
/// * `signature` - DER-encoded signature
///
/// # Returns
///
/// `Ok(())` if signature is valid, `Err` otherwise
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::ecdsa;
///
/// let (private_key, public_key) = ecdsa::generate_keypair();
/// let message = b"Hello, FIDO2!";
///
/// let signature = ecdsa::sign(&private_key, message).unwrap();
/// assert!(ecdsa::verify(&public_key, message, &signature).is_ok());
///
/// // Wrong message should fail
/// assert!(ecdsa::verify(&public_key, b"wrong", &signature).is_err());
/// ```
pub fn verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    // Parse public key
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;

    // Parse signature from DER
    let sig = Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?;

    // Verify signature
    verifying_key
        .verify(data, &sig)
        .map_err(|_| CryptoError::InvalidSignature)?;

    Ok(())
}

/// Verify raw signature (r || s format)
///
/// # Arguments
///
/// * `public_key` - 65-byte uncompressed SEC1 format (0x04 || x || y)
/// * `data` - Data that was signed
/// * `signature` - 64-byte raw signature (r || s)
///
/// # Returns
///
/// `Ok(())` if signature is valid, `Err` otherwise
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::ecdsa;
///
/// let (private_key, public_key) = ecdsa::generate_keypair();
/// let message = b"Hello, FIDO2!";
///
/// let signature = ecdsa::sign_raw(&private_key, message).unwrap();
/// assert!(ecdsa::verify_raw(&public_key, message, &signature).is_ok());
/// ```
pub fn verify_raw(public_key: &[u8], data: &[u8], signature: &[u8; 64]) -> Result<()> {
    // Parse public key
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;

    // Parse raw signature
    let sig = Signature::from_bytes(signature.into()).map_err(|_| CryptoError::InvalidSignature)?;

    // Verify signature
    verifying_key
        .verify(data, &sig)
        .map_err(|_| CryptoError::InvalidSignature)?;

    Ok(())
}

/// Get public key from private key
///
/// # Arguments
///
/// * `private_key` - 32-byte private scalar
///
/// # Returns
///
/// 65-byte uncompressed SEC1 format public key (0x04 || x || y)
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::ecdsa;
///
/// let (private_key, expected_public) = ecdsa::generate_keypair();
/// let derived_public = ecdsa::public_from_private(&private_key).unwrap();
/// assert_eq!(derived_public, expected_public);
/// ```
pub fn public_from_private(private_key: &[u8; 32]) -> Result<Vec<u8>> {
    let signing_key =
        SigningKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidPrivateKey)?;

    let verifying_key = signing_key.verifying_key();
    Ok(verifying_key.to_encoded_point(false).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (private_key, public_key) = generate_keypair();

        assert_eq!(private_key.len(), 32);
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04); // Uncompressed point marker

        // Private key should not be all zeros
        assert_ne!(private_key, [0u8; 32]);
    }

    #[test]
    fn test_sign_and_verify() {
        let (private_key, public_key) = generate_keypair();
        let message = b"Hello, FIDO2!";

        let signature = sign(&private_key, message).unwrap();

        // DER signature is typically 70-73 bytes (can vary due to DER encoding)
        assert!(signature.len() >= 68 && signature.len() <= 73);

        // Verify signature
        assert!(verify(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_sign_raw_and_verify_raw() {
        let (private_key, public_key) = generate_keypair();
        let message = b"Hello, FIDO2!";

        let signature = sign_raw(&private_key, message).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify raw signature
        assert!(verify_raw(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let (private_key, public_key) = generate_keypair();
        let message = b"Hello, FIDO2!";
        let wrong_message = b"Wrong message";

        let signature = sign(&private_key, message).unwrap();

        // Should fail with wrong message
        assert!(verify(&public_key, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let (private_key, _) = generate_keypair();
        let (_, wrong_public_key) = generate_keypair();
        let message = b"Hello, FIDO2!";

        let signature = sign(&private_key, message).unwrap();

        // Should fail with wrong public key
        assert!(verify(&wrong_public_key, message, &signature).is_err());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let (_, public_key) = generate_keypair();
        let message = b"Hello, FIDO2!";
        let bad_signature = vec![0u8; 72];

        // Should fail with invalid signature
        assert!(verify(&public_key, message, &bad_signature).is_err());
    }

    #[test]
    fn test_public_from_private() {
        let (private_key, expected_public) = generate_keypair();
        let derived_public = public_from_private(&private_key).unwrap();

        assert_eq!(derived_public, expected_public);
    }

    #[test]
    fn test_deterministic_public_key() {
        let private_key = [42u8; 32]; // Fixed private key

        // Deriving public key multiple times should give same result
        let pub1 = public_from_private(&private_key).unwrap();
        let pub2 = public_from_private(&private_key).unwrap();

        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_invalid_private_key() {
        // All zeros is not a valid private key
        let invalid_key = [0u8; 32];
        assert!(sign(&invalid_key, b"test").is_err());
        assert!(public_from_private(&invalid_key).is_err());
    }
}
