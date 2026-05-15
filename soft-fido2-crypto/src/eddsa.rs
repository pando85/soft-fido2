//! Ed25519 (EdDSA) signatures for CTAP assertions
//!
//! COSE algorithm identifier: -8 (EdDSA)
//! Spec: <https://www.rfc-editor.org/rfc/rfc8410.html>
//!
//! EdDSA uses:
//! - Curve: Edwards25519
//! - Signature: Ed25519 (PureEdDSA)
//! - Hash: SHA-512 (internal to Ed25519)

extern crate alloc;

use crate::error::{CryptoError, Result};

use alloc::vec::Vec;
use ed25519_dalek::Signer;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand_08::RngCore;
use rand_08::rngs::OsRng;
use zeroize::Zeroizing;

pub use ed25519_dalek::PUBLIC_KEY_LENGTH;
pub use ed25519_dalek::SECRET_KEY_LENGTH;
pub use ed25519_dalek::SIGNATURE_LENGTH;

/// Generate new random Ed25519 key pair
///
/// Returns (private_key, public_key) where:
/// - private_key: 32-byte seed wrapped in Zeroizing for automatic zeroing
/// - public_key: 32-byte Ed25519 public key
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::eddsa;
///
/// let (private_key, public_key) = eddsa::generate_keypair();
/// assert_eq!(private_key.len(), 32);
/// assert_eq!(public_key.len(), 32);
/// ```
pub fn generate_keypair() -> (Zeroizing<[u8; 32]>, Vec<u8>) {
    let mut secret_key = [0u8; 32];
    OsRng.fill_bytes(&mut secret_key);

    let signing_key = SigningKey::from_bytes(&secret_key);
    let verifying_key = signing_key.verifying_key();

    let private_key = Zeroizing::new(secret_key);
    let public_key = verifying_key.to_bytes().to_vec();

    (private_key, public_key)
}

/// Sign data with Ed25519
///
/// Returns 64-byte Ed25519 signature.
///
/// # Arguments
///
/// * `private_key` - 32-byte seed
/// * `data` - Data to sign
///
/// # Returns
///
/// 64-byte Ed25519 signature
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::eddsa;
///
/// let (private_key, _) = eddsa::generate_keypair();
/// let message = b"Hello, FIDO2!";
///
/// let signature = eddsa::sign(&private_key, message).unwrap();
/// assert_eq!(signature.len(), 64);
/// ```
pub fn sign(private_key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let signing_key = SigningKey::from_bytes(private_key);

    let signature: Signature = signing_key.sign(data);

    Ok(signature.to_bytes().to_vec())
}

/// Verify Ed25519 signature
///
/// # Arguments
///
/// * `public_key` - 32-byte Ed25519 public key
/// * `data` - Data that was signed
/// * `signature` - 64-byte Ed25519 signature
///
/// # Returns
///
/// `Ok(())` if signature is valid, `Err` otherwise
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::eddsa;
///
/// let (private_key, public_key) = eddsa::generate_keypair();
/// let message = b"Hello, FIDO2!";
///
/// let signature = eddsa::sign(&private_key, message).unwrap();
/// assert!(eddsa::verify(&public_key, message, &signature).is_ok());
///
/// // Wrong message should fail
/// assert!(eddsa::verify(&public_key, b"wrong", &signature).is_err());
/// ```
pub fn verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?,
    )
    .map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig = Signature::from_slice(signature).map_err(|_| CryptoError::InvalidSignature)?;

    verifying_key
        .verify(data, &sig)
        .map_err(|_| CryptoError::InvalidSignature)?;

    Ok(())
}

/// Get public key from private key
///
/// # Arguments
///
/// * `private_key` - 32-byte seed
///
/// # Returns
///
/// 32-byte Ed25519 public key
///
/// # Examples
///
/// ```
/// use soft_fido2_crypto::eddsa;
///
/// let (private_key, expected_public) = eddsa::generate_keypair();
/// let derived_public = eddsa::public_from_private(&private_key).unwrap();
/// assert_eq!(derived_public, expected_public);
/// ```
pub fn public_from_private(private_key: &[u8; 32]) -> Result<Vec<u8>> {
    let signing_key = SigningKey::from_bytes(private_key);

    let verifying_key = signing_key.verifying_key();
    Ok(verifying_key.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_keypair_generation() {
        let (private_key, public_key) = generate_keypair();

        assert_eq!(private_key.len(), 32);
        assert_eq!(public_key.len(), 32);

        // Private key should not be all zeros
        assert_ne!(*private_key, [0u8; 32]);
    }

    #[test]
    fn test_sign_and_verify() {
        let (private_key, public_key) = generate_keypair();
        let message = b"Hello, FIDO2!";

        let signature = sign(&private_key, message).unwrap();

        assert_eq!(signature.len(), 64);

        // Verify signature
        assert!(verify(&public_key, message, &signature).is_ok());
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
        let bad_signature = vec![0u8; 64];

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
        let private_key = [42u8; 32];

        // Deriving public key multiple times should give same result
        let pub1 = public_from_private(&private_key).unwrap();
        let pub2 = public_from_private(&private_key).unwrap();

        assert_eq!(pub1, pub2);
    }
}
