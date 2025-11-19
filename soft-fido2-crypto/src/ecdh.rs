//! P-256 ECDH for CTAP PIN protocol key agreement
//!
//! Implements key agreement per FIDO2 spec:
//! <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-pin-protocol>

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{CryptoError, Result};

use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use rand::rngs::OsRng;

/// P-256 key pair for ECDH key agreement
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {
    /// Generate new random ECDH key pair
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::ecdh::KeyPair;
    ///
    /// let keypair = KeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self> {
        let secret = SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        Ok(Self { secret, public })
    }

    /// Get public key in COSE format
    ///
    /// Returns (x, y) coordinates as two 32-byte arrays.
    /// This format is used in CTAP for COSE_Key encoding (kty: 2, alg: -25, crv: 1).
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::ecdh::KeyPair;
    ///
    /// let keypair = KeyPair::generate().unwrap();
    /// let (x, y) = keypair.public_key_cose();
    /// assert_eq!(x.len(), 32);
    /// assert_eq!(y.len(), 32);
    /// ```
    pub fn public_key_cose(&self) -> ([u8; 32], [u8; 32]) {
        let point = self.public.to_encoded_point(false);
        let x = point.x().expect("uncompressed point has x coordinate");
        let y = point.y().expect("uncompressed point has y coordinate");

        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&x[..]);
        y_bytes.copy_from_slice(&y[..]);

        (x_bytes, y_bytes)
    }

    /// Get public key in uncompressed SEC1 format (0x04 || x || y)
    ///
    /// This is the standard 65-byte encoding used in many contexts.
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::ecdh::KeyPair;
    ///
    /// let keypair = KeyPair::generate().unwrap();
    /// let bytes = keypair.public_key_bytes();
    /// assert_eq!(bytes.len(), 65);
    /// assert_eq!(bytes[0], 0x04);  // Uncompressed point marker
    /// ```
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Compute shared secret with peer's public key
    ///
    /// Performs ECDH key agreement with the peer's public key.
    /// The peer public key should be in uncompressed SEC1 format (65 bytes: 0x04 || x || y).
    ///
    /// Per FIDO2 spec, the shared secret is the x-coordinate of the resulting point.
    ///
    /// # Arguments
    ///
    /// * `peer_public_key` - Peer's public key in uncompressed SEC1 format
    ///
    /// # Returns
    ///
    /// 32-byte shared secret (x-coordinate of ECDH result)
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::ecdh::KeyPair;
    ///
    /// let alice = KeyPair::generate().unwrap();
    /// let bob = KeyPair::generate().unwrap();
    ///
    /// let alice_shared = alice.shared_secret(&bob.public_key_bytes()).unwrap();
    /// let bob_shared = bob.shared_secret(&alice.public_key_bytes()).unwrap();
    ///
    /// assert_eq!(alice_shared, bob_shared);
    /// ```
    pub fn shared_secret(&self, peer_public_key: &[u8]) -> Result<[u8; 32]> {
        // Parse peer's public key from SEC1 encoding
        let peer_public = PublicKey::from_sec1_bytes(peer_public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        // Perform ECDH
        let shared =
            p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer_public.as_affine());

        // Return x-coordinate as shared secret (per FIDO2 spec)
        let mut secret = [0u8; 32];
        secret.copy_from_slice(shared.raw_secret_bytes());
        Ok(secret)
    }

    /// Create KeyPair from existing secret key bytes
    ///
    /// # Arguments
    ///
    /// * `secret_bytes` - 32-byte secret scalar
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::ecdh::KeyPair;
    ///
    /// let secret_bytes = [42u8; 32];  // Not a real key!
    /// // This will likely fail because not all 32-byte values are valid scalars
    /// let result = KeyPair::from_bytes(&secret_bytes);
    /// ```
    pub fn from_bytes(secret_bytes: &[u8; 32]) -> Result<Self> {
        let secret = SecretKey::from_bytes(secret_bytes.into())
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        let public = secret.public_key();
        Ok(Self { secret, public })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate().unwrap();
        let (x, y) = keypair.public_key_cose();

        // Verify coordinates are 32 bytes each
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);

        // Verify they're not all zeros
        assert_ne!(x, [0u8; 32]);
        assert_ne!(y, [0u8; 32]);
    }

    #[test]
    fn test_public_key_bytes_format() {
        let keypair = KeyPair::generate().unwrap();
        let bytes = keypair.public_key_bytes();

        // Should be 65 bytes: 0x04 || x (32) || y (32)
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04); // Uncompressed point marker
    }

    #[test]
    fn test_ecdh_key_agreement() {
        // Alice and Bob generate keypairs
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();

        // Each computes shared secret with the other's public key
        let alice_shared = alice.shared_secret(&bob.public_key_bytes()).unwrap();
        let bob_shared = bob.shared_secret(&alice.public_key_bytes()).unwrap();

        // Shared secrets must match
        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 32);

        // Shared secret should not be all zeros
        assert_ne!(alice_shared, [0u8; 32]);
    }

    #[test]
    fn test_ecdh_different_peers() {
        let alice = KeyPair::generate().unwrap();
        let bob = KeyPair::generate().unwrap();
        let charlie = KeyPair::generate().unwrap();

        let alice_bob = alice.shared_secret(&bob.public_key_bytes()).unwrap();
        let alice_charlie = alice.shared_secret(&charlie.public_key_bytes()).unwrap();

        // Different peers should produce different shared secrets
        assert_ne!(alice_bob, alice_charlie);
    }

    #[test]
    fn test_invalid_public_key() {
        let keypair = KeyPair::generate().unwrap();

        // Invalid length
        let result = keypair.shared_secret(&[0u8; 32]);
        assert!(result.is_err());

        // Invalid point (all zeros with correct length)
        let result = keypair.shared_secret(&[0u8; 65]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cose_format_matches_sec1() {
        let keypair = KeyPair::generate().unwrap();
        let (x, y) = keypair.public_key_cose();
        let sec1 = keypair.public_key_bytes();

        // SEC1 format: 0x04 || x || y
        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..33], &x);
        assert_eq!(&sec1[33..65], &y);
    }
}
