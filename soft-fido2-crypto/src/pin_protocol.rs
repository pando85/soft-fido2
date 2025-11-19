//! PIN/UV authentication protocols (V1 and V2)
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorClientPIN>
//!
//! Protocol V1: AES-256-CBC encryption + SHA-256 HMAC
//! Protocol V2: HMAC-SHA-256 only (FIPS-approved, no encryption for auth)

use crate::error::{CryptoError, Result};

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use aes::Aes256;
use cbc::{
    Decryptor, Encryptor,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// PIN Protocol Version 1 (AES-256-CBC + SHA-256 HMAC)
///
/// This protocol uses:
/// - AES-256-CBC with zero IV for encryption
/// - HMAC-SHA-256 (first 16 bytes) for authentication
pub mod v1 {
    use super::*;

    /// Encrypt plaintext with AES-256-CBC using zero IV
    ///
    /// Per CTAP spec, PIN protocol V1 uses zero IV.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte encryption key (derived from ECDH)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// PKCS#7 padded ciphertext
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::pin_protocol::v1;
    ///
    /// let key = [0x42u8; 32];
    /// let plaintext = b"Hello, FIDO2!";
    ///
    /// let ciphertext = v1::encrypt(&key, plaintext).unwrap();
    /// assert!(ciphertext.len() >= plaintext.len());
    /// ```
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Use zero IV per spec
        let iv = [0u8; 16];

        // Allocate buffer with space for padding (worst case: plaintext + 16 bytes)
        let mut buffer = vec![0u8; plaintext.len() + 16];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let cipher = Aes256CbcEnc::new(key.into(), &iv.into());
        let ciphertext = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(ciphertext.to_vec())
    }

    /// Decrypt ciphertext with AES-256-CBC using zero IV
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte encryption key (derived from ECDH)
    /// * `ciphertext` - Encrypted data with PKCS#7 padding
    ///
    /// # Returns
    ///
    /// Decrypted plaintext with padding removed
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::pin_protocol::v1;
    ///
    /// let key = [0x42u8; 32];
    /// let plaintext = b"Hello, FIDO2!";
    ///
    /// let ciphertext = v1::encrypt(&key, plaintext).unwrap();
    /// let decrypted = v1::decrypt(&key, &ciphertext).unwrap();
    ///
    /// assert_eq!(decrypted, plaintext);
    /// ```
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let iv = [0u8; 16];

        // Copy ciphertext to mutable buffer
        let mut buffer = ciphertext.to_vec();

        let cipher = Aes256CbcDec::new(key.into(), &iv.into());
        let plaintext = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext.to_vec())
    }

    /// Compute HMAC-SHA-256 and return first 16 bytes
    ///
    /// This is used for pinUvAuthParam calculation.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte HMAC key (derived from ECDH)
    /// * `data` - Data to authenticate
    ///
    /// # Returns
    ///
    /// First 16 bytes of HMAC-SHA-256
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::pin_protocol::v1;
    ///
    /// let key = [0x42u8; 32];
    /// let data = b"client_data_hash";
    ///
    /// let mac = v1::authenticate(&key, data);
    /// assert_eq!(mac.len(), 16);
    /// ```
    pub fn authenticate(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(data);
        let result = mac.finalize();

        let mut out = [0u8; 16];
        out.copy_from_slice(&result.into_bytes()[..16]);
        out
    }

    /// Verify HMAC-SHA-256 using constant-time comparison
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte HMAC key
    /// * `data` - Data to authenticate
    /// * `expected` - Expected MAC value (16 bytes)
    ///
    /// # Returns
    ///
    /// `true` if MAC is valid, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::pin_protocol::v1;
    ///
    /// let key = [0x42u8; 32];
    /// let data = b"client_data_hash";
    ///
    /// let mac = v1::authenticate(&key, data);
    /// assert!(v1::verify(&key, data, &mac));
    ///
    /// // Wrong data should fail
    /// assert!(!v1::verify(&key, b"wrong", &mac));
    /// ```
    pub fn verify(key: &[u8; 32], data: &[u8], expected: &[u8; 16]) -> bool {
        let computed = authenticate(key, data);
        computed.ct_eq(expected).into()
    }

    /// Derive encryption and HMAC keys from shared secret
    ///
    /// Per CTAP spec, both keys are derived by hashing the shared secret.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - 32-byte ECDH shared secret
    ///
    /// # Returns
    ///
    /// (encryption_key, hmac_key) - both 32 bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::pin_protocol::v1;
    ///
    /// let shared_secret = [0x42u8; 32];
    /// let (enc_key, hmac_key) = v1::derive_keys(&shared_secret);
    ///
    /// assert_eq!(enc_key.len(), 32);
    /// assert_eq!(hmac_key.len(), 32);
    /// ```
    pub fn derive_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        // Both keys are SHA-256(sharedSecret)
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        let hash = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);

        // In V1, both encryption and HMAC use the same derived key
        (key, key)
    }
}

/// PIN Protocol Version 2 (HMAC-SHA-256 only)
///
/// This protocol is FIPS-approved and uses only HMAC for authentication.
/// No encryption is used for pinUvAuthParam (only for PIN itself).
pub mod v2 {
    use super::*;

    /// Compute HMAC-SHA-256 and return first 16 bytes
    ///
    /// Identical to V1 for authentication purposes.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte HMAC key (derived from ECDH)
    /// * `data` - Data to authenticate
    ///
    /// # Returns
    ///
    /// First 16 bytes of HMAC-SHA-256
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::pin_protocol::v2;
    ///
    /// let key = [0x42u8; 32];
    /// let data = b"client_data_hash";
    ///
    /// let mac = v2::authenticate(&key, data);
    /// assert_eq!(mac.len(), 16);
    /// ```
    pub fn authenticate(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
        // Same as V1
        v1::authenticate(key, data)
    }

    /// Verify HMAC-SHA-256 using constant-time comparison
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte HMAC key
    /// * `data` - Data to authenticate
    /// * `expected` - Expected MAC value (16 bytes)
    ///
    /// # Returns
    ///
    /// `true` if MAC is valid, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::pin_protocol::v2;
    ///
    /// let key = [0x42u8; 32];
    /// let data = b"client_data_hash";
    ///
    /// let mac = v2::authenticate(&key, data);
    /// assert!(v2::verify(&key, data, &mac));
    /// ```
    pub fn verify(key: &[u8; 32], data: &[u8], expected: &[u8; 16]) -> bool {
        let computed = authenticate(key, data);
        computed.ct_eq(expected).into()
    }

    /// Derive HMAC key from shared secret for V2
    ///
    /// Uses HKDF-SHA-256 per CTAP 2.1 specification.
    /// HKDF-SHA-256(salt=32 zero bytes, IKM=sharedSecret, info="CTAP2 HMAC key", L=32)
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - 32-byte ECDH shared secret
    ///
    /// # Returns
    ///
    /// 32-byte HMAC key
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_crypto::pin_protocol::v2;
    ///
    /// let shared_secret = [0x42u8; 32];
    /// let hmac_key = v2::derive_hmac_key(&shared_secret);
    ///
    /// assert_eq!(hmac_key.len(), 32);
    /// ```
    pub fn derive_hmac_key(shared_secret: &[u8; 32]) -> [u8; 32] {
        use hkdf::Hkdf;

        // Per CTAP 2.1 spec: HKDF-SHA-256 with 32-byte zero salt
        let salt = [0u8; 32];
        let info = b"CTAP2 HMAC key";

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let mut key = [0u8; 32];
        hkdf.expand(info, &mut key)
            .expect("32 bytes is valid length for HKDF-SHA-256");

        key
    }

    /// Encrypt plaintext with AES-256-CBC for V2
    ///
    /// V2 encryption differs from V1:
    /// - Generates a random 16-byte IV
    /// - Prepends IV to the ciphertext (first 16 bytes)
    /// - Encrypts data starting at byte 16
    ///
    /// Format: [IV (16 bytes)] || [Encrypted data]
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte AES encryption key
    /// * `plaintext` - Data to encrypt (must be multiple of 16 bytes)
    ///
    /// # Returns
    ///
    /// IV prepended ciphertext (length = 16 + plaintext.len())
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes::Aes256;
        use aes::cipher::{BlockEncrypt, KeyInit};
        use rand::Rng;

        if !plaintext.len().is_multiple_of(16) {
            return Err(CryptoError::EncryptionFailed);
        }

        // Generate random IV
        let mut rng = rand::thread_rng();
        let mut iv: [u8; 16] = [0u8; 16];
        rng.fill(&mut iv);

        // Allocate output: IV + ciphertext
        let mut output = vec![0u8; 16 + plaintext.len()];

        // Copy IV to first 16 bytes
        output[0..16].copy_from_slice(&iv);

        // Initialize AES cipher
        let cipher = Aes256::new(key.into());

        // Encrypt using CBC mode with the random IV
        let mut iv_block = iv;
        for (i, chunk) in plaintext.chunks(16).enumerate() {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);

            // XOR with IV
            for j in 0..16 {
                block[j] ^= iv_block[j];
            }

            // Encrypt block
            let mut encrypted_block = block.into();
            cipher.encrypt_block(&mut encrypted_block);

            // Copy to output (starting at byte 16)
            output[16 + i * 16..16 + (i + 1) * 16].copy_from_slice(&encrypted_block);

            // Update IV for next block (CBC chaining)
            iv_block = encrypted_block.into();
        }

        Ok(output)
    }

    /// Decrypt ciphertext with AES-256-CBC for V2
    ///
    /// V2 decryption expects ciphertext in format:
    /// [IV (16 bytes)] || [Encrypted data]
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte AES encryption key
    /// * `ciphertext` - IV-prepended encrypted data
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes::Aes256;
        use aes::cipher::{BlockDecrypt, KeyInit};

        if ciphertext.len() < 16 || !(ciphertext.len() - 16).is_multiple_of(16) {
            return Err(CryptoError::DecryptionFailed);
        }

        // Extract IV from first 16 bytes
        let mut iv: [u8; 16] = [0u8; 16];
        iv.copy_from_slice(&ciphertext[0..16]);

        // Initialize AES cipher
        let cipher = Aes256::new(key.into());

        // Allocate output (excluding IV)
        let encrypted_data = &ciphertext[16..];
        let mut output = vec![0u8; encrypted_data.len()];

        // Decrypt using CBC mode
        let mut iv_block = iv;
        for (i, chunk) in encrypted_data.chunks(16).enumerate() {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);

            // Decrypt block
            let encrypted_block = block;
            let mut decrypted_block = block.into();
            cipher.decrypt_block(&mut decrypted_block);

            // XOR with IV
            let mut plaintext_block: [u8; 16] = decrypted_block.into();
            for j in 0..16 {
                plaintext_block[j] ^= iv_block[j];
            }

            // Copy to output
            output[i * 16..(i + 1) * 16].copy_from_slice(&plaintext_block);

            // Update IV for next block (CBC chaining)
            iv_block = encrypted_block;
        }

        Ok(output)
    }

    /// Derive encryption key from shared secret for V2
    ///
    /// Uses HKDF-SHA-256 per CTAP 2.1 specification.
    /// HKDF-SHA-256(salt=32 zero bytes, IKM=sharedSecret, info="CTAP2 AES key", L=32)
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - 32-byte ECDH shared secret
    ///
    /// # Returns
    ///
    /// 32-byte encryption key
    pub fn derive_encryption_key(shared_secret: &[u8; 32]) -> [u8; 32] {
        use hkdf::Hkdf;

        // Per CTAP 2.1 spec: HKDF-SHA-256 with 32-byte zero salt
        let salt = [0u8; 32];
        let info = b"CTAP2 AES key";

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let mut key = [0u8; 32];
        hkdf.expand(info, &mut key)
            .expect("32 bytes is valid length for HKDF-SHA-256");

        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, FIDO2!";

        let ciphertext = v1::encrypt(&key, plaintext).unwrap();
        assert!(ciphertext.len() >= plaintext.len()); // Includes padding

        let decrypted = v1::decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_v1_authenticate() {
        let key = [0x42u8; 32];
        let data = b"client_data_hash";

        let mac = v1::authenticate(&key, data);
        assert_eq!(mac.len(), 16);

        // Verify returns true for correct MAC
        assert!(v1::verify(&key, data, &mac));

        // Verify returns false for wrong data
        assert!(!v1::verify(&key, b"wrong_data", &mac));
    }

    #[test]
    fn test_v1_decrypt_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"Hello, FIDO2!";

        let ciphertext = v1::encrypt(&key1, plaintext).unwrap();

        // Decryption with wrong key should fail
        let result = v1::decrypt(&key2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_v1_derive_keys() {
        let shared_secret = [0x55u8; 32];
        let (enc_key, hmac_key) = v1::derive_keys(&shared_secret);

        assert_eq!(enc_key.len(), 32);
        assert_eq!(hmac_key.len(), 32);

        // In V1, both keys are the same
        assert_eq!(enc_key, hmac_key);

        // Keys should be deterministic
        let (enc_key2, _) = v1::derive_keys(&shared_secret);
        assert_eq!(enc_key, enc_key2);
    }

    #[test]
    fn test_v2_authenticate() {
        let key = [0x42u8; 32];
        let data = b"client_data_hash";

        let mac = v2::authenticate(&key, data);
        assert_eq!(mac.len(), 16);

        assert!(v2::verify(&key, data, &mac));
        assert!(!v2::verify(&key, b"wrong_data", &mac));
    }

    #[test]
    fn test_v2_encrypt_decrypt() {
        let key = [0x42u8; 32];
        // V2 uses AES-CBC which requires plaintext to be block-aligned (16 bytes)
        let plaintext = b"Hello, FIDO2!123"; // 16 bytes

        let ciphertext = v2::encrypt(&key, plaintext).unwrap();
        let decrypted = v2::decrypt(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_v2_derive_keys() {
        let shared_secret = [0x55u8; 32];
        let hmac_key = v2::derive_hmac_key(&shared_secret);
        let enc_key = v2::derive_encryption_key(&shared_secret);

        assert_eq!(hmac_key.len(), 32);
        assert_eq!(enc_key.len(), 32);

        // In V2, keys should be different
        assert_ne!(hmac_key, enc_key);
    }

    #[test]
    fn test_v1_v2_compatibility() {
        // V1 and V2 should produce same authentication result
        // when using the same key
        let key = [0x42u8; 32];
        let data = b"client_data_hash";

        let mac_v1 = v1::authenticate(&key, data);
        let mac_v2 = v2::authenticate(&key, data);

        assert_eq!(mac_v1, mac_v2);
    }

    #[test]
    fn test_constant_time_verification() {
        let key = [0x42u8; 32];
        let data = b"test_data";

        let correct_mac = v1::authenticate(&key, data);
        let mut wrong_mac = correct_mac;
        wrong_mac[0] ^= 0x01; // Flip one bit

        // Both should complete without timing differences
        assert!(v1::verify(&key, data, &correct_mac));
        assert!(!v1::verify(&key, data, &wrong_mac));
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = b"";

        let ciphertext = v1::encrypt(&key, plaintext).unwrap();
        // Should have padding even for empty plaintext
        assert!(!ciphertext.is_empty());

        let decrypted = v1::decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_long_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = vec![0x55u8; 1000]; // 1KB

        let ciphertext = v1::encrypt(&key, &plaintext).unwrap();
        let decrypted = v1::decrypt(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
