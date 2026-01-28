//! CTAP Extension Processing
//!
//! Implements CTAP extensions for enhanced functionality:
//! - credProtect: Credential protection policy (fully implemented)
//! - hmac-secret: HMAC-based secrets for credentials (fully implemented)
//!
//! # Extension Implementation Status
//!
//! | Extension | makeCredential | getAssertion |
//! |-----------|----------------|--------------|
//! | credProtect | ✅ Full | ✅ Full |
//! | hmac-secret | ✅ Full | ✅ Full |
//! | credBlob | ✅ Full | ⚠️ Stub |
//! | largeBlobKey | ✅ Full | ⚠️ Stub |
//! | minPinLength | ✅ Full | N/A |
//!
//! ## hmac-secret Extension
//!
//! The hmac-secret extension provides a way to derive symmetric secrets from
//! a credential. During makeCredential, a 32-byte random `cred_random` is
//! generated and stored with the credential. During getAssertion, the platform
//! provides an encrypted salt, and the authenticator returns
//! HMAC-SHA-256(cred_random, salt).
//!
//! This extension is the foundation for WebAuthn's PRF extension, which allows
//! web applications to derive symmetric keys from passkeys.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-extensions>

use crate::status::Result;

use alloc::string::ToString;
use alloc::{vec, vec::Vec};
use rand::RngCore;
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
    /// Key agreement (platform's public key in SEC1 uncompressed format)
    pub key_agreement: Vec<u8>,

    /// Salt (encrypted)
    pub salt_enc: Vec<u8>,

    /// Salt authentication
    pub salt_auth: Vec<u8>,

    /// PIN/UV auth protocol version
    pub pin_uv_auth_protocol: u8,
}

/// Parse a COSE_Key (P-256 EC2) to SEC1 uncompressed format (0x04 || x || y)
///
/// COSE_Key for P-256 has:
/// - 1: kty = 2 (EC2)
/// - 3: alg = -25 (ECDH-ES + HKDF-256)
/// - -1: crv = 1 (P-256)
/// - -2: x coordinate (32 bytes)
/// - -3: y coordinate (32 bytes)
fn parse_cose_key_to_sec1(cose_key: &[(crate::cbor::Value, crate::cbor::Value)]) -> Vec<u8> {
    let mut x: Option<&[u8]> = None;
    let mut y: Option<&[u8]> = None;

    for (k, v) in cose_key {
        if let crate::cbor::Value::Integer(key_int) = k {
            let key_i: i128 = *key_int;
            match key_i {
                -2 => {
                    // x coordinate
                    if let crate::cbor::Value::Bytes(b) = v {
                        x = Some(b.as_slice());
                    }
                }
                -3 => {
                    // y coordinate
                    if let crate::cbor::Value::Bytes(b) = v {
                        y = Some(b.as_slice());
                    }
                }
                _ => {} // Ignore other fields
            }
        }
    }

    // Build SEC1 uncompressed point: 0x04 || x || y
    if let (Some(x_bytes), Some(y_bytes)) = (x, y) {
        if x_bytes.len() == 32 && y_bytes.len() == 32 {
            let mut result = vec![0x04u8];
            result.extend_from_slice(x_bytes);
            result.extend_from_slice(y_bytes);
            return result;
        }
    }

    // Return empty if parsing failed
    Vec::new()
}

impl GetAssertionExtensions {
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
                    ext_ids::HMAC_SECRET => {
                        // hmac-secret input is a map with:
                        // 1: keyAgreement (COSE_Key)
                        // 2: saltEnc
                        // 3: saltAuth
                        // 4: pinUvAuthProtocol (optional, defaults to 1)
                        if let crate::cbor::Value::Map(hmac_map) = val {
                            let mut key_agreement: Option<Vec<u8>> = None;
                            let mut salt_enc: Option<Vec<u8>> = None;
                            let mut salt_auth: Option<Vec<u8>> = None;
                            let mut pin_uv_auth_protocol: u8 = 1; // Default to protocol 1

                            for (hkey, hval) in hmac_map {
                                if let crate::cbor::Value::Integer(key_int) = hkey {
                                    let key_i: i128 = *key_int;
                                    match key_i {
                                        1 => {
                                            // keyAgreement is a COSE_Key - extract public key bytes
                                            if let crate::cbor::Value::Map(cose_key) = hval {
                                                key_agreement =
                                                    Some(parse_cose_key_to_sec1(cose_key));
                                            }
                                        }
                                        2 => {
                                            // saltEnc - encrypted salt(s)
                                            if let crate::cbor::Value::Bytes(b) = hval {
                                                salt_enc = Some(b.clone());
                                            }
                                        }
                                        3 => {
                                            // saltAuth - HMAC of saltEnc
                                            if let crate::cbor::Value::Bytes(b) = hval {
                                                salt_auth = Some(b.clone());
                                            }
                                        }
                                        4 => {
                                            // pinUvAuthProtocol
                                            if let crate::cbor::Value::Integer(p) = hval {
                                                let p_val: i128 = *p;
                                                if let Ok(p8) = u8::try_from(p_val) {
                                                    pin_uv_auth_protocol = p8;
                                                }
                                            }
                                        }
                                        _ => {} // Ignore unknown keys
                                    }
                                }
                            }

                            // All required fields must be present
                            if let (Some(ka), Some(se), Some(sa)) =
                                (key_agreement, salt_enc, salt_auth)
                            {
                                exts.hmac_secret = Some(HmacSecretInput {
                                    key_agreement: ka,
                                    salt_enc: se,
                                    salt_auth: sa,
                                    pin_uv_auth_protocol,
                                });
                            }
                        }
                    }
                    ext_ids::CRED_BLOB => {
                        if let crate::cbor::Value::Bool(b) = val {
                            exts.get_cred_blob = Some(*b);
                        }
                    }
                    ext_ids::LARGE_BLOB_KEY => {
                        if let crate::cbor::Value::Bool(b) = val {
                            exts.large_blob_key = Some(*b);
                        }
                    }
                    _ => {} // Ignore unknown extensions
                }
            }
        }

        Ok(exts)
    }

    /// Build extension outputs for getAssertion response
    pub fn build_outputs(&self) -> Option<crate::cbor::Value> {
        // This is a stub - the actual hmac-secret output is computed via compute_hmac_secret
        None
    }

    /// Check if hmac-secret extension is requested
    pub fn has_hmac_secret(&self) -> bool {
        self.hmac_secret.is_some()
    }

    /// Get the hmac-secret input if present
    pub fn get_hmac_secret(&self) -> Option<&HmacSecretInput> {
        self.hmac_secret.as_ref()
    }
}

/// Compute hmac-secret extension output
///
/// Per FIDO2 CTAP2.1 spec (section 12.4), the hmac-secret extension:
/// 1. Platform provides keyAgreement (its ephemeral public key) for ECDH
/// 2. Authenticator performs ECDH to establish shared secret
/// 3. Authenticator derives keys and verifies saltAuth
/// 4. Authenticator decrypts salts, computes HMAC(credRandom, salt), encrypts output
/// 5. Authenticator returns its public key + encrypted output
///
/// # Arguments
/// * `input` - The hmac-secret extension input from the client
/// * `cred_random` - The 32-byte credential random from the credential
///
/// # Returns
/// * `Some((public_key, encrypted_output))` - Authenticator's public key (COSE format) and encrypted HMAC output
/// * `None` - If computation failed
pub fn compute_hmac_secret(
    input: &HmacSecretInput,
    cred_random: &[u8],
) -> Option<(crate::cbor::Value, Vec<u8>)> {
    // Validate input
    if input.key_agreement.is_empty() || input.salt_enc.is_empty() || cred_random.len() != 32 {
        return None;
    }

    // Generate authenticator's ephemeral key pair for ECDH
    let auth_keypair = soft_fido2_crypto::ecdh::KeyPair::generate().ok()?;

    // Compute shared secret with platform's public key
    let shared_secret = auth_keypair.shared_secret(&input.key_agreement).ok()?;

    // Derive keys based on PIN protocol version
    let (hmac_key, enc_key) = match input.pin_uv_auth_protocol {
        1 => {
            let (enc, hmac) =
                soft_fido2_crypto::pin_protocol::v1::derive_keys(&shared_secret);
            (hmac, enc)
        }
        2 => {
            let hmac = soft_fido2_crypto::pin_protocol::v2::derive_hmac_key(&shared_secret);
            let enc =
                soft_fido2_crypto::pin_protocol::v2::derive_encryption_key(&shared_secret);
            (hmac, enc)
        }
        _ => return None, // Unsupported protocol
    };

    // Verify saltAuth
    let valid = match input.pin_uv_auth_protocol {
        1 => {
            if input.salt_auth.len() < 16 {
                return None;
            }
            let mut expected = [0u8; 16];
            expected.copy_from_slice(&input.salt_auth[..16]);
            soft_fido2_crypto::pin_protocol::v1::verify(&hmac_key, &input.salt_enc, &expected)
        }
        2 => {
            if input.salt_auth.len() < 32 {
                return None;
            }
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&input.salt_auth[..32]);
            soft_fido2_crypto::pin_protocol::v2::verify(&hmac_key, &input.salt_enc, &expected)
        }
        _ => return None,
    };

    if !valid {
        return None;
    }

    // Decrypt salt(s)
    let salts = match input.pin_uv_auth_protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::decrypt(&enc_key, &input.salt_enc).ok()?,
        2 => soft_fido2_crypto::pin_protocol::v2::decrypt(&enc_key, &input.salt_enc).ok()?,
        _ => return None,
    };

    // Validate salt length (32 bytes for one salt, 64 bytes for two salts)
    if salts.len() != 32 && salts.len() != 64 {
        return None;
    }

    // Compute HMAC output(s)
    // Use the hmac and sha2 crates from soft_fido2_crypto's re-exports
    let mut output = Vec::new();

    // First salt (always present)
    let salt1 = &salts[..32];
    let output1 = soft_fido2_crypto::hmac_sha256(cred_random, salt1);
    output.extend_from_slice(&output1);

    // Second salt (optional)
    if salts.len() == 64 {
        let salt2 = &salts[32..64];
        let output2 = soft_fido2_crypto::hmac_sha256(cred_random, salt2);
        output.extend_from_slice(&output2);
    }

    // Encrypt output
    let encrypted = match input.pin_uv_auth_protocol {
        1 => soft_fido2_crypto::pin_protocol::v1::encrypt(&enc_key, &output).ok()?,
        2 => soft_fido2_crypto::pin_protocol::v2::encrypt(&enc_key, &output).ok()?,
        _ => return None,
    };

    // Build authenticator's public key in COSE_Key format
    let (x, y) = auth_keypair.public_key_cose();
    let public_key = crate::cbor::Value::Map(vec![
        // kty: 2 (EC2)
        (
            crate::cbor::Value::Integer(1.into()),
            crate::cbor::Value::Integer(2.into()),
        ),
        // alg: -25 (ECDH-ES+HKDF-256)
        (
            crate::cbor::Value::Integer(3.into()),
            crate::cbor::Value::Integer((-25i32).into()),
        ),
        // crv: 1 (P-256)
        (
            crate::cbor::Value::Integer((-1i32).into()),
            crate::cbor::Value::Integer(1.into()),
        ),
        // x: x-coordinate
        (
            crate::cbor::Value::Integer((-2i32).into()),
            crate::cbor::Value::Bytes(x.to_vec()),
        ),
        // y: y-coordinate
        (
            crate::cbor::Value::Integer((-3i32).into()),
            crate::cbor::Value::Bytes(y.to_vec()),
        ),
    ]);

    Some((public_key, encrypted))
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
