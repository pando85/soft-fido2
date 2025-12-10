//! CTAP2 PIN Protocol Support
//!
//! Provides PIN/UV authentication protocol implementation for CTAP2.

use crate::error::{Error, Result};
use crate::request::PinUvAuthProtocol;
use crate::transport::Transport;

use soft_fido2_crypto::pin_protocol;
use soft_fido2_ctap::SecBytes;
use soft_fido2_ctap::cbor::{MapBuilder, Value};

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// PIN protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProtocol {
    /// PIN protocol version 1 (AES-256-CBC + HMAC-SHA-256)
    V1,
    /// PIN protocol version 2 (HMAC-SECRET)
    V2,
}

impl From<PinProtocol> for PinUvAuthProtocol {
    fn from(protocol: PinProtocol) -> Self {
        match protocol {
            PinProtocol::V1 => PinUvAuthProtocol::V1,
            PinProtocol::V2 => PinUvAuthProtocol::V2,
        }
    }
}

impl From<PinUvAuthProtocol> for PinProtocol {
    fn from(protocol: PinUvAuthProtocol) -> Self {
        match protocol {
            PinUvAuthProtocol::V1 => PinProtocol::V1,
            PinUvAuthProtocol::V2 => PinProtocol::V2,
        }
    }
}

/// PIN/UV authentication encapsulation
pub struct PinUvAuthEncapsulation {
    protocol: PinProtocol,
    /// Platform's ECDH secret key (32 bytes, memory-protected)
    platform_secret: Option<SecBytes>,
    /// Platform's public key (65 bytes uncompressed, not secret)
    platform_public: Option<[u8; 65]>,
    /// Authenticator's public key (from getKeyAgreement)
    authenticator_key: Option<P256PublicKey>,
    /// Shared secret derived from ECDH (32 bytes, memory-protected)
    shared_secret: Option<SecBytes>,
    /// PIN token (32 bytes, memory-protected)
    pin_token: Option<SecBytes>,
}

impl PinUvAuthEncapsulation {
    /// Create a new PIN/UV authentication encapsulation
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to use for initialization (performs key agreement)
    /// * `protocol` - The PIN protocol version to use
    pub fn new(transport: &mut Transport, protocol: PinProtocol) -> Result<Self> {
        let mut encap = Self {
            protocol,
            platform_secret: None,
            platform_public: None,
            authenticator_key: None,
            shared_secret: None,
            pin_token: None,
        };

        // Perform key agreement immediately
        encap.initialize(transport)?;

        Ok(encap)
    }

    /// Initialize the encapsulation by performing key agreement
    ///
    /// This sends clientPin subcommand 0x02 (getKeyAgreement) to the authenticator.
    pub fn initialize(&mut self, transport: &mut Transport) -> Result<()> {
        // Generate platform key pair (using SecretKey for persistence)
        let platform_secret_key = P256SecretKey::random(&mut OsRng);
        let platform_public_key = platform_secret_key.public_key();
        let platform_public_point = platform_public_key.to_encoded_point(false);

        // Store platform secret key (memory-protected)
        let secret_bytes: [u8; 32] = *platform_secret_key.to_bytes().as_ref();
        self.platform_secret = Some(SecBytes::from_slice(&secret_bytes));

        let public_bytes = platform_public_point.as_bytes();
        let mut public_array = [0u8; 65];
        public_array.copy_from_slice(public_bytes);
        self.platform_public = Some(public_array);

        // Build getKeyAgreement request using MapBuilder
        let protocol_version = match self.protocol {
            PinProtocol::V1 => 1u8,
            PinProtocol::V2 => 2u8,
        };

        let request_bytes = MapBuilder::new()
            .insert(1, protocol_version) // pinUvAuthProtocol
            .map_err(|_| Error::Other)?
            .insert(2, 0x02u8) // subCommand (getKeyAgreement = 0x02)
            .map_err(|_| Error::Other)?
            .build()
            .map_err(|_| Error::Other)?;

        // Send clientPin command (0x06) with 30s timeout
        let response = transport.send_ctap_command(0x06, &request_bytes, 30000)?;

        // Transport layer already checked status byte and returns only CBOR data for success
        if response.is_empty() {
            return Err(Error::Other);
        }

        // Parse CBOR response (entire response is CBOR data)
        let response_value: Value =
            soft_fido2_ctap::cbor::decode(&response).map_err(|_| Error::Other)?;

        // Extract keyAgreement from response (should be in response[0x01])
        let authenticator_cose_key = match response_value {
            Value::Map(map) => map
                .iter()
                .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 1.into()))
                .map(|(_, v)| v.clone())
                .ok_or(Error::Other)?,
            _ => return Err(Error::Other),
        };

        // Parse COSE key to get P-256 public key
        let authenticator_public_key = Self::parse_cose_key(&authenticator_cose_key)?;

        // Perform ECDH to derive shared secret
        use p256::ecdh::diffie_hellman;
        let shared_secret = diffie_hellman(
            platform_secret_key.to_nonzero_scalar(),
            authenticator_public_key.as_affine(),
        );

        // Store authenticator key and shared secret (memory-protected)
        self.authenticator_key = Some(authenticator_public_key);
        let shared_secret_bytes = shared_secret.raw_secret_bytes();
        self.shared_secret = Some(SecBytes::from_slice(shared_secret_bytes.as_slice()));

        Ok(())
    }

    /// Get a PIN/UV auth token using PIN with permissions
    ///
    /// This is the recommended way to get a PIN token in CTAP 2.1.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `pin` - The user's PIN
    /// * `permissions` - Permission flags (0x01 = makeCredential, 0x02 = getAssertion, etc.)
    /// * `rp_id` - Optional RP ID to scope the permission
    pub fn get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        transport: &mut Transport,
        pin: &str,
        permissions: u8,
        rp_id: Option<&str>,
    ) -> Result<Vec<u8>> {
        let shared_secret = self.shared_secret.as_ref().ok_or(Error::Other)?;

        // Compute PIN hash (zeroized on drop)
        let pin_hash = Zeroizing::new({
            use sha2::{Digest, Sha256};
            let hash: [u8; 32] = Sha256::digest(pin.as_bytes()).into();
            hash
        });

        // Derive keys (zeroized on drop)
        let (enc_key, _hmac_key) = self.derive_keys_zeroized(shared_secret.as_slice())?;

        let pin_hash_enc =
            match self.protocol {
                PinProtocol::V1 => pin_protocol::v1::encrypt(&enc_key, &pin_hash[..16])
                    .map_err(|_| Error::Other)?,
                PinProtocol::V2 => pin_protocol::v2::encrypt(&enc_key, &pin_hash[..16])
                    .map_err(|_| Error::Other)?,
            };

        // Get platform key agreement parameter
        let platform_key_agreement = self.get_key_agreement_cose()?;

        let protocol_version = match self.protocol {
            PinProtocol::V1 => 1u8,
            PinProtocol::V2 => 2u8,
        };

        let mut builder = MapBuilder::new();
        builder = builder
            .insert(1, protocol_version)
            .map_err(|_| Error::Other)?;
        builder = builder
            .insert(2, 0x09u8) // subCommand (getPinUvAuthTokenUsingPinWithPermissions)
            .map_err(|_| Error::Other)?;
        builder = builder
            .insert(3, &platform_key_agreement)
            .map_err(|_| Error::Other)?;
        builder = builder
            .insert_bytes(6, &pin_hash_enc)
            .map_err(|_| Error::Other)?;
        builder = builder.insert(9, permissions).map_err(|_| Error::Other)?;

        if let Some(rp_id_str) = rp_id {
            builder = builder.insert(10, rp_id_str).map_err(|_| Error::Other)?;
        }

        let request_bytes = builder.build().map_err(|_| Error::Other)?;

        let response = transport.send_ctap_command(0x06, &request_bytes, 30000)?;

        if response.is_empty() {
            return Err(Error::Other);
        }

        let response_value: Value =
            soft_fido2_ctap::cbor::decode(&response).map_err(|_| Error::Other)?;

        let pin_token_enc = match response_value {
            Value::Map(map) => map
                .iter()
                .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 2.into()))
                .and_then(|(_, v)| match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or(Error::Other)?,
            _ => return Err(Error::Other),
        };

        // Decrypt PIN token
        let pin_token = Zeroizing::new(match self.protocol {
            PinProtocol::V1 => {
                let decrypted = pin_protocol::v1::decrypt(&enc_key, &pin_token_enc)
                    .map_err(|_| Error::Other)?;
                let mut token = [0u8; 32];
                token.copy_from_slice(&decrypted[..32]);
                token
            }
            PinProtocol::V2 => {
                let decrypted = pin_protocol::v2::decrypt(&enc_key, &pin_token_enc)
                    .map_err(|_| Error::Other)?;
                let mut token = [0u8; 32];
                token.copy_from_slice(&decrypted[..32]);
                token
            }
        });

        // Store PIN token (memory-protected)
        self.pin_token = Some(SecBytes::from_slice(&*pin_token));

        Ok(pin_token.to_vec())
    }

    /// Get PIN/UV auth token using built-in user verification (UV)
    ///
    /// This method uses the authenticator's built-in user verification (biometric/fingerprint)
    /// instead of PIN authentication. This is useful when:
    /// - No PIN is set on the authenticator
    /// - The authenticator supports biometric UV
    /// - UV is preferred over PIN
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `permissions` - Permission flags (0x01 = makeCredential, 0x02 = getAssertion, etc.)
    /// * `rp_id` - Optional RP ID to scope the permission
    pub fn get_pin_uv_auth_token_using_uv_with_permissions(
        &mut self,
        transport: &mut Transport,
        permissions: u8,
        rp_id: Option<&str>,
    ) -> Result<Vec<u8>> {
        // Get platform key agreement parameter
        let platform_key_agreement = self.get_key_agreement_cose()?;

        // Build getPinUvAuthTokenUsingUvWithPermissions request
        let protocol_version = match self.protocol {
            PinProtocol::V1 => 1u8,
            PinProtocol::V2 => 2u8,
        };

        let mut builder = MapBuilder::new();
        builder = builder
            .insert(1, protocol_version) // pinUvAuthProtocol
            .map_err(|_| Error::Other)?;
        builder = builder
            .insert(2, 0x06u8) // subCommand (getPinUvAuthTokenUsingUvWithPermissions = 0x06)
            .map_err(|_| Error::Other)?;
        builder = builder
            .insert(3, &platform_key_agreement) // keyAgreement
            .map_err(|_| Error::Other)?;
        builder = builder
            .insert(9, permissions) // permissions
            .map_err(|_| Error::Other)?;

        if let Some(rp_id_str) = rp_id {
            builder = builder
                .insert(10, rp_id_str) // rpId
                .map_err(|_| Error::Other)?;
        }

        let request_bytes = builder.build().map_err(|_| Error::Other)?;

        // Send clientPin command (0x06) with 30s timeout
        let response = transport.send_ctap_command(0x06, &request_bytes, 30000)?;

        // Transport layer already checked status byte and returns only CBOR data for success
        if response.is_empty() {
            return Err(Error::Other);
        }

        // Parse CBOR response (entire response is CBOR data)
        let response_value: Value =
            soft_fido2_ctap::cbor::decode(&response).map_err(|_| Error::Other)?;

        let pin_token_enc = match response_value {
            Value::Map(map) => map
                .iter()
                .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 2.into()))
                .and_then(|(_, v)| match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or(Error::Other)?,
            _ => return Err(Error::Other),
        };

        // Get shared secret and derive keys (zeroized on drop)
        let shared_secret = self.shared_secret.as_ref().ok_or(Error::Other)?;
        let (enc_key, _hmac_key) = self.derive_keys_zeroized(shared_secret.as_slice())?;

        // Decrypt PIN token (zeroized on drop)
        let pin_token = Zeroizing::new(match self.protocol {
            PinProtocol::V1 => {
                let decrypted = pin_protocol::v1::decrypt(&enc_key, &pin_token_enc)
                    .map_err(|_| Error::Other)?;
                let mut token = [0u8; 32];
                token.copy_from_slice(&decrypted[..32]);
                token
            }
            PinProtocol::V2 => {
                let decrypted = pin_protocol::v2::decrypt(&enc_key, &pin_token_enc)
                    .map_err(|_| Error::Other)?;
                let mut token = [0u8; 32];
                token.copy_from_slice(&decrypted[..32]);
                token
            }
        });

        // Store PIN token (memory-protected)
        self.pin_token = Some(SecBytes::from_slice(&*pin_token));

        Ok(pin_token.to_vec())
    }

    /// Calculate pinUvAuthParam for a request
    ///
    /// # Arguments
    ///
    /// * `data` - The data to authenticate (e.g., clientDataHash || rpIdHash for makeCredential)
    /// * `pin_token` - The PIN token obtained from get_pin_uv_auth_token_using_pin_with_permissions
    pub fn authenticate(&self, data: &[u8], pin_token: &[u8]) -> Result<Vec<u8>> {
        let pin_token_array: &[u8; 32] = pin_token.try_into().map_err(|_| Error::Other)?;
        let result = match self.protocol {
            PinProtocol::V1 => pin_protocol::v1::authenticate(pin_token_array, data).to_vec(),
            PinProtocol::V2 => pin_protocol::v2::authenticate(pin_token_array, data).to_vec(),
        };

        Ok(result)
    }

    /// Get the platform's key agreement parameter in COSE format
    fn get_key_agreement_cose(&self) -> Result<Value> {
        let secret_bytes = self.platform_secret.as_ref().ok_or(Error::Other)?;
        let secret_arr = secret_bytes.to_array::<32>().ok_or(Error::Other)?;
        let secret_key =
            P256SecretKey::from_bytes((&*secret_arr).into()).map_err(|_| Error::Other)?;
        let public_key = secret_key.public_key();
        let point = public_key.to_encoded_point(false);

        let key_map = vec![
            (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
            (Value::Integer(3.into()), Value::Integer((-25).into())), // alg: ECDH-ES+HKDF-256
            (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
            (
                Value::Integer((-2).into()),
                Value::Bytes(point.x().ok_or(Error::Other)?.to_vec()),
            ), // x
            (
                Value::Integer((-3).into()),
                Value::Bytes(point.y().ok_or(Error::Other)?.to_vec()),
            ), // y
        ];

        Ok(Value::Map(key_map))
    }

    /// Derive encryption and HMAC keys from shared secret (zeroized on drop)
    #[allow(clippy::type_complexity)]
    fn derive_keys_zeroized(
        &self,
        shared_secret: &[u8],
    ) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
        // Convert slice to fixed-size array
        let secret_arr: &[u8; 32] = shared_secret.try_into().map_err(|_| Error::Other)?;

        match self.protocol {
            PinProtocol::V1 => {
                let (enc, hmac) = pin_protocol::v1::derive_keys(secret_arr);
                Ok((Zeroizing::new(enc), Zeroizing::new(hmac)))
            }
            PinProtocol::V2 => {
                let enc = pin_protocol::v2::derive_encryption_key(secret_arr);
                let hmac = pin_protocol::v2::derive_hmac_key(secret_arr);
                Ok((Zeroizing::new(enc), Zeroizing::new(hmac)))
            }
        }
    }

    /// Parse a COSE key to extract P-256 public key
    fn parse_cose_key(cose_key: &Value) -> Result<P256PublicKey> {
        let map = match cose_key {
            Value::Map(m) => m,
            _ => return Err(Error::Other),
        };

        // Extract x and y coordinates
        let x = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if *i == (-2).into()))
            .and_then(|(_, v)| match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or(Error::Other)?;

        let y = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if *i == (-3).into()))
            .and_then(|(_, v)| match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or(Error::Other)?;

        // Create uncompressed SEC1 encoding: 0x04 || x || y
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);

        // Parse as P-256 public key
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        let point = p256::EncodedPoint::from_bytes(&uncompressed).map_err(|_| Error::Other)?;

        // CtOption::into() returns Option
        let public_key: Option<P256PublicKey> = P256PublicKey::from_encoded_point(&point).into();
        public_key.ok_or(Error::Other)
    }

    /// Set a new PIN on the authenticator
    ///
    /// This method sets the initial PIN on an authenticator that doesn't have one set.
    /// The PIN must be 4-63 UTF-8 characters.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `new_pin` - The new PIN to set (4-63 UTF-8 characters)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A PIN is already set on the authenticator
    /// - The PIN length is invalid (must be 4-63 characters)
    /// - The shared secret hasn't been established (call initialize first)
    /// - Communication with the authenticator fails
    pub fn set_pin(&mut self, transport: &mut Transport, new_pin: &str) -> Result<()> {
        let shared_secret = self.shared_secret.as_ref().ok_or(Error::Other)?;

        // Validate PIN length (CTAP spec: 4-63 Unicode code points)
        let pin_len = new_pin.chars().count();
        if !(4..=63).contains(&pin_len) {
            return Err(Error::InvalidPinLength);
        }

        // Pad PIN to 64 bytes with zeros (CTAP spec requirement, zeroized on drop)
        let padded_pin = Zeroizing::new({
            let mut buf = [0u8; 64];
            let pin_bytes = new_pin.as_bytes();
            if pin_bytes.len() > 64 {
                return Err(Error::InvalidPinLength);
            }
            buf[..pin_bytes.len()].copy_from_slice(pin_bytes);
            buf
        });

        // Derive keys (zeroized on drop)
        let (enc_key, hmac_key) = self.derive_keys_zeroized(shared_secret.as_slice())?;

        // Encrypt padded PIN
        let new_pin_enc = match self.protocol {
            PinProtocol::V1 => {
                pin_protocol::v1::encrypt(&enc_key, &*padded_pin).map_err(|_| Error::Other)?
            }
            PinProtocol::V2 => {
                pin_protocol::v2::encrypt(&enc_key, &*padded_pin).map_err(|_| Error::Other)?
            }
        };

        // Compute pinUvAuthParam = HMAC(hmac_key, newPinEnc)
        let pin_uv_auth_param = match self.protocol {
            PinProtocol::V1 => pin_protocol::v1::authenticate(&hmac_key, &new_pin_enc).to_vec(),
            PinProtocol::V2 => pin_protocol::v2::authenticate(&hmac_key, &new_pin_enc).to_vec(),
        };

        // Get platform key agreement parameter
        let platform_key_agreement = self.get_key_agreement_cose()?;

        // Build setPin request
        let protocol_version = match self.protocol {
            PinProtocol::V1 => 1u8,
            PinProtocol::V2 => 2u8,
        };

        let request_bytes = MapBuilder::new()
            .insert(1, protocol_version) // pinUvAuthProtocol
            .map_err(|_| Error::Other)?
            .insert(2, 0x03u8) // subCommand (setPin = 0x03)
            .map_err(|_| Error::Other)?
            .insert(3, &platform_key_agreement) // keyAgreement
            .map_err(|_| Error::Other)?
            .insert_bytes(4, &pin_uv_auth_param) // pinUvAuthParam
            .map_err(|_| Error::Other)?
            .insert_bytes(5, &new_pin_enc) // newPinEnc
            .map_err(|_| Error::Other)?
            .build()
            .map_err(|_| Error::Other)?;

        // Send clientPin command (0x06) with 30s timeout
        let _response = transport.send_ctap_command(0x06, &request_bytes, 30000)?;

        // Success - empty response means PIN was set
        Ok(())
    }

    /// Change the PIN on the authenticator
    ///
    /// This method changes an existing PIN to a new one.
    /// Both PINs must be 4-63 UTF-8 characters.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `current_pin` - The current PIN
    /// * `new_pin` - The new PIN to set (4-63 UTF-8 characters)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No PIN is set on the authenticator
    /// - The current PIN is incorrect
    /// - The new PIN length is invalid (must be 4-63 characters)
    /// - The shared secret hasn't been established (call initialize first)
    /// - Communication with the authenticator fails
    pub fn change_pin(
        &mut self,
        transport: &mut Transport,
        current_pin: &str,
        new_pin: &str,
    ) -> Result<()> {
        let shared_secret = self.shared_secret.as_ref().ok_or(Error::Other)?;

        // Validate new PIN length (CTAP spec: 4-63 Unicode code points)
        let pin_len = new_pin.chars().count();
        if !(4..=63).contains(&pin_len) {
            return Err(Error::InvalidPinLength);
        }

        // Compute current PIN hash (SHA-256, zeroized on drop)
        let current_pin_hash = Zeroizing::new({
            use sha2::{Digest, Sha256};
            let hash: [u8; 32] = Sha256::digest(current_pin.as_bytes()).into();
            hash
        });

        // Pad new PIN to 64 bytes with zeros (zeroized on drop)
        let padded_new_pin = Zeroizing::new({
            let mut buf = [0u8; 64];
            let new_pin_bytes = new_pin.as_bytes();
            if new_pin_bytes.len() > 64 {
                return Err(Error::InvalidPinLength);
            }
            buf[..new_pin_bytes.len()].copy_from_slice(new_pin_bytes);
            buf
        });

        // Derive keys (zeroized on drop)
        let (enc_key, hmac_key) = self.derive_keys_zeroized(shared_secret.as_slice())?;

        // Encrypt current PIN hash (first 16 bytes per CTAP spec)
        let pin_hash_enc = match self.protocol {
            PinProtocol::V1 => pin_protocol::v1::encrypt(&enc_key, &current_pin_hash[..16])
                .map_err(|_| Error::Other)?,
            PinProtocol::V2 => pin_protocol::v2::encrypt(&enc_key, &current_pin_hash[..16])
                .map_err(|_| Error::Other)?,
        };

        // Encrypt new padded PIN
        let new_pin_enc =
            match self.protocol {
                PinProtocol::V1 => pin_protocol::v1::encrypt(&enc_key, &*padded_new_pin)
                    .map_err(|_| Error::Other)?,
                PinProtocol::V2 => pin_protocol::v2::encrypt(&enc_key, &*padded_new_pin)
                    .map_err(|_| Error::Other)?,
            };

        // Compute pinUvAuthParam = HMAC(hmac_key, newPinEnc || pinHashEnc)
        let mut verify_data = new_pin_enc.clone();
        verify_data.extend_from_slice(&pin_hash_enc);

        let pin_uv_auth_param = match self.protocol {
            PinProtocol::V1 => pin_protocol::v1::authenticate(&hmac_key, &verify_data).to_vec(),
            PinProtocol::V2 => pin_protocol::v2::authenticate(&hmac_key, &verify_data).to_vec(),
        };

        // Get platform key agreement parameter
        let platform_key_agreement = self.get_key_agreement_cose()?;

        // Build changePin request
        let protocol_version = match self.protocol {
            PinProtocol::V1 => 1u8,
            PinProtocol::V2 => 2u8,
        };

        let request_bytes = MapBuilder::new()
            .insert(1, protocol_version) // pinUvAuthProtocol
            .map_err(|_| Error::Other)?
            .insert(2, 0x04u8) // subCommand (changePin = 0x04)
            .map_err(|_| Error::Other)?
            .insert(3, &platform_key_agreement) // keyAgreement
            .map_err(|_| Error::Other)?
            .insert_bytes(4, &pin_uv_auth_param) // pinUvAuthParam
            .map_err(|_| Error::Other)?
            .insert_bytes(5, &new_pin_enc) // newPinEnc
            .map_err(|_| Error::Other)?
            .insert_bytes(6, &pin_hash_enc) // pinHashEnc
            .map_err(|_| Error::Other)?
            .build()
            .map_err(|_| Error::Other)?;

        // Send clientPin command (0x06) with 30s timeout
        let _response = transport.send_ctap_command(0x06, &request_bytes, 30000)?;

        // Success - empty response means PIN was changed
        Ok(())
    }

    /// Get PIN retries remaining
    ///
    /// Returns the number of PIN attempts remaining before the authenticator is blocked.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    ///
    /// # Returns
    ///
    /// The number of PIN retries remaining (typically 0-8)
    pub fn get_pin_retries(&self, transport: &mut Transport) -> Result<u8> {
        // Build getPinRetries request
        let request_bytes = MapBuilder::new()
            .insert(2, 0x01u8) // subCommand (getPinRetries = 0x01)
            .map_err(|_| Error::Other)?
            .build()
            .map_err(|_| Error::Other)?;

        // Send clientPin command (0x06) with 30s timeout
        let response = transport.send_ctap_command(0x06, &request_bytes, 30000)?;

        if response.is_empty() {
            return Err(Error::Other);
        }

        // Parse CBOR response
        let response_value: Value =
            soft_fido2_ctap::cbor::decode(&response).map_err(|_| Error::Other)?;

        // Extract pinRetries from response (key 0x03)
        let retries = match response_value {
            Value::Map(map) => map
                .iter()
                .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 3.into()))
                .and_then(|(_, v)| match v {
                    Value::Integer(i) => {
                        let val: i128 = *i;
                        u8::try_from(val).ok()
                    }
                    _ => None,
                })
                .ok_or(Error::Other)?,
            _ => return Err(Error::Other),
        };

        Ok(retries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_protocol_conversion() {
        assert_eq!(PinProtocol::from(PinUvAuthProtocol::V1), PinProtocol::V1);
        assert_eq!(PinProtocol::from(PinUvAuthProtocol::V2), PinProtocol::V2);
    }
}
