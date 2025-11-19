//! authenticatorGetInfo command
//!
//! Returns information about the authenticator including:
//! - Supported versions
//! - AAGUID
//! - Options (rk, up, uv, etc.)
//! - PIN/UV protocols
//! - Supported algorithms
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetInfo>

use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::cbor::MapBuilder;
use crate::status::Result;
use serde::Serialize;

/// GetInfo response keys
#[allow(dead_code)]
mod keys {
    pub const VERSIONS: i32 = 0x01;
    pub const EXTENSIONS: i32 = 0x02;
    pub const AAGUID: i32 = 0x03;
    pub const OPTIONS: i32 = 0x04;
    pub const MAX_MSG_SIZE: i32 = 0x05;
    pub const PIN_UV_AUTH_PROTOCOLS: i32 = 0x06;
    pub const MAX_CREDENTIAL_COUNT_IN_LIST: i32 = 0x07;
    pub const MAX_CREDENTIAL_ID_LENGTH: i32 = 0x08;
    pub const TRANSPORTS: i32 = 0x09;
    pub const ALGORITHMS: i32 = 0x0A;
    pub const MAX_SERIALIZED_LARGE_BLOB_ARRAY: i32 = 0x0B;
    pub const FORCE_PIN_CHANGE: i32 = 0x0C;
    pub const MIN_PIN_LENGTH: i32 = 0x0D;
    pub const FIRMWARE_VERSION: i32 = 0x0E;
    pub const MAX_CRED_BLOB_LENGTH: i32 = 0x0F;
    pub const MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH: i32 = 0x10;
    pub const PREFERRED_PLATFORM_UV_ATTEMPTS: i32 = 0x11;
    pub const UV_MODALITY: i32 = 0x12;
    pub const CERTIFICATIONS: i32 = 0x13;
    pub const REMAINING_DISCOVERABLE_CREDENTIALS: i32 = 0x14;
    pub const VENDOR_PROTOTYPE_CONFIG_COMMANDS: i32 = 0x15;
}

/// Handle authenticatorGetInfo command
///
/// This command requires no input and returns the authenticator's capabilities.
pub fn handle<C: AuthenticatorCallbacks>(auth: &Authenticator<C>) -> Result<Vec<u8>> {
    let config = auth.config();

    // Build response map
    let mut builder = MapBuilder::new();

    // Versions (0x01) - required
    let versions = vec!["FIDO_2_0".to_string(), "FIDO_2_1".to_string()];
    builder = builder.insert(keys::VERSIONS, versions)?;

    // Extensions (0x02) - optional
    if !config.extensions.is_empty() {
        builder = builder.insert(keys::EXTENSIONS, &config.extensions)?;
    }

    // AAGUID (0x03) - required (must be CBOR bytes, not array!)
    builder = builder.insert_bytes(keys::AAGUID, &config.aaguid)?;

    // Options (0x04) - optional but recommended
    #[derive(Serialize)]
    struct Options {
        #[serde(skip_serializing_if = "Option::is_none")]
        rk: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        up: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        uv: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        plat: Option<bool>,
        #[serde(rename = "clientPin", skip_serializing_if = "Option::is_none")]
        client_pin: Option<bool>,
        #[serde(
            rename = "credentialMgmtPreview",
            skip_serializing_if = "Option::is_none"
        )]
        credential_mgmt_preview: Option<bool>,
        #[serde(rename = "credMgmt", skip_serializing_if = "Option::is_none")]
        cred_mgmt: Option<bool>,
        #[serde(rename = "makeCredUvNotRqd", skip_serializing_if = "Option::is_none")]
        make_cred_uv_not_required: Option<bool>,
    }

    // Determine clientPin value: use configured option if set, otherwise check actual PIN state
    let client_pin_value = config
        .options
        .client_pin
        .unwrap_or_else(|| auth.is_pin_set());

    let options = Options {
        rk: Some(config.options.rk),
        up: Some(config.options.up),
        uv: config.options.uv,
        plat: Some(config.options.plat),
        client_pin: Some(client_pin_value),
        credential_mgmt_preview: Some(config.options.cred_mgmt),
        cred_mgmt: Some(config.options.cred_mgmt),
        make_cred_uv_not_required: if config.options.make_cred_uv_not_required {
            Some(true)
        } else {
            None
        },
    };
    builder = builder.insert(keys::OPTIONS, options)?;

    // Max message size (0x05) - Optional, not required by spec
    // if let Some(max_msg_size) = config.max_msg_size {
    //     builder = builder.insert(keys::MAX_MSG_SIZE, max_msg_size)?;
    // }

    // PIN/UV auth protocols (0x06) - required if clientPin option is present
    builder = builder.insert(keys::PIN_UV_AUTH_PROTOCOLS, &config.pin_uv_auth_protocols)?;

    // Max credential count in list (0x07) - Optional, not commonly used
    // builder = builder.insert(keys::MAX_CREDENTIAL_COUNT_IN_LIST, config.max_credentials)?;

    // Max credential ID length (0x08) - Optional, not commonly used
    // if let Some(max_cred_id_len) = config.max_credential_id_length {
    //     builder = builder.insert(keys::MAX_CREDENTIAL_ID_LENGTH, max_cred_id_len)?;
    // }

    // Transports (0x09) - optional
    if !config.transports.is_empty() {
        builder = builder.insert(keys::TRANSPORTS, &config.transports)?;
    }

    // Algorithms (0x0A) - optional but recommended
    #[derive(Serialize)]
    struct AlgEntry {
        #[serde(rename = "type")]
        typ: String,
        alg: i32,
    }

    let algorithms: Vec<AlgEntry> = config
        .algorithms
        .iter()
        .map(|&alg| AlgEntry {
            typ: "public-key".to_string(),
            alg,
        })
        .collect();

    if !algorithms.is_empty() {
        builder = builder.insert(keys::ALGORITHMS, algorithms)?;
    }

    // Firmware version (0x0E) - optional
    if let Some(fw_version) = config.firmware_version {
        builder = builder.insert(keys::FIRMWARE_VERSION, fw_version)?;
    }

    // Max cred blob length (0x0F) - Optional, not commonly used
    // if let Some(max_cred_blob_len) = config.max_cred_blob_length {
    //     builder = builder.insert(keys::MAX_CRED_BLOB_LENGTH, max_cred_blob_len)?;
    // }

    // Min PIN length (0x0D) - Optional, not commonly advertised
    // if auth.is_pin_set() {
    //     builder = builder.insert(keys::MIN_PIN_LENGTH, auth.min_pin_length())?;
    // }

    // Remaining discoverable credentials (0x14) - optional
    let remaining = auth.remaining_discoverable_credentials();
    if let Some(remaining_count) = remaining {
        builder = builder.insert(keys::REMAINING_DISCOVERABLE_CREDENTIALS, remaining_count)?;
    }

    let response = builder.build()?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::AuthenticatorConfig;
    use crate::callbacks::{
        CredentialStorageCallbacks, UpResult, UserInteractionCallbacks, UvResult,
    };
    use crate::cbor::MapParser;
    use crate::status::StatusCode;
    use crate::types::Credential;

    // Simple mock for testing
    struct MockCallbacks;

    impl MockCallbacks {
        fn new() -> Self {
            Self
        }
    }

    impl UserInteractionCallbacks for MockCallbacks {
        fn request_up(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> crate::status::Result<UpResult> {
            Ok(UpResult::Accepted)
        }

        fn request_uv(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> crate::status::Result<UvResult> {
            Ok(UvResult::Accepted)
        }

        fn select_credential(
            &self,
            _rp_id: &str,
            _user_names: &[String],
        ) -> crate::status::Result<usize> {
            Ok(0)
        }
    }

    impl CredentialStorageCallbacks for MockCallbacks {
        fn write_credential(&self, _credential: &Credential) -> crate::status::Result<()> {
            Ok(())
        }

        fn delete_credential(&self, _credential_id: &[u8]) -> crate::status::Result<()> {
            Ok(())
        }

        fn read_credentials(
            &self,
            _rp_id: &str,
            _user_id: Option<&[u8]>,
        ) -> crate::status::Result<Vec<Credential>> {
            Ok(Vec::new())
        }

        fn get_credential(&self, _credential_id: &[u8]) -> crate::status::Result<Credential> {
            Err(StatusCode::NoCredentials)
        }

        fn update_credential(&self, _credential: &Credential) -> crate::status::Result<()> {
            Ok(())
        }

        fn enumerate_rps(&self) -> crate::status::Result<Vec<(String, Option<String>, usize)>> {
            Ok(Vec::new())
        }

        fn credential_exists(&self, _credential_id: &[u8]) -> crate::status::Result<bool> {
            Ok(false)
        }

        fn credential_count(&self) -> crate::status::Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn test_get_info_basic() {
        let config = AuthenticatorConfig::new();
        let callbacks = MockCallbacks::new();
        let auth = Authenticator::new(config, callbacks);

        let response = handle(&auth).unwrap();
        let parser = MapParser::from_bytes(&response).unwrap();

        // Check required fields
        let versions: Vec<String> = parser.get(keys::VERSIONS).unwrap();
        assert!(versions.contains(&"FIDO_2_0".to_string()));
        assert!(versions.contains(&"FIDO_2_1".to_string()));

        let aaguid = parser.get_bytes(keys::AAGUID).unwrap();
        assert_eq!(aaguid.len(), 16);

        let protocols: Vec<u8> = parser.get(keys::PIN_UV_AUTH_PROTOCOLS).unwrap();
        assert!(protocols.contains(&1) || protocols.contains(&2));
    }

    #[test]
    fn test_get_info_with_extensions() {
        let config = AuthenticatorConfig::new()
            .with_extensions(vec!["credProtect".to_string(), "hmac-secret".to_string()]);
        let callbacks = MockCallbacks::new();
        let auth = Authenticator::new(config, callbacks);

        let response = handle(&auth).unwrap();
        let parser = MapParser::from_bytes(&response).unwrap();

        let extensions: Vec<String> = parser.get(keys::EXTENSIONS).unwrap();
        assert_eq!(extensions.len(), 2);
        assert!(extensions.contains(&"credProtect".to_string()));
    }

    #[test]
    fn test_get_info_with_algorithms() {
        let config = AuthenticatorConfig::new().with_algorithms(vec![-7, -8]); // ES256, EdDSA
        let callbacks = MockCallbacks::new();
        let auth = Authenticator::new(config, callbacks);

        let response = handle(&auth).unwrap();
        let parser = MapParser::from_bytes(&response).unwrap();

        // Algorithms should be present
        assert!(parser.contains_key(keys::ALGORITHMS));
    }
}
