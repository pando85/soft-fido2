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

use crate::{
    authenticator::Authenticator, callbacks::AuthenticatorCallbacks, cbor::MapBuilder,
    status::Result,
};

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use serde::Serialize;

/// Maximum number of credentials accepted in makeCredential excludeList and
/// getAssertion allowList. Keep this aligned with the command parsers.
const MAX_CREDENTIAL_COUNT_IN_LIST: usize = 128;

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

const FIDO_2_0: &str = "FIDO_2_0";

/// Return only version identifiers whose mandatory feature set is complete.
///
/// FIDO_2_1 and FIDO_2_3 both require a complete hmac-secret implementation.
/// Until dual credential secrets are persisted for discoverable and wrapped
/// credentials, advertising either version would be a false conformance claim.
fn advertised_versions() -> Vec<String> {
    vec![FIDO_2_0.to_string()]
}

/// Handle authenticatorGetInfo command
///
/// This command requires no input and returns the authenticator's capabilities.
pub fn handle<C: AuthenticatorCallbacks, K: crate::key_provider::CredentialKeyProvider>(
    auth: &Authenticator<C, K>,
) -> Result<Vec<u8>> {
    let config = auth.config();

    let mut builder = MapBuilder::new();

    // Versions (0x01) - required. Version advertisement is a
    // conformance claim, so it is gated on mandatory feature completeness.
    let versions = advertised_versions();
    builder = builder.insert(keys::VERSIONS, versions)?;

    // Advertise only extensions that are implemented end-to-end. Partial
    // credBlob, largeBlobKey and hmac-secret behavior must not influence a
    // platform's request path.
    let extensions: Vec<&String> = config
        .extensions
        .iter()
        .filter(|extension| extension.as_str() == crate::extensions::ext_ids::CRED_PROTECT)
        .collect();
    if !extensions.is_empty() {
        builder = builder.insert(keys::EXTENSIONS, extensions)?;
    }

    // AAGUID (0x03) - required (must be CBOR bytes, not an integer array).
    builder = builder.insert_bytes(keys::AAGUID, &config.aaguid)?;

    // Options (0x04). Fields are declared in canonical key order.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Options {
        #[serde(skip_serializing_if = "Option::is_none")]
        ep: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rk: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        up: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        uv: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        plat: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        always_uv: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cred_mgmt: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bio_enroll: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_pin: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pin_uv_auth_token: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        make_cred_uv_not_rqd: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_mgmt_preview: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        no_mc_ga_permissions_with_client_pin: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        user_verification_mgmt_preview: Option<bool>,
    }

    // clientPin communicates both support and whether a PIN is configured:
    // absent = unsupported, false = supported/not configured, true = configured.
    let client_pin_value = config.options.client_pin.map(|_| auth.is_pin_set());

    let options = Options {
        ep: config.options.ep,
        rk: Some(config.options.rk),
        up: Some(config.options.up),
        uv: config.options.uv,
        plat: Some(config.options.plat),
        always_uv: Some(config.options.always_uv),
        cred_mgmt: Some(config.options.cred_mgmt),
        bio_enroll: config.options.bio_enroll,
        client_pin: client_pin_value,
        pin_uv_auth_token: Some(config.options.pin_uv_auth_token),
        make_cred_uv_not_rqd: Some(
            !config.options.always_uv && config.options.make_cred_uv_not_rqd,
        ),
        // The legacy preview command (0x41) is not implemented.
        credential_mgmt_preview: None,
        no_mc_ga_permissions_with_client_pin: None,
        user_verification_mgmt_preview: None,
    };
    builder = builder.insert(keys::OPTIONS, options)?;

    if let Some(max_msg_size) = config.max_msg_size {
        builder = builder.insert(keys::MAX_MSG_SIZE, max_msg_size)?;
    }

    if !config.pin_uv_auth_protocols.is_empty() {
        builder = builder.insert(keys::PIN_UV_AUTH_PROTOCOLS, &config.pin_uv_auth_protocols)?;
    }

    builder = builder.insert(
        keys::MAX_CREDENTIAL_COUNT_IN_LIST,
        MAX_CREDENTIAL_COUNT_IN_LIST,
    )?;

    if let Some(max_cred_id_len) = config.max_credential_id_length {
        builder = builder.insert(keys::MAX_CREDENTIAL_ID_LENGTH, max_cred_id_len)?;
    }

    if !config.transports.is_empty() {
        builder = builder.insert(keys::TRANSPORTS, &config.transports)?;
    }

    #[derive(Serialize)]
    struct AlgEntry {
        alg: i32,
        r#type: String,
    }

    let algorithms: Vec<AlgEntry> = config
        .algorithms
        .iter()
        .map(|&alg| AlgEntry {
            alg,
            r#type: "public-key".to_string(),
        })
        .collect();
    if !algorithms.is_empty() {
        builder = builder.insert(keys::ALGORITHMS, algorithms)?;
    }

    // minPINLength is required whenever ClientPIN is supported.
    if config.options.client_pin.is_some() {
        builder = builder.insert(keys::MIN_PIN_LENGTH, auth.min_pin_length())?;
    }

    if let Some(fw_version) = config.firmware_version {
        builder = builder.insert(keys::FIRMWARE_VERSION, fw_version)?;
    }

    // Do not emit maxCredBlobLength or remainingDiscoverableCredentials until
    // credBlob persistence and dynamic capacity accounting are implemented.

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        authenticator::AuthenticatorConfig,
        cbor::{MapParser, Value},
        test_utils::MockCallbacks,
    };

    #[test]
    fn test_get_info_basic() {
        let config = AuthenticatorConfig::new();
        let auth = Authenticator::new(config, MockCallbacks);

        let response = handle(&auth).unwrap();
        let parser = MapParser::from_bytes(&response).unwrap();

        let versions: Vec<String> = parser.get(keys::VERSIONS).unwrap();
        assert_eq!(versions, vec!["FIDO_2_0".to_string()]);
        assert!(!versions.contains(&"FIDO_2_1".to_string()));
        assert!(!versions.contains(&"FIDO_2_2".to_string()));
        assert!(!versions.contains(&"FIDO_2_3".to_string()));

        let aaguid = parser.get_bytes(keys::AAGUID).unwrap();
        assert_eq!(aaguid.len(), 16);

        let protocols: Vec<u8> = parser.get(keys::PIN_UV_AUTH_PROTOCOLS).unwrap();
        assert!(protocols.contains(&1) || protocols.contains(&2));

        let list_limit: usize = parser.get(keys::MAX_CREDENTIAL_COUNT_IN_LIST).unwrap();
        assert_eq!(list_limit, MAX_CREDENTIAL_COUNT_IN_LIST);
        assert!(!parser.contains_key(keys::MIN_PIN_LENGTH));
        assert!(!parser.contains_key(keys::REMAINING_DISCOVERABLE_CREDENTIALS));
    }

    #[test]
    fn test_get_info_reports_min_pin_length_when_client_pin_is_supported() {
        let mut config = AuthenticatorConfig::new();
        config.options.client_pin = Some(false);
        let auth = Authenticator::new(config, MockCallbacks);

        let response = handle(&auth).unwrap();
        let parser = MapParser::from_bytes(&response).unwrap();

        assert_eq!(
            parser.get::<usize>(keys::MIN_PIN_LENGTH).unwrap(),
            auth.min_pin_length()
        );
    }

    #[test]
    fn test_get_info_does_not_advertise_preview_credential_management() {
        let config = AuthenticatorConfig::new();
        let auth = Authenticator::new(config, MockCallbacks);
        let response = handle(&auth).unwrap();
        let parser = MapParser::from_bytes(&response).unwrap();
        let options: Value = parser.get(keys::OPTIONS).unwrap();

        let Value::Map(options) = options else {
            panic!("options must be a map");
        };
        assert!(!options.iter().any(|(key, _)| {
            matches!(key, Value::Text(name) if name == "credentialMgmtPreview")
        }));
    }

    #[test]
    fn test_get_info_advertises_only_complete_extensions() {
        let config = AuthenticatorConfig::new().with_extensions(vec![
            "credProtect".to_string(),
            "hmac-secret".to_string(),
            "credBlob".to_string(),
            "largeBlobKey".to_string(),
        ]);
        let auth = Authenticator::new(config, MockCallbacks);

        let response = handle(&auth).unwrap();
        let parser = MapParser::from_bytes(&response).unwrap();
        let extensions: Vec<String> = parser.get(keys::EXTENSIONS).unwrap();

        assert_eq!(extensions, vec!["credProtect".to_string()]);
    }

    #[test]
    fn test_get_info_with_algorithms() {
        let config = AuthenticatorConfig::new().with_algorithms(vec![-7, -8]);
        let auth = Authenticator::new(config, MockCallbacks);

        let response = handle(&auth).unwrap();
        let parser = MapParser::from_bytes(&response).unwrap();
        assert!(parser.contains_key(keys::ALGORITHMS));
    }

    #[test]
    fn version_gate_is_fail_closed_until_mandatory_features_are_complete() {
        assert_eq!(advertised_versions(), vec!["FIDO_2_0".to_string()]);
    }
}
