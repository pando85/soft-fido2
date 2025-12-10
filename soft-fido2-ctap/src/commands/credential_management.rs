//! authenticatorCredentialManagement command
//!
//! Handles credential management operations including:
//! - Getting credentials metadata
//! - Enumerating RPs
//! - Enumerating credentials
//! - Deleting credentials
//! - Updating user information
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorCredentialManagement>

use crate::{
    authenticator::Authenticator,
    callbacks::AuthenticatorCallbacks,
    cbor::{MapBuilder, MapParser},
    status::{Result, StatusCode},
    types::User,
};

use alloc::{string::ToString, vec, vec::Vec};

/// Credential Management subcommand codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubCommand {
    GetCredsMetadata = 0x01,
    EnumerateRPsBegin = 0x02,
    EnumerateRPsGetNextRP = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

impl TryFrom<u8> for SubCommand {
    type Error = StatusCode;

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(SubCommand::GetCredsMetadata),
            0x02 => Ok(SubCommand::EnumerateRPsBegin),
            0x03 => Ok(SubCommand::EnumerateRPsGetNextRP),
            0x04 => Ok(SubCommand::EnumerateCredentialsBegin),
            0x05 => Ok(SubCommand::EnumerateCredentialsGetNextCredential),
            0x06 => Ok(SubCommand::DeleteCredential),
            0x07 => Ok(SubCommand::UpdateUserInformation),
            _ => Err(StatusCode::InvalidSubcommand),
        }
    }
}

/// Request parameter keys
mod req_keys {
    pub const SUBCOMMAND: i32 = 0x01;
    pub const SUBCOMMAND_PARAMS: i32 = 0x02;
    pub const PIN_UV_AUTH_PROTOCOL: i32 = 0x03;
    pub const PIN_UV_AUTH_PARAM: i32 = 0x04;
}

/// Response keys
#[allow(dead_code)]
mod resp_keys {
    pub const EXISTING_RESIDENT_CREDENTIALS_COUNT: i32 = 0x01;
    pub const MAX_POSSIBLE_REMAINING_RESIDENTIAL_CREDENTIALS_COUNT: i32 = 0x02;
    pub const RP: i32 = 0x03;
    pub const RP_ID_HASH: i32 = 0x04;
    pub const TOTAL_RPS: i32 = 0x05;
    pub const USER: i32 = 0x06;
    pub const CREDENTIAL_ID: i32 = 0x07;
    pub const PUBLIC_KEY: i32 = 0x08;
    pub const TOTAL_CREDENTIALS: i32 = 0x09;
    pub const CRED_PROTECT: i32 = 0x0A;
    pub const LARGE_BLOB_KEY: i32 = 0x0B;
}

/// Subcommand parameter keys
mod subparam_keys {
    pub const RP_ID_HASH: i32 = 0x01;
    pub const CREDENTIAL_ID: i32 = 0x02;
    pub const USER: i32 = 0x03;
}

/// Handle authenticatorCredentialManagement command
///
/// Requires PIN/UV auth token with CredentialManagement permission (0x04).
/// Each subcommand has its own auth validation per FIDO 2.2 spec.
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;

    // Parse subcommand
    let subcommand_byte: u8 = parser.get(req_keys::SUBCOMMAND)?;
    let subcommand = SubCommand::try_from(subcommand_byte)?;

    // Dispatch to subcommand handlers - each performs its own auth validation
    match subcommand {
        SubCommand::GetCredsMetadata => handle_get_creds_metadata(auth, &parser),
        SubCommand::EnumerateRPsBegin => handle_enumerate_rps_begin(auth, &parser),
        SubCommand::EnumerateRPsGetNextRP => handle_enumerate_rps_get_next(auth),
        SubCommand::EnumerateCredentialsBegin => handle_enumerate_credentials_begin(auth, &parser),
        SubCommand::EnumerateCredentialsGetNextCredential => {
            handle_enumerate_credentials_get_next(auth)
        }
        SubCommand::DeleteCredential => handle_delete_credential(auth, &parser),
        SubCommand::UpdateUserInformation => handle_update_user_information(auth, &parser),
    }
}

/// Verify credential management authentication per FIDO 2.2 spec
///
/// Performs the standard auth validation steps required by all CM subcommands:
/// 1. Check pinUvAuthParam presence
/// 2. Check mandatory parameters
/// 3. Validate pinUvAuthProtocol support
/// 4. Verify pinUvAuthParam
/// 5. Verify cm permission and RP ID scope
///
/// # Arguments
/// * `auth` - Authenticator instance
/// * `parser` - Request parser
/// * `subcommand_byte` - Subcommand code
/// * `subcommand_params` - Optional params to include in auth data (for verify())
/// * `request_rp_id` - Optional RP ID for permission scope checking
/// * `require_no_rp_id` - If true, token MUST NOT have permissions RP ID
fn verify_credential_management_auth<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
    subcommand_byte: u8,
    subcommand_params: Option<&[u8]>,
    request_rp_id: Option<&str>,
    require_no_rp_id: bool,
) -> Result<()> {
    // Step 1: If pinUvAuthParam is missing, return PUAT_REQUIRED
    let pin_uv_auth_param: Option<Vec<u8>> =
        if parser.get_raw(req_keys::PIN_UV_AUTH_PARAM).is_some() {
            Some(parser.get_bytes(req_keys::PIN_UV_AUTH_PARAM)?)
        } else {
            None
        };

    if pin_uv_auth_param.is_none() {
        return Err(StatusCode::PuatRequired);
    }

    // Step 2: Check mandatory parameters (pinUvAuthProtocol must be present)
    let pin_uv_auth_protocol: Option<u8> = parser.get_opt(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    if pin_uv_auth_protocol.is_none() {
        return Err(StatusCode::MissingParameter);
    }

    // Step 3: Validate pinUvAuthProtocol support
    let protocol = pin_uv_auth_protocol.unwrap();
    if !auth.config().pin_uv_auth_protocols.contains(&protocol) {
        return Err(StatusCode::InvalidParameter);
    }

    // Step 4: Build auth data and verify pinUvAuthParam
    // Auth data = subcommand byte || subcommand params (if present)
    let mut auth_data = vec![subcommand_byte];
    if let Some(params) = subcommand_params {
        auth_data.extend_from_slice(params);
    }

    let pin_auth = pin_uv_auth_param.unwrap();
    auth.verify_pin_uv_auth_param(protocol, &pin_auth, &auth_data)?;

    // Step 5: Verify cm permission and RP ID scope
    if require_no_rp_id {
        // Token MUST NOT have an associated permissions RP ID
        // This is checked by passing None - if token has RP ID, it will fail
        auth.verify_pin_uv_auth_token(crate::pin_token::Permission::CredentialManagement, None)?;
    } else if let Some(rp_id) = request_rp_id {
        // Token must have NO associated RP ID OR match the request's RP ID
        // Try with the RP ID first
        auth.verify_pin_uv_auth_token(
            crate::pin_token::Permission::CredentialManagement,
            Some(rp_id),
        )?;
    } else {
        // No RP ID requirement - just verify cm permission
        auth.verify_pin_uv_auth_token(crate::pin_token::Permission::CredentialManagement, None)?;
    }

    Ok(())
}

/// Handle getCredsMetadata subcommand
fn handle_get_creds_metadata<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    // Auth validation per FIDO 2.2 spec section 6.8.2
    verify_credential_management_auth(
        auth,
        parser,
        SubCommand::GetCredsMetadata as u8,
        None, // No subcommand params
        None, // No RP ID
        true, // MUST NOT have permissions RP ID
    )?;
    // Get current credential count
    let count = auth.callbacks().credential_count()?;

    // Get remaining capacity
    let remaining = auth
        .remaining_discoverable_credentials()
        .unwrap_or(auth.config().max_credentials);

    MapBuilder::new()
        .insert(resp_keys::EXISTING_RESIDENT_CREDENTIALS_COUNT, count as i32)?
        .insert(
            resp_keys::MAX_POSSIBLE_REMAINING_RESIDENTIAL_CREDENTIALS_COUNT,
            remaining as i32,
        )?
        .build()
}

/// Handle enumerateRPsBegin subcommand
fn handle_enumerate_rps_begin<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    // Auth validation per FIDO 2.2 spec section 6.8.3
    verify_credential_management_auth(
        auth,
        parser,
        SubCommand::EnumerateRPsBegin as u8,
        None, // No subcommand params
        None, // No RP ID
        true, // MUST NOT have permissions RP ID
    )?;
    // Start RP enumeration and get first RP
    let ((rp_id, rp_name, _cred_count), total_rps) = auth.start_rp_enumeration()?;

    // Build RP structure (publicKeyCredentialRpEntity)
    // According to WebAuthn spec, uses TEXT keys: "id" and "name"
    // Must be in canonical CBOR order: "id" (len 2) before "name" (len 4)

    // Build the Value directly to ensure correct CBOR encoding
    let mut rp_map = vec![(
        crate::cbor::Value::Text("id".to_string()),
        crate::cbor::Value::Text(rp_id.clone()),
    )];

    if let Some(name) = &rp_name {
        rp_map.push((
            crate::cbor::Value::Text("name".to_string()),
            crate::cbor::Value::Text(name.clone()),
        ));
    }

    let rp_value = crate::cbor::Value::Map(rp_map);

    let rp_id_hash = compute_rp_id_hash(&rp_id);

    MapBuilder::new()
        .insert(resp_keys::RP, rp_value)?
        .insert_bytes(resp_keys::RP_ID_HASH, &rp_id_hash)?
        .insert(resp_keys::TOTAL_RPS, total_rps as i32)?
        .build()
}

/// Handle enumerateRPsGetNextRP subcommand
fn handle_enumerate_rps_get_next<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
) -> Result<Vec<u8>> {
    // Get next RP from enumeration state
    let (rp_id, rp_name, _cred_count) = auth.get_next_rp()?;

    // Build RP structure (same as enumerateRPsBegin) - build Value directly
    let mut rp_map = vec![(
        crate::cbor::Value::Text("id".to_string()),
        crate::cbor::Value::Text(rp_id.clone()),
    )];

    if let Some(name) = &rp_name {
        rp_map.push((
            crate::cbor::Value::Text("name".to_string()),
            crate::cbor::Value::Text(name.clone()),
        ));
    }

    let rp_value = crate::cbor::Value::Map(rp_map);
    let rp_id_hash = compute_rp_id_hash(&rp_id);

    MapBuilder::new()
        .insert(resp_keys::RP, rp_value)?
        .insert_bytes(resp_keys::RP_ID_HASH, &rp_id_hash)?
        .build()
}

/// Handle enumerateCredentialsBegin subcommand
fn handle_enumerate_credentials_begin<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    // Get subcommand parameters (needed for auth)
    let params_value: crate::cbor::Value = parser.get(req_keys::SUBCOMMAND_PARAMS)?;

    // Serialize params for auth verification
    let mut params_bytes = Vec::new();
    crate::cbor::into_writer(&params_value, &mut params_bytes)
        .map_err(|_| StatusCode::InvalidCbor)?;

    // Map RP ID hash to RP ID (needed for permission check)
    let params_parser = MapParser::from_value(params_value.clone())?;
    let rp_id_hash: Vec<u8> = params_parser.get_bytes(subparam_keys::RP_ID_HASH)?;

    let rps = auth.callbacks().enumerate_rps()?;
    let matching_rp = rps
        .iter()
        .find(|(rp_id, _, _)| {
            let computed = compute_rp_id_hash(rp_id);
            computed == rp_id_hash.as_slice()
        })
        .ok_or(StatusCode::NoCredentials)?;
    let (rp_id, _, _) = matching_rp;

    // Auth validation per FIDO 2.2 spec section 6.8.4
    // Auth data = enumerateCredentialsBegin (0x04) || subCommandParams
    verify_credential_management_auth(
        auth,
        parser,
        SubCommand::EnumerateCredentialsBegin as u8,
        Some(&params_bytes), // Include params in auth
        Some(rp_id),         // Token must match this RP ID (or have no RP ID)
        false,               // Can have permissions RP ID
    )?;

    // Start credential enumeration and get first credential
    let (cred, total_credentials) = auth.start_credential_enumeration(rp_id)?;

    // Build user structure
    let user = User {
        id: cred.user_id.clone(),
        name: cred.user_name.clone(),
        display_name: cred.user_display_name.clone(),
    };

    // Build credential ID descriptor (PublicKeyCredentialDescriptor)
    // Must have "id" and "type" in canonical CBOR order (by length, then alphabetically)
    let cred_id = crate::cbor::Value::Map(vec![
        (
            crate::cbor::Value::Text("id".to_string()), // len 2
            crate::cbor::Value::Bytes(cred.id.clone()),
        ),
        (
            crate::cbor::Value::Text("type".to_string()), // len 4
            crate::cbor::Value::Text("public-key".to_string()),
        ),
    ]);

    MapBuilder::new()
        .insert(resp_keys::USER, user)?
        .insert(resp_keys::CREDENTIAL_ID, cred_id)?
        .insert(resp_keys::TOTAL_CREDENTIALS, total_credentials as i32)?
        .build()
}

/// Handle enumerateCredentialsGetNextCredential subcommand
fn handle_enumerate_credentials_get_next<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
) -> Result<Vec<u8>> {
    // Get next credential from enumeration state
    let cred = auth.get_next_credential()?;

    // Build user structure
    let user = User {
        id: cred.user_id.clone(),
        name: cred.user_name.clone(),
        display_name: cred.user_display_name.clone(),
    };

    // Build credential ID descriptor (PublicKeyCredentialDescriptor)
    // Must have "id" and "type" in canonical CBOR order
    let cred_id = crate::cbor::Value::Map(vec![
        (
            crate::cbor::Value::Text("id".to_string()), // len 2
            crate::cbor::Value::Bytes(cred.id.clone()),
        ),
        (
            crate::cbor::Value::Text("type".to_string()), // len 4
            crate::cbor::Value::Text("public-key".to_string()),
        ),
    ]);

    MapBuilder::new()
        .insert(resp_keys::USER, user)?
        .insert(resp_keys::CREDENTIAL_ID, cred_id)?
        .build()
}

/// Handle deleteCredential subcommand
fn handle_delete_credential<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    // Get subcommand parameters (needed for auth)
    let params_value: crate::cbor::Value = parser.get(req_keys::SUBCOMMAND_PARAMS)?;

    // Serialize params for auth verification
    let mut params_bytes = Vec::new();
    crate::cbor::into_writer(&params_value, &mut params_bytes)
        .map_err(|_| StatusCode::InvalidCbor)?;

    // Extract credential ID to get RP ID for permission check
    let params_parser = MapParser::from_value(params_value)?;
    let cred_id_value: crate::cbor::Value = params_parser.get(subparam_keys::CREDENTIAL_ID)?;

    // Parse credential ID from descriptor
    let cred_id_bytes = match &cred_id_value {
        crate::cbor::Value::Map(m) => {
            let mut id = None;
            for (k, v) in m {
                if let (crate::cbor::Value::Text(key), crate::cbor::Value::Bytes(bytes)) = (k, v)
                    && key == "id"
                {
                    id = Some(bytes.clone());
                    break;
                }
            }
            id.ok_or(StatusCode::InvalidParameter)?
        }
        _ => return Err(StatusCode::InvalidParameter),
    };

    // Get credential to find RP ID
    let credential = auth.callbacks().get_credential(&cred_id_bytes)?;

    // Auth validation per FIDO 2.2 spec section 6.8.5
    // Auth data = deleteCredential (0x06) || subCommandParams
    verify_credential_management_auth(
        auth,
        parser,
        SubCommand::DeleteCredential as u8,
        Some(&params_bytes),     // Include params in auth
        Some(&credential.rp_id), // Token must match credential's RP ID (or have no RP ID)
        false,                   // Can have permissions RP ID
    )?;

    // Delete the credential
    auth.callbacks()
        .delete_credential(&cred_id_bytes)
        .and_then(|_| MapBuilder::new().build())
}

/// Handle updateUserInformation subcommand
fn handle_update_user_information<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    // Get subcommand parameters (needed for auth)
    let params_value: crate::cbor::Value = parser.get(req_keys::SUBCOMMAND_PARAMS)?;

    // Serialize params for auth verification
    let mut params_bytes = Vec::new();
    crate::cbor::into_writer(&params_value, &mut params_bytes)
        .map_err(|_| StatusCode::InvalidCbor)?;

    // Extract credential ID and new user info
    let params_parser = MapParser::from_value(params_value)?;
    let cred_id_value: crate::cbor::Value = params_parser.get(subparam_keys::CREDENTIAL_ID)?;
    let new_user: User = params_parser.get(subparam_keys::USER)?;

    // Parse credential ID from descriptor
    let cred_id_bytes = match &cred_id_value {
        crate::cbor::Value::Map(m) => {
            let mut id = None;
            for (k, v) in m {
                if let (crate::cbor::Value::Text(key), crate::cbor::Value::Bytes(bytes)) = (k, v)
                    && key == "id"
                {
                    id = Some(bytes.clone());
                    break;
                }
            }
            id.ok_or(StatusCode::InvalidParameter)?
        }
        _ => return Err(StatusCode::InvalidParameter),
    };

    // Get existing credential
    let mut credential = auth.callbacks().get_credential(&cred_id_bytes)?;

    // Auth validation per FIDO 2.2 spec section 6.8.6
    // Auth data = updateUserInformation (0x07) || subCommandParams
    verify_credential_management_auth(
        auth,
        parser,
        SubCommand::UpdateUserInformation as u8,
        Some(&params_bytes),     // Include params in auth
        Some(&credential.rp_id), // Token must match credential's RP ID (or have no RP ID)
        false,                   // Can have permissions RP ID
    )?;

    // Verify user ID matches (per spec step 8)
    if credential.user_id != new_user.id {
        return Err(StatusCode::InvalidParameter);
    }

    // Update user fields (per spec step 9)
    // If field is present and non-empty, update it; if absent or empty, remove it
    credential.user_name = new_user.name.clone();
    credential.user_display_name = new_user.display_name.clone();

    // Save updated credential
    auth.callbacks().update_credential(&credential)?;

    MapBuilder::new().build()
}

/// Compute SHA-256 hash of RP ID
fn compute_rp_id_hash(rp_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        UpResult, UvResult,
        authenticator::{Authenticator, AuthenticatorConfig},
        callbacks::{CredentialStorageCallbacks, UserInteractionCallbacks},
        types::Credential,
    };

    struct MockCallbacks {
        cred_count: usize,
    }

    impl MockCallbacks {
        fn new(count: usize) -> Self {
            Self { cred_count: count }
        }
    }

    impl UserInteractionCallbacks for MockCallbacks {
        fn request_up(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> Result<UpResult> {
            Ok(UpResult::Accepted)
        }

        fn request_uv(
            &self,
            _info: &str,
            _user_name: Option<&str>,
            _rp_id: &str,
        ) -> Result<UvResult> {
            Ok(UvResult::Accepted)
        }

        fn select_credential(&self, _rp_id: &str, _user_names: &[String]) -> Result<usize> {
            Ok(0)
        }
    }

    impl CredentialStorageCallbacks for MockCallbacks {
        fn write_credential(&self, _credential: &Credential) -> Result<()> {
            Ok(())
        }

        fn delete_credential(&self, _credential_id: &[u8]) -> Result<()> {
            Ok(())
        }

        fn read_credentials(
            &self,
            _rp_id: &str,
            _user_id: Option<&[u8]>,
        ) -> Result<Vec<Credential>> {
            Ok(vec![])
        }

        fn credential_exists(&self, _credential_id: &[u8]) -> Result<bool> {
            Ok(false)
        }

        fn get_credential(&self, _credential_id: &[u8]) -> Result<Credential> {
            Err(StatusCode::NoCredentials)
        }

        fn update_credential(&self, _credential: &Credential) -> Result<()> {
            Ok(())
        }

        fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
            Ok(vec![(
                "example.com".to_string(),
                Some("Example".to_string()),
                5,
            )])
        }

        fn credential_count(&self) -> Result<usize> {
            Ok(self.cred_count)
        }
    }

    #[test]
    fn test_get_creds_metadata() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, MockCallbacks::new(10));
        auth.set_pin("1234").unwrap();

        // Get PIN token with cm permission
        let token = auth
            .get_pin_token(
                "1234",
                crate::pin_token::Permission::CredentialManagement.to_u8(),
                None,
            )
            .unwrap();

        // Build auth data: just subcommand byte
        let auth_data = vec![0x01u8]; // getCredsMetadata

        // Create pinUvAuthParam using protocol V2
        let pin_auth = soft_fido2_crypto::pin_protocol::v2::authenticate(&token, &auth_data);

        // Build request
        let request = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x01u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 2u8)
            .unwrap()
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_auth)
            .unwrap()
            .build()
            .unwrap();

        let response = handle(&mut auth, &request).unwrap();
        assert!(!response.is_empty());

        // Parse response
        let parser = MapParser::from_bytes(&response).unwrap();
        let count: i32 = parser
            .get(resp_keys::EXISTING_RESIDENT_CREDENTIALS_COUNT)
            .unwrap();
        assert_eq!(count, 10);
    }

    #[test]
    fn test_enumerate_rps_begin() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, MockCallbacks::new(5));
        auth.set_pin("1234").unwrap();

        // Get PIN token with cm permission
        let token = auth
            .get_pin_token(
                "1234",
                crate::pin_token::Permission::CredentialManagement.to_u8(),
                None,
            )
            .unwrap();

        // Build auth data: just subcommand byte
        let auth_data = vec![0x02u8]; // enumerateRPsBegin

        // Create pinUvAuthParam using protocol V2
        let pin_auth = soft_fido2_crypto::pin_protocol::v2::authenticate(&token, &auth_data);

        // Build request
        let request = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x02u8)
            .unwrap()
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 2u8)
            .unwrap()
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_auth)
            .unwrap()
            .build()
            .unwrap();

        let response = handle(&mut auth, &request).unwrap();
        assert!(!response.is_empty());

        // Parse response
        let parser = MapParser::from_bytes(&response).unwrap();
        let total: i32 = parser.get(resp_keys::TOTAL_RPS).unwrap();
        assert_eq!(total, 1);
    }

    #[test]
    fn test_credential_management_requires_pin() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, MockCallbacks::new(0));
        // Don't set PIN - but still need to provide pinUvAuthParam to get past first check

        // Build request without pinUvAuthParam
        let request = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x01u8)
            .unwrap()
            .build()
            .unwrap();

        let result = handle(&mut auth, &request);
        // Per spec, missing pinUvAuthParam returns PUAT_REQUIRED
        assert_eq!(result, Err(StatusCode::PuatRequired));
    }
}
