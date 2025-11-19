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

use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::cbor::{MapBuilder, MapParser};
use crate::status::{Result, StatusCode};
use crate::types::User;

/// Credential Management subcommand codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum SubCommand {
    GetCredsMetadata = 0x01,
    EnumerateRPsBegin = 0x02,
    EnumerateRPsGetNextRP = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
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
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;

    // Parse subcommand
    let subcommand: u8 = parser.get(req_keys::SUBCOMMAND)?;

    // All subcommands require PIN/UV auth
    let _pin_protocol: Option<u8> = parser.get_opt(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let _pin_auth: Option<Vec<u8>> = parser.get_opt(req_keys::PIN_UV_AUTH_PARAM)?;

    // TODO: Verify PIN/UV auth token has CredentialManagement permission (0x04)
    // For now, just check if PIN is set
    if !auth.is_pin_set() {
        return Err(StatusCode::PinRequired);
    }

    match subcommand {
        0x01 => handle_get_creds_metadata(auth),
        0x02 => handle_enumerate_rps_begin(auth),
        0x03 => handle_enumerate_rps_get_next(auth),
        0x04 => handle_enumerate_credentials_begin(auth, &parser),
        0x05 => handle_enumerate_credentials_get_next(auth),
        0x06 => handle_delete_credential(auth, &parser),
        0x07 => handle_update_user_information(auth, &parser),
        _ => Err(StatusCode::InvalidSubcommand),
    }
}

/// Handle getCredsMetadata subcommand
fn handle_get_creds_metadata<C: AuthenticatorCallbacks>(
    auth: &Authenticator<C>,
) -> Result<Vec<u8>> {
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
    auth: &Authenticator<C>,
) -> Result<Vec<u8>> {
    // Get all RPs
    let rps = auth.callbacks().enumerate_rps()?;

    if rps.is_empty() {
        return Err(StatusCode::NoCredentials);
    }

    // TODO: Store RP enumeration state for getNextRP
    // For now, just return the first RP

    let (rp_id, rp_name, _cred_count) = &rps[0];

    // Build RP structure
    let mut rp_builder = MapBuilder::new();

    rp_builder = rp_builder.insert(1, rp_id.clone())?;
    if let Some(name) = rp_name {
        rp_builder = rp_builder.insert(2, name.clone())?;
    }

    let rp_value = rp_builder.build_value()?;

    MapBuilder::new()
        .insert(resp_keys::RP, rp_value)?
        .insert_bytes(resp_keys::RP_ID_HASH, &compute_rp_id_hash(rp_id))?
        .insert(resp_keys::TOTAL_RPS, rps.len() as i32)?
        .build()
}

/// Handle enumerateRPsGetNextRP subcommand
fn handle_enumerate_rps_get_next<C: AuthenticatorCallbacks>(
    _auth: &Authenticator<C>,
) -> Result<Vec<u8>> {
    // TODO: Implement RP enumeration state management
    // For now, return NoCredentials to indicate no more RPs
    Err(StatusCode::NoCredentials)
}

/// Handle enumerateCredentialsBegin subcommand
fn handle_enumerate_credentials_begin<C: AuthenticatorCallbacks>(
    auth: &Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    // Get subcommand parameters
    let params: crate::cbor::Value = parser.get(req_keys::SUBCOMMAND_PARAMS)?;
    let params_parser = MapParser::from_value(params)?;

    // Extract RP ID hash
    let rp_id_hash: Vec<u8> = params_parser.get(subparam_keys::RP_ID_HASH)?;

    // TODO: Map RP ID hash to RP ID (requires storing hash->id mapping)
    // For now, enumerate all credentials and filter by trying to match
    // This is inefficient but works for the implementation

    // Get all RPs and find matching RP
    let rps = auth.callbacks().enumerate_rps()?;
    let matching_rp = rps
        .iter()
        .find(|(rp_id, _, _)| compute_rp_id_hash(rp_id) == rp_id_hash.as_slice())
        .ok_or(StatusCode::NoCredentials)?;

    let (rp_id, _, _) = matching_rp;

    // Get credentials for this RP
    let credentials = auth.callbacks().read_credentials(rp_id, None)?;

    if credentials.is_empty() {
        return Err(StatusCode::NoCredentials);
    }

    // Return first credential
    let cred = &credentials[0];

    // Build user structure
    let user = User {
        id: cred.user_id.clone(),
        name: cred.user_name.clone(),
        display_name: cred.user_display_name.clone(),
    };

    // Build credential ID descriptor
    let cred_id = crate::cbor::Value::Map(vec![(
        crate::cbor::Value::Text("id".to_string()),
        crate::cbor::Value::Bytes(cred.id.clone()),
    )]);

    MapBuilder::new()
        .insert(resp_keys::USER, user)?
        .insert(resp_keys::CREDENTIAL_ID, cred_id)?
        .insert(resp_keys::TOTAL_CREDENTIALS, credentials.len() as i32)?
        .build()
}

/// Handle enumerateCredentialsGetNextCredential subcommand
fn handle_enumerate_credentials_get_next<C: AuthenticatorCallbacks>(
    _auth: &Authenticator<C>,
) -> Result<Vec<u8>> {
    // TODO: Implement credential enumeration state management
    // For now, return NoCredentials to indicate no more credentials
    Err(StatusCode::NoCredentials)
}

/// Handle deleteCredential subcommand
fn handle_delete_credential<C: AuthenticatorCallbacks>(
    auth: &Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    // Get subcommand parameters
    let params: crate::cbor::Value = parser.get(req_keys::SUBCOMMAND_PARAMS)?;
    let params_parser = MapParser::from_value(params)?;

    // Extract credential ID
    let cred_id_value: crate::cbor::Value = params_parser.get(subparam_keys::CREDENTIAL_ID)?;

    // Parse credential ID from descriptor

    match cred_id_value {
        crate::cbor::Value::Map(m) => {
            for (k, v) in m {
                if let (crate::cbor::Value::Text(key), crate::cbor::Value::Bytes(id)) = (k, v)
                    && key == "id"
                {
                    return auth
                        .callbacks()
                        .delete_credential(&id)
                        .and_then(|_| MapBuilder::new().build());
                }
            }
            Err(StatusCode::InvalidParameter)
        }
        _ => Err(StatusCode::InvalidParameter),
    }?
}

/// Handle updateUserInformation subcommand
fn handle_update_user_information<C: AuthenticatorCallbacks>(
    auth: &Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    // Get subcommand parameters
    let params: crate::cbor::Value = parser.get(req_keys::SUBCOMMAND_PARAMS)?;
    let params_parser = MapParser::from_value(params)?;

    // Extract credential ID and new user info
    let cred_id_value: crate::cbor::Value = params_parser.get(subparam_keys::CREDENTIAL_ID)?;
    let new_user: User = params_parser.get(subparam_keys::USER)?;

    // Parse credential ID and update user information
    match cred_id_value {
        crate::cbor::Value::Map(m) => {
            for (k, v) in m {
                if let (crate::cbor::Value::Text(key), crate::cbor::Value::Bytes(id)) = (k, v)
                    && key == "id"
                {
                    // Found the ID, use it
                    let bytes = id;
                    // Get existing credential
                    let mut credential = auth.callbacks().get_credential(&bytes)?;

                    // Update user fields
                    credential.user_name = new_user.name.clone();
                    credential.user_display_name = new_user.display_name.clone();

                    // Save updated credential
                    auth.callbacks().update_credential(&credential)?;

                    return MapBuilder::new().build();
                }
            }
            Err(StatusCode::InvalidParameter)
        }
        _ => Err(StatusCode::InvalidParameter),
    }
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
    use crate::authenticator::{Authenticator, AuthenticatorConfig};
    use crate::callbacks::{CredentialStorageCallbacks, UserInteractionCallbacks};
    use crate::types::Credential;
    use crate::{UpResult, UvResult};

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

        // Build request
        let request = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x01u8)
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

        // Build request
        let request = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x02u8)
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
        // Don't set PIN

        // Build request
        let request = MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, 0x01u8)
            .unwrap()
            .build()
            .unwrap();

        let result = handle(&mut auth, &request);
        assert_eq!(result, Err(StatusCode::PinRequired));
    }
}
