//! FIDO2 Client API
//!
//! High-level, type-safe interface for communicating with FIDO2 authenticators.
//!
//! # Architecture
//!
//! This module is organized into logical sections:
//! - **Core Operations**: makeCredential, getAssertion, getInfo
//! - **Credential Management**: enumerate/delete/update credentials and RPs
//! - **Authentication Helpers**: PIN/UV token acquisition
//! - **CBOR Helpers**: Low-level encoding utilities
//!
//! # Design Principles
//!
//! - **Zero-Copy**: Uses `SmallVec` and stack buffers to minimize allocations
//! - **Type Safety**: Builder patterns prevent invalid request construction
//! - **Performance**: Canonical CBOR encoding, pre-allocated vectors
//! - **Ergonomics**: High-level convenience methods with sensible defaults

mod auth;
mod cbor_helpers;
pub mod credential_mgmt;

use crate::error::{Error, Result};
use crate::request::{GetAssertionRequest, MakeCredentialRequest};
use crate::transport::Transport;

use soft_fido2_ctap::cbor::{MapBuilder, Value};

use serde::Serialize;
use sha2::{Digest, Sha256};
use smallvec::SmallVec;

/// Client for communicating with FIDO2 authenticators
///
/// All methods are stateless and require an active `Transport` connection.
pub struct Client;

impl Client {
    /// Create a new credential (WebAuthn registration)
    ///
    /// Uses the builder pattern for type-safe, ergonomic credential creation.
    pub fn make_credential(
        transport: &mut Transport,
        request: MakeCredentialRequest,
    ) -> Result<Vec<u8>> {
        let mut builder = MapBuilder::new();

        builder = builder
            .insert_bytes(1, request.client_data_hash().as_slice())
            .map_err(|_| Error::Other)?;

        let mut rp_fields: SmallVec<[(&str, &str); 2]> = SmallVec::new();
        rp_fields.push(("id", request.rp().id.as_str()));
        if let Some(name) = &request.rp().name {
            rp_fields.push(("name", name.as_str()));
        }
        builder = builder
            .insert_text_map(2, &rp_fields)
            .map_err(|_| Error::Other)?;

        let user_cbor = soft_fido2_ctap::cbor::encode(&request.user()).map_err(|_| Error::Other)?;
        builder = builder
            .insert(
                3,
                &soft_fido2_ctap::cbor::decode::<Value>(&user_cbor).map_err(|_| Error::Other)?,
            )
            .map_err(|_| Error::Other)?;

        #[derive(Serialize)]
        struct PubKeyCredParam {
            alg: i32,
            #[serde(rename = "type")]
            cred_type: &'static str,
        }

        let alg_param = PubKeyCredParam {
            alg: -7,
            cred_type: "public-key",
        };
        let alg_params: SmallVec<[PubKeyCredParam; 1]> = SmallVec::from_buf([alg_param]);
        builder = builder.insert(4, alg_params).map_err(|_| Error::Other)?;

        if request.resident_key.is_some() || request.user_verification.is_some() {
            #[derive(Serialize)]
            struct Options {
                #[serde(skip_serializing_if = "Option::is_none")]
                rk: Option<bool>,
                #[serde(skip_serializing_if = "Option::is_none")]
                uv: Option<bool>,
            }

            let options = Options {
                rk: request.resident_key,
                uv: request.user_verification,
            };

            builder = builder.insert(7, &options).map_err(|_| Error::Other)?;
        }

        if let Some(pin_auth) = request.pin_uv_auth() {
            builder = builder
                .insert_bytes(8, pin_auth.param())
                .map_err(|_| Error::Other)?;

            builder = builder
                .insert(9, pin_auth.protocol_u8())
                .map_err(|_| Error::Other)?;
        }

        let request_bytes = builder.build().map_err(|_| Error::Other)?;
        let response = transport.send_ctap_command(0x01, &request_bytes, request.timeout_ms)?;

        Ok(response)
    }

    /// Get an assertion (WebAuthn authentication)
    ///
    /// Uses the builder pattern for type-safe, ergonomic assertion retrieval.
    pub fn get_assertion(
        transport: &mut Transport,
        request: GetAssertionRequest,
    ) -> Result<Vec<u8>> {
        let mut builder = MapBuilder::new();

        builder = builder
            .insert(1, request.rp_id())
            .map_err(|_| Error::Other)?;

        builder = builder
            .insert_bytes(2, request.client_data_hash().as_slice())
            .map_err(|_| Error::Other)?;

        if !request.allow_list().is_empty() {
            #[derive(Serialize)]
            struct Credential<'a> {
                id: &'a [u8],
                #[serde(rename = "type")]
                credential_type: &'a str,
            }

            let allow_list: SmallVec<[Credential; 4]> = request
                .allow_list()
                .iter()
                .map(|cred| Credential {
                    id: cred.id.as_slice(),
                    credential_type: cred.credential_type.as_str(),
                })
                .collect();

            builder = builder.insert(3, &allow_list).map_err(|_| Error::Other)?;
        }

        if request.user_verification.is_some() {
            #[derive(Serialize)]
            struct Options {
                #[serde(skip_serializing_if = "Option::is_none")]
                uv: Option<bool>,
            }

            let options = Options {
                uv: request.user_verification,
            };

            builder = builder.insert(5, options).map_err(|_| Error::Other)?;
        }

        if let Some(pin_auth) = request.pin_uv_auth() {
            builder = builder
                .insert_bytes(6, pin_auth.param())
                .map_err(|_| Error::Other)?;

            builder = builder
                .insert(7, pin_auth.protocol_u8())
                .map_err(|_| Error::Other)?;
        }

        let request_bytes = builder.build().map_err(|_| Error::Other)?;
        let response = transport.send_ctap_command(0x02, &request_bytes, request.timeout_ms)?;

        Ok(response)
    }

    /// Send authenticatorGetInfo command
    pub fn authenticator_get_info(transport: &mut Transport) -> Result<Vec<u8>> {
        let response = transport.send_ctap_command(0x04, &[], 30000)?;
        Ok(response)
    }

    /// Create a new credential (zero-allocation variant)
    ///
    /// The caller provides a buffer to write the response into.
    /// Returns the number of bytes written.
    pub fn make_credential_buf(
        transport: &mut Transport,
        request: MakeCredentialRequest,
        response: &mut [u8],
    ) -> Result<usize> {
        let mut builder = MapBuilder::new();

        builder = builder
            .insert_bytes(1, request.client_data_hash().as_slice())
            .map_err(|_| Error::Other)?;

        let mut rp_fields: SmallVec<[(&str, &str); 2]> = SmallVec::new();
        rp_fields.push(("id", request.rp().id.as_str()));
        if let Some(name) = &request.rp().name {
            rp_fields.push(("name", name.as_str()));
        }
        builder = builder
            .insert_text_map(2, &rp_fields)
            .map_err(|_| Error::Other)?;

        let user_cbor = soft_fido2_ctap::cbor::encode(&request.user()).map_err(|_| Error::Other)?;

        builder = builder
            .insert(
                3,
                &soft_fido2_ctap::cbor::decode::<Value>(&user_cbor).map_err(|_| Error::Other)?,
            )
            .map_err(|_| Error::Other)?;

        #[derive(Serialize)]
        struct PubKeyCredParam {
            alg: i32,
            #[serde(rename = "type")]
            cred_type: &'static str,
        }

        let alg_param = PubKeyCredParam {
            alg: -7,
            cred_type: "public-key",
        };
        let alg_params: SmallVec<[PubKeyCredParam; 1]> = SmallVec::from_buf([alg_param]);
        builder = builder.insert(4, alg_params).map_err(|_| Error::Other)?;

        if request.resident_key.is_some() || request.user_verification.is_some() {
            #[derive(Serialize)]
            struct Options {
                #[serde(skip_serializing_if = "Option::is_none")]
                rk: Option<bool>,
                #[serde(skip_serializing_if = "Option::is_none")]
                uv: Option<bool>,
            }

            let options = Options {
                rk: request.resident_key,
                uv: request.user_verification,
            };

            builder = builder.insert(7, &options).map_err(|_| Error::Other)?;
        }

        if let Some(pin_auth) = request.pin_uv_auth() {
            builder = builder
                .insert_bytes(8, pin_auth.param())
                .map_err(|_| Error::Other)?;

            builder = builder
                .insert(9, pin_auth.protocol_u8())
                .map_err(|_| Error::Other)?;
        }

        let request_bytes = builder.build().map_err(|_| Error::Other)?;
        transport.send_ctap_command_buf(0x01, &request_bytes, response, request.timeout_ms)
    }

    /// Get an assertion (zero-allocation variant)
    ///
    /// The caller provides a buffer to write the response into.
    /// Returns the number of bytes written.
    pub fn get_assertion_buf(
        transport: &mut Transport,
        request: GetAssertionRequest,
        response: &mut [u8],
    ) -> Result<usize> {
        let mut builder = MapBuilder::new();

        builder = builder
            .insert(1, request.rp_id())
            .map_err(|_| Error::Other)?;

        builder = builder
            .insert_bytes(2, request.client_data_hash().as_slice())
            .map_err(|_| Error::Other)?;

        if !request.allow_list().is_empty() {
            #[derive(Serialize)]
            struct Credential<'a> {
                id: &'a [u8],
                #[serde(rename = "type")]
                credential_type: &'a str,
            }

            let allow_list: SmallVec<[Credential; 4]> = request
                .allow_list()
                .iter()
                .map(|cred| Credential {
                    id: cred.id.as_slice(),
                    credential_type: cred.credential_type.as_str(),
                })
                .collect();

            builder = builder.insert(3, &allow_list).map_err(|_| Error::Other)?;
        }

        if request.user_verification.is_some() {
            #[derive(Serialize)]
            struct Options {
                #[serde(skip_serializing_if = "Option::is_none")]
                uv: Option<bool>,
            }

            let options = Options {
                uv: request.user_verification,
            };

            builder = builder.insert(5, options).map_err(|_| Error::Other)?;
        }

        if let Some(pin_auth) = request.pin_uv_auth() {
            builder = builder
                .insert_bytes(6, pin_auth.param())
                .map_err(|_| Error::Other)?;

            builder = builder
                .insert(7, pin_auth.protocol_u8())
                .map_err(|_| Error::Other)?;
        }

        let request_bytes = builder.build().map_err(|_| Error::Other)?;
        transport.send_ctap_command_buf(0x02, &request_bytes, response, request.timeout_ms)
    }

    /// Send authenticatorGetInfo command (zero-allocation variant)
    ///
    /// The caller provides a buffer to write the response into.
    /// Returns the number of bytes written.
    pub fn authenticator_get_info_buf(
        transport: &mut Transport,
        response: &mut [u8],
    ) -> Result<usize> {
        transport.send_ctap_command_buf(0x04, &[], response, 30000)
    }

    /// Get credentials metadata (wrapper for credential_mgmt module)
    pub fn get_credentials_metadata(
        transport: &mut Transport,
        request: crate::request::CredentialManagementRequest,
    ) -> Result<crate::response::CredentialsMetadata> {
        credential_mgmt::get_credentials_metadata(transport, request)
    }

    /// Begin RP enumeration (wrapper for credential_mgmt module)
    pub fn enumerate_rps_begin(
        transport: &mut Transport,
        request: crate::request::CredentialManagementRequest,
    ) -> Result<crate::response::RpEnumerationBeginResponse> {
        credential_mgmt::enumerate_rps_begin(transport, request)
    }

    /// Get next RP in enumeration (wrapper for credential_mgmt module)
    pub fn enumerate_rps_get_next(transport: &mut Transport) -> Result<crate::response::RpInfo> {
        credential_mgmt::enumerate_rps_get_next(transport)
    }

    /// Enumerate all RPs (wrapper for credential_mgmt module)
    pub fn enumerate_rps(
        transport: &mut Transport,
        request: crate::request::CredentialManagementRequest,
    ) -> Result<Vec<crate::response::RpInfo>> {
        credential_mgmt::enumerate_rps(transport, request)
    }

    /// Begin credential enumeration (wrapper for credential_mgmt module)
    pub fn enumerate_credentials_begin(
        transport: &mut Transport,
        request: crate::request::EnumerateCredentialsRequest,
    ) -> Result<crate::response::CredentialEnumerationBeginResponse> {
        credential_mgmt::enumerate_credentials_begin(transport, request)
    }

    /// Get next credential (wrapper for credential_mgmt module)
    pub fn enumerate_credentials_get_next(
        transport: &mut Transport,
    ) -> Result<crate::response::CredentialInfo> {
        credential_mgmt::enumerate_credentials_get_next(transport)
    }

    /// Enumerate all credentials (wrapper for credential_mgmt module)
    pub fn enumerate_credentials(
        transport: &mut Transport,
        request: crate::request::EnumerateCredentialsRequest,
    ) -> Result<Vec<crate::response::CredentialInfo>> {
        credential_mgmt::enumerate_credentials(transport, request)
    }

    /// Delete a credential (wrapper for credential_mgmt module)
    pub fn delete_credential(
        transport: &mut Transport,
        request: crate::request::DeleteCredentialRequest,
    ) -> Result<()> {
        credential_mgmt::delete_credential(transport, request)
    }

    /// Update user information (wrapper for credential_mgmt module)
    pub fn update_user_information(
        transport: &mut Transport,
        request: crate::request::UpdateUserRequest,
    ) -> Result<()> {
        credential_mgmt::update_user_information(transport, request)
    }

    /// Get a PIN/UV auth token for credential management operations
    ///
    /// Handles the complete PIN authentication flow and returns a ready-to-use token.
    pub fn get_pin_token_for_credential_management(
        transport: &mut Transport,
        pin: &str,
        protocol: crate::pin::PinProtocol,
    ) -> Result<crate::request::PinUvAuth> {
        use crate::pin::PinUvAuthEncapsulation;
        use crate::request::Permission;

        let mut encapsulation = PinUvAuthEncapsulation::new(transport, protocol)?;

        let permissions = Permission::CredentialManagement as u8;
        let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
            transport,
            pin,
            permissions,
            None,
        )?;

        Ok(crate::request::PinUvAuth::new(pin_token, protocol.into()))
    }

    /// Get a PIN/UV auth token using user verification (biometric/platform auth)
    ///
    /// Attempts to get a PIN token using built-in user verification
    /// instead of PIN. Not all authenticators support this.
    pub fn get_uv_token_for_credential_management(
        transport: &mut Transport,
        protocol: crate::pin::PinProtocol,
    ) -> Result<crate::request::PinUvAuth> {
        use crate::pin::PinUvAuthEncapsulation;
        use crate::request::Permission;

        let mut encapsulation = PinUvAuthEncapsulation::new(transport, protocol)?;

        let permissions = Permission::CredentialManagement as u8;
        let uv_token = encapsulation.get_pin_uv_auth_token_using_uv_with_permissions(
            transport,
            permissions,
            None,
        )?;

        Ok(crate::request::PinUvAuth::new(uv_token, protocol.into()))
    }
}

/// Compute SHA-256 hash of RP ID
pub fn compute_rp_id_hash(rp_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::request::ClientDataHash;

    use soft_fido2_ctap::types::{RelyingParty, User};

    #[test]
    fn test_make_credential_request_encoding() {
        let hash = ClientDataHash::new([0u8; 32]);
        let rp = RelyingParty {
            id: "example.com".to_string(),
            name: Some("Example Corp".to_string()),
        };
        let user = User {
            id: vec![1, 2, 3, 4],
            name: Some("alice@example.com".to_string()),
            display_name: Some("Alice".to_string()),
        };

        let request = MakeCredentialRequest::new(hash, rp, user);

        assert_eq!(request.rp().id, "example.com");
        assert_eq!(request.user().id, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_get_assertion_request_encoding() {
        let hash = ClientDataHash::new([0u8; 32]);
        let request = GetAssertionRequest::new(hash, "example.com".to_string());

        assert_eq!(request.rp_id(), "example.com");
    }

    #[test]
    fn test_compute_rp_id_hash() {
        let hash = compute_rp_id_hash("example.com");
        assert_eq!(hash.len(), 32);
    }
}
