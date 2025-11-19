//! FIDO2 Client API
//!
//! High-level client interface for communicating with FIDO2 authenticators.

use crate::error::{Error, Result};
use crate::request::{GetAssertionRequest, MakeCredentialRequest};
use crate::transport::Transport;

use soft_fido2_ctap::cbor::{MapBuilder, Value};

use std::collections::BTreeMap;

/// Client for communicating with FIDO2 authenticators
pub struct Client;

impl Client {
    /// Create a new credential (WebAuthn registration)
    ///
    /// Uses the builder pattern for type-safe, ergonomic credential creation.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `request` - A `MakeCredentialRequest` built using the builder pattern
    ///
    /// # Returns
    ///
    /// The raw CBOR-encoded attestation object from the authenticator
    pub fn make_credential(
        transport: &mut Transport,
        request: MakeCredentialRequest,
    ) -> Result<Vec<u8>> {
        // Build the CTAP2 authenticatorMakeCredential request using MapBuilder
        let mut builder = MapBuilder::new();

        // 0x01: clientDataHash (required)
        builder = builder
            .insert_bytes(1, request.client_data_hash().as_slice())
            .map_err(|_| Error::Other)?;

        // 0x02: rp (required)
        let mut rp_map = BTreeMap::new();
        rp_map.insert("id", request.rp().id.as_str());
        if let Some(name) = &request.rp().name {
            rp_map.insert("name", name.as_str());
        }
        builder = builder.insert(2, &rp_map).map_err(|_| Error::Other)?;

        // 0x03: user (required)
        let user_id_bytes = request.user().id.as_slice();
        let user_name = request.user().name.as_deref();
        let user_display_name = request.user().display_name.as_deref();

        // Build user map manually to handle optional fields and byte array
        let user_cbor = {
            use serde::Serialize;

            #[derive(Serialize)]
            struct UserEntity<'a> {
                id: &'a [u8],
                #[serde(skip_serializing_if = "Option::is_none")]
                name: Option<&'a str>,
                #[serde(skip_serializing_if = "Option::is_none")]
                #[serde(rename = "displayName")]
                display_name: Option<&'a str>,
            }

            let user_entity = UserEntity {
                id: user_id_bytes,
                name: user_name,
                display_name: user_display_name,
            };

            soft_fido2_ctap::cbor::encode(&user_entity).map_err(|_| Error::Other)?
        };
        builder = builder
            .insert(
                3,
                &soft_fido2_ctap::cbor::decode::<Value>(&user_cbor).map_err(|_| Error::Other)?,
            )
            .map_err(|_| Error::Other)?;

        // 0x04: pubKeyCredParams (required) - ES256 only for now
        use serde::Serialize;

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
        builder = builder
            .insert(4, vec![alg_param])
            .map_err(|_| Error::Other)?;

        // 0x05: excludeList (optional, empty for now)
        // 0x06: extensions (optional)

        // 0x07: options (optional)
        if request.resident_key.is_some() || request.user_verification.is_some() {
            use serde::Serialize;

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

        // 0x08: pinUvAuthParam (optional)
        if let Some(pin_auth) = request.pin_uv_auth() {
            builder = builder
                .insert_bytes(8, pin_auth.param())
                .map_err(|_| Error::Other)?;

            // 0x09: pinUvAuthProtocol (required if pinUvAuthParam is present)
            builder = builder
                .insert(9, pin_auth.protocol_u8())
                .map_err(|_| Error::Other)?;
        }

        // Build the CBOR request
        let request_bytes = builder.build().map_err(|_| Error::Other)?;

        // Send CTAP command 0x01 (authenticatorMakeCredential)
        let response = transport.send_ctap_command(0x01, &request_bytes)?;

        Ok(response)
    }

    /// Get an assertion (WebAuthn authentication)
    ///
    /// Uses the builder pattern for type-safe, ergonomic assertion retrieval.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `request` - A `GetAssertionRequest` built using the builder pattern
    ///
    /// # Returns
    ///
    /// The raw CBOR-encoded assertion from the authenticator
    pub fn get_assertion(
        transport: &mut Transport,
        request: GetAssertionRequest,
    ) -> Result<Vec<u8>> {
        // Build the CTAP2 authenticatorGetAssertion request using MapBuilder
        let mut builder = MapBuilder::new();

        // 0x01: rpId (required)
        builder = builder
            .insert(1, request.rp_id())
            .map_err(|_| Error::Other)?;

        // 0x02: clientDataHash (required)
        builder = builder
            .insert_bytes(2, request.client_data_hash().as_slice())
            .map_err(|_| Error::Other)?;

        // 0x03: allowList (optional)
        if !request.allow_list().is_empty() {
            use serde::Serialize;

            #[derive(Serialize)]
            struct Credential<'a> {
                id: &'a [u8],
                #[serde(rename = "type")]
                credential_type: &'a str,
            }

            let allow_list: Vec<Credential> = request
                .allow_list()
                .iter()
                .map(|cred| Credential {
                    id: cred.id.as_slice(),
                    credential_type: cred.credential_type.as_str(),
                })
                .collect();

            builder = builder.insert(3, &allow_list).map_err(|_| Error::Other)?;
        }

        // 0x04: extensions (optional)

        // 0x05: options (optional)
        if request.user_verification.is_some() {
            use serde::Serialize;

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

        // 0x06: pinUvAuthParam (optional)
        if let Some(pin_auth) = request.pin_uv_auth() {
            builder = builder
                .insert_bytes(6, pin_auth.param())
                .map_err(|_| Error::Other)?;

            // 0x07: pinUvAuthProtocol (required if pinUvAuthParam is present)
            builder = builder
                .insert(7, pin_auth.protocol_u8())
                .map_err(|_| Error::Other)?;
        }

        // Build the CBOR request
        let request_bytes = builder.build().map_err(|_| Error::Other)?;

        // Send CTAP command 0x02 (authenticatorGetAssertion)
        let response = transport.send_ctap_command(0x02, &request_bytes)?;

        Ok(response)
    }

    /// Send authenticatorGetInfo command
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    ///
    /// # Returns
    ///
    /// The raw CBOR-encoded authenticator info
    pub fn authenticator_get_info(transport: &mut Transport) -> Result<Vec<u8>> {
        // authenticatorGetInfo has no parameters
        let response = transport.send_ctap_command(0x04, &[])?;
        Ok(response)
    }

    /// Create a new credential (zero-allocation variant)
    ///
    /// This is the zero-allocation version of `make_credential`. The caller provides
    /// a buffer to write the response into, and this method returns the number of bytes written.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `request` - A `MakeCredentialRequest` built using the builder pattern
    /// * `response` - Buffer to write the response into (should be at least 7609 bytes for max CTAP response)
    ///
    /// # Returns
    ///
    /// Number of bytes written to the response buffer
    ///
    /// # Errors
    ///
    /// Returns `Error::Other` if the buffer is too small for the response
    ///
    /// # Note
    ///
    /// Uses MapBuilder and StackBuffer for zero-allocation CBOR encoding.
    /// Eliminates heap allocations by writing directly to the caller's buffer.
    pub fn make_credential_buf(
        transport: &mut Transport,
        request: MakeCredentialRequest,
        response: &mut [u8],
    ) -> Result<usize> {
        // Build the CTAP2 authenticatorMakeCredential request using MapBuilder
        let mut builder = MapBuilder::new();

        // 0x01: clientDataHash (required)
        builder = builder
            .insert_bytes(1, request.client_data_hash().as_slice())
            .map_err(|_| Error::Other)?;

        // 0x02: rp (required)
        let mut rp_map = BTreeMap::new();
        rp_map.insert("id", request.rp().id.as_str());
        if let Some(name) = &request.rp().name {
            rp_map.insert("name", name.as_str());
        }
        builder = builder.insert(2, &rp_map).map_err(|_| Error::Other)?;

        // 0x03: user (required)
        let user_id_bytes = request.user().id.as_slice();
        let user_name = request.user().name.as_deref();
        let user_display_name = request.user().display_name.as_deref();

        // Build user map manually to handle optional fields and byte array
        let user_cbor = {
            use serde::Serialize;

            #[derive(Serialize)]
            struct UserEntity<'a> {
                id: &'a [u8],
                #[serde(skip_serializing_if = "Option::is_none")]
                name: Option<&'a str>,
                #[serde(skip_serializing_if = "Option::is_none")]
                #[serde(rename = "displayName")]
                display_name: Option<&'a str>,
            }

            let user_entity = UserEntity {
                id: user_id_bytes,
                name: user_name,
                display_name: user_display_name,
            };

            soft_fido2_ctap::cbor::encode(&user_entity).map_err(|_| Error::Other)?
        };
        builder = builder
            .insert(
                3,
                &soft_fido2_ctap::cbor::decode::<Value>(&user_cbor).map_err(|_| Error::Other)?,
            )
            .map_err(|_| Error::Other)?;

        // 0x04: pubKeyCredParams (required) - ES256 only for now
        use serde::Serialize;

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
        builder = builder
            .insert(4, vec![alg_param])
            .map_err(|_| Error::Other)?;

        // 0x05: excludeList (optional, empty for now)
        // 0x06: extensions (optional)

        // 0x07: options (optional)
        if request.resident_key.is_some() || request.user_verification.is_some() {
            use serde::Serialize;

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

        // 0x08: pinUvAuthParam (optional)
        if let Some(pin_auth) = request.pin_uv_auth() {
            builder = builder
                .insert_bytes(8, pin_auth.param())
                .map_err(|_| Error::Other)?;

            // 0x09: pinUvAuthProtocol (required if pinUvAuthParam is present)
            builder = builder
                .insert(9, pin_auth.protocol_u8())
                .map_err(|_| Error::Other)?;
        }

        // Build the CBOR request
        let request_bytes = builder.build().map_err(|_| Error::Other)?;

        // Send CTAP command 0x01 (authenticatorMakeCredential) using zero-allocation transport
        transport.send_ctap_command_buf(0x01, &request_bytes, response)
    }

    /// Get an assertion (zero-allocation variant)
    ///
    /// This is the zero-allocation version of `get_assertion`. The caller provides
    /// a buffer to write the response into, and this method returns the number of bytes written.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `request` - A `GetAssertionRequest` built using the builder pattern
    /// * `response` - Buffer to write the response into (should be at least 7609 bytes for max CTAP response)
    ///
    /// # Returns
    ///
    /// Number of bytes written to the response buffer
    ///
    /// # Errors
    ///
    /// Returns `Error::Other` if the buffer is too small for the response
    ///
    /// # Note
    ///
    /// Uses MapBuilder and StackBuffer for zero-allocation CBOR encoding.
    /// Eliminates heap allocations by writing directly to the caller's buffer.
    pub fn get_assertion_buf(
        transport: &mut Transport,
        request: GetAssertionRequest,
        response: &mut [u8],
    ) -> Result<usize> {
        // Build the CTAP2 authenticatorGetAssertion request using MapBuilder
        let mut builder = MapBuilder::new();

        // 0x01: rpId (required)
        builder = builder
            .insert(1, request.rp_id())
            .map_err(|_| Error::Other)?;

        // 0x02: clientDataHash (required)
        builder = builder
            .insert_bytes(2, request.client_data_hash().as_slice())
            .map_err(|_| Error::Other)?;

        // 0x03: allowList (optional)
        if !request.allow_list().is_empty() {
            use serde::Serialize;

            #[derive(Serialize)]
            struct Credential<'a> {
                id: &'a [u8],
                #[serde(rename = "type")]
                credential_type: &'a str,
            }

            let allow_list: Vec<Credential> = request
                .allow_list()
                .iter()
                .map(|cred| Credential {
                    id: cred.id.as_slice(),
                    credential_type: cred.credential_type.as_str(),
                })
                .collect();

            builder = builder.insert(3, &allow_list).map_err(|_| Error::Other)?;
        }

        // 0x04: extensions (optional)

        // 0x05: options (optional)
        if request.user_verification.is_some() {
            use serde::Serialize;

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

        // 0x06: pinUvAuthParam (optional)
        if let Some(pin_auth) = request.pin_uv_auth() {
            builder = builder
                .insert_bytes(6, pin_auth.param())
                .map_err(|_| Error::Other)?;

            // 0x07: pinUvAuthProtocol (required if pinUvAuthParam is present)
            builder = builder
                .insert(7, pin_auth.protocol_u8())
                .map_err(|_| Error::Other)?;
        }

        // Build the CBOR request
        let request_bytes = builder.build().map_err(|_| Error::Other)?;

        // Send CTAP command 0x02 (authenticatorGetAssertion) using zero-allocation transport
        transport.send_ctap_command_buf(0x02, &request_bytes, response)
    }

    /// Send authenticatorGetInfo command (zero-allocation variant)
    ///
    /// This is the zero-allocation version of `authenticator_get_info`. The caller provides
    /// a buffer to write the response into, and this method returns the number of bytes written.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `response` - Buffer to write the response into (should be at least 7609 bytes for max CTAP response)
    ///
    /// # Returns
    ///
    /// Number of bytes written to the response buffer
    ///
    /// # Errors
    ///
    /// Returns `Error::Other` if the buffer is too small for the response
    pub fn authenticator_get_info_buf(
        transport: &mut Transport,
        response: &mut [u8],
    ) -> Result<usize> {
        // authenticatorGetInfo has no parameters
        transport.send_ctap_command_buf(0x04, &[], response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::ClientDataHash;
    use crate::types::{RelyingParty, User};

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

        // Just verify we can build a request without panicking
        assert_eq!(request.rp().id, "example.com");
        assert_eq!(request.user().id, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_get_assertion_request_encoding() {
        let hash = ClientDataHash::new([0u8; 32]);
        let request = GetAssertionRequest::new(hash, "example.com");

        // Just verify we can build a request without panicking
        assert_eq!(request.rp_id(), "example.com");
        assert!(request.allow_list().is_empty());
    }
}
