//! FIDO2 Client API
//!
//! High-level client interface for communicating with FIDO2 authenticators.

use crate::error::{Error, Result};
use crate::request::{
    CredentialManagementRequest, DeleteCredentialRequest, EnumerateCredentialsRequest,
    GetAssertionRequest, MakeCredentialRequest, PinUvAuthProtocol, UpdateUserRequest,
};
use crate::transport::Transport;

use soft_fido2_ctap::cbor::{MapBuilder, Value};

use serde::Serialize;
use sha2::{Digest, Sha256};
use smallvec::SmallVec;

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
        // Use SmallVec to avoid heap allocation for RP fields
        let mut rp_fields: SmallVec<[(&str, &str); 2]> = SmallVec::new();
        rp_fields.push(("id", request.rp().id.as_str()));
        if let Some(name) = &request.rp().name {
            rp_fields.push(("name", name.as_str()));
        }
        builder = builder
            .insert_text_map(2, &rp_fields)
            .map_err(|_| Error::Other)?;

        // 0x03: user (required)
        let user_cbor = soft_fido2_ctap::cbor::encode(&request.user()).map_err(|_| Error::Other)?;
        builder = builder
            .insert(
                3,
                &soft_fido2_ctap::cbor::decode::<Value>(&user_cbor).map_err(|_| Error::Other)?,
            )
            .map_err(|_| Error::Other)?;

        // 0x04: pubKeyCredParams (required) - ES256 only for now
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
        // Use SmallVec to avoid heap allocation for single algorithm
        let alg_params: SmallVec<[PubKeyCredParam; 1]> = SmallVec::from_buf([alg_param]);
        builder = builder.insert(4, alg_params).map_err(|_| Error::Other)?;

        // 0x05: excludeList (optional, empty for now)
        // 0x06: extensions (optional)

        // 0x07: options (optional)
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
        let response = transport.send_ctap_command(0x01, &request_bytes, request.timeout_ms)?;

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
            #[derive(Serialize)]
            struct Credential<'a> {
                id: &'a [u8],
                #[serde(rename = "type")]
                credential_type: &'a str,
            }

            // Use SmallVec to avoid heap allocation for common cases (0-4 credentials)
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

        // 0x04: extensions (optional)

        // 0x05: options (optional)
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
        let response = transport.send_ctap_command(0x02, &request_bytes, request.timeout_ms)?;

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
        // authenticatorGetInfo has no parameters, use default 30s timeout
        let response = transport.send_ctap_command(0x04, &[], 30000)?;
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
        // Use SmallVec to avoid heap allocation for RP fields
        let mut rp_fields: SmallVec<[(&str, &str); 2]> = SmallVec::new();
        rp_fields.push(("id", request.rp().id.as_str()));
        if let Some(name) = &request.rp().name {
            rp_fields.push(("name", name.as_str()));
        }
        builder = builder
            .insert_text_map(2, &rp_fields)
            .map_err(|_| Error::Other)?;

        // 0x03: user (required)
        let user_cbor = soft_fido2_ctap::cbor::encode(&request.user()).map_err(|_| Error::Other)?;

        builder = builder
            .insert(
                3,
                &soft_fido2_ctap::cbor::decode::<Value>(&user_cbor).map_err(|_| Error::Other)?,
            )
            .map_err(|_| Error::Other)?;

        // 0x04: pubKeyCredParams (required) - ES256 only for now
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
        // Use SmallVec to avoid heap allocation for single algorithm
        let alg_params: SmallVec<[PubKeyCredParam; 1]> = SmallVec::from_buf([alg_param]);
        builder = builder.insert(4, alg_params).map_err(|_| Error::Other)?;

        // 0x05: excludeList (optional, empty for now)
        // 0x06: extensions (optional)

        // 0x07: options (optional)
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
        transport.send_ctap_command_buf(0x01, &request_bytes, response, request.timeout_ms)
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
            #[derive(Serialize)]
            struct Credential<'a> {
                id: &'a [u8],
                #[serde(rename = "type")]
                credential_type: &'a str,
            }

            // Use SmallVec to avoid heap allocation for common cases (0-4 credentials)
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

        // 0x04: extensions (optional)

        // 0x05: options (optional)
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
        transport.send_ctap_command_buf(0x02, &request_bytes, response, request.timeout_ms)
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
        // authenticatorGetInfo has no parameters, use default 30s timeout
        transport.send_ctap_command_buf(0x04, &[], response, 30000)
    }

    /// Get credentials metadata
    ///
    /// Returns count of existing and maximum possible remaining discoverable credentials.
    ///
    /// # Arguments
    /// * `transport` - Transport to communicate with authenticator
    /// * `request` - Credential management request with PIN/UV auth
    ///
    /// # Returns
    /// Metadata about credential storage on the authenticator
    ///
    /// # Spec Requirements
    /// - Requires PIN/UV auth token with CredentialManagement permission (0x04)
    /// - Token MUST NOT have a permissions RP ID parameter
    /// - pinUvAuthParam = authenticate(pinUvAuthToken, 0x01)
    ///
    /// # Errors
    /// - `Error::PinAuthRequired` - PIN/UV auth token missing or invalid
    /// - `Error::UnauthorizedPermission` - Token lacks CredentialManagement permission
    ///
    /// # Example
    /// ```no_run
    /// use soft_fido2::{Client, Transport};
    /// use soft_fido2::request::{CredentialManagementRequest, PinUvAuth, PinUvAuthProtocol};
    ///
    /// # fn example(transport: &mut Transport, pin_token: Vec<u8>) -> soft_fido2::error::Result<()> {
    /// let pin_uv_auth = PinUvAuth::new(pin_token, PinUvAuthProtocol::V2);
    /// let request = CredentialManagementRequest::new(Some(pin_uv_auth));
    /// let metadata = Client::get_credentials_metadata(transport, request)?;
    ///
    /// println!("Existing: {}", metadata.existing_resident_credentials_count);
    /// println!("Remaining: {}", metadata.max_possible_remaining_resident_credentials_count);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_credentials_metadata(
        transport: &mut Transport,
        request: CredentialManagementRequest,
    ) -> Result<crate::response::CredentialsMetadata> {
        // Build pinUvAuthParam: authenticate(pinUvAuthToken, 0x01)
        // For this subcommand, message is just the subcommand byte (0x01)
        let message = vec![0x01u8];

        let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
            let pin_uv_auth_param =
                calculate_pin_uv_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

            // Build CBOR request
            MapBuilder::new()
                .insert(0x01, 0x01u8)? // subCommand: getCredsMetadata
                .insert(0x03, pin_auth.protocol_u8())? // pinUvAuthProtocol
                .insert_bytes(0x04, &pin_uv_auth_param)? // pinUvAuthParam
                .build()
                .map_err(|_| Error::Other)?
        } else {
            // No PIN auth required
            MapBuilder::new()
                .insert(0x01, 0x01u8)? // subCommand: getCredsMetadata
                .build()
                .map_err(|_| Error::Other)?
        };

        // Send CTAP command 0x0A (authenticatorCredentialManagement)
        let response = transport.send_ctap_command(0x0A, &request_bytes, 30000)?;

        // Parse response
        crate::response::CredentialsMetadata::from_cbor(&response)
    }

    /// Begin RP enumeration
    ///
    /// Returns first RP information and total count.
    /// Use `enumerate_rps_get_next` to retrieve remaining RPs,
    /// or use `enumerate_rps` convenience method for automatic enumeration.
    ///
    /// # Arguments
    /// * `transport` - Transport to communicate with authenticator
    /// * `request` - Credential management request with PIN/UV auth
    ///
    /// # Returns
    /// First RP and total count
    ///
    /// # Spec Requirements
    /// - Requires PIN/UV auth token with CredentialManagement permission
    /// - Token MUST NOT have permissions RP ID parameter
    /// - pinUvAuthParam = authenticate(pinUvAuthToken, 0x02)
    /// - Returns CTAP2_ERR_NO_CREDENTIALS if no discoverable credentials exist
    ///
    /// # Errors
    /// - `Error::NoCredentials` - No discoverable credentials on authenticator
    pub fn enumerate_rps_begin(
        transport: &mut Transport,
        request: CredentialManagementRequest,
    ) -> Result<crate::response::RpEnumerationBeginResponse> {
        // Build pinUvAuthParam: authenticate(pinUvAuthToken, 0x02)
        let message = vec![0x02u8];

        let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
            let pin_uv_auth_param =
                calculate_pin_uv_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

            // Build CBOR request
            MapBuilder::new()
                .insert(0x01, 0x02u8)? // subCommand: enumerateRPsBegin
                .insert(0x03, pin_auth.protocol_u8())? // pinUvAuthProtocol
                .insert_bytes(0x04, &pin_uv_auth_param)? // pinUvAuthParam
                .build()
                .map_err(|_| Error::Other)?
        } else {
            // No PIN auth required
            MapBuilder::new()
                .insert(0x01, 0x02u8)? // subCommand: enumerateRPsBegin
                .build()
                .map_err(|_| Error::Other)?
        };

        // Send command
        let response = transport.send_ctap_command(0x0A, &request_bytes, 30000)?;

        // Parse response
        crate::response::RpEnumerationBeginResponse::from_cbor(&response)
    }

    /// Get next RP in enumeration
    ///
    /// Stateful command - MUST be called after `enumerate_rps_begin`.
    /// Call (total_rps - 1) times to retrieve all remaining RPs.
    ///
    /// # Returns
    /// Next RP information
    ///
    /// # Note
    /// This is a stateful command. The authenticator maintains enumeration state
    /// and returns the next RP in sequence. No PIN/UV auth required for continuation.
    pub fn enumerate_rps_get_next(transport: &mut Transport) -> Result<crate::response::RpInfo> {
        // Build CBOR request (only subCommand, no PIN auth)
        let request_bytes = MapBuilder::new()
            .insert(0x01, 0x03u8)? // subCommand: enumerateRPsGetNextRP
            .build()
            .map_err(|_| Error::Other)?;

        // Send command
        let response = transport.send_ctap_command(0x0A, &request_bytes, 30000)?;

        // Parse response
        crate::response::RpEnumerationNextResponse::from_cbor(&response)
    }

    /// Enumerate all RPs (convenience method)
    ///
    /// Automatically handles begin + get_next calls to retrieve all RPs.
    /// This is the recommended method for most use cases.
    ///
    /// # Returns
    /// Vec of all RPs on the authenticator
    ///
    /// # Example
    /// ```no_run
    /// use soft_fido2::{Client, Transport};
    /// use soft_fido2::request::{CredentialManagementRequest, PinUvAuth, PinUvAuthProtocol};
    ///
    /// # fn example(transport: &mut Transport, pin_token: Vec<u8>) -> soft_fido2::error::Result<()> {
    /// let pin_uv_auth = PinUvAuth::new(pin_token, PinUvAuthProtocol::V2);
    /// let request = CredentialManagementRequest::new(Some(pin_uv_auth));
    /// let rps = Client::enumerate_rps(transport, request)?;
    ///
    /// for rp in rps {
    ///     println!("RP: {} ({})", rp.id, rp.name.unwrap_or_default());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn enumerate_rps(
        transport: &mut Transport,
        request: CredentialManagementRequest,
    ) -> Result<Vec<crate::response::RpInfo>> {
        // Call begin to get first RP and total count
        let begin_response = Self::enumerate_rps_begin(transport, request)?;

        // Pre-allocate vector with known capacity to avoid reallocations
        let mut rps = Vec::with_capacity(begin_response.total_rps as usize);
        rps.push(begin_response.rp);

        // Call get_next for remaining RPs
        for _ in 1..begin_response.total_rps {
            let rp = Self::enumerate_rps_get_next(transport)?;
            rps.push(rp);
        }

        Ok(rps)
    }

    /// Begin credential enumeration for an RP
    ///
    /// Returns first credential and total count.
    /// Use `enumerate_credentials_get_next` to retrieve remaining credentials,
    /// or use `enumerate_credentials` convenience method for automatic enumeration.
    ///
    /// # Arguments
    /// * `transport` - Transport to communicate with authenticator
    /// * `request` - Enumerate credentials request with RP ID hash
    ///
    /// # Spec Requirements
    /// - pinUvAuthParam = authenticate(pinUvAuthToken, 0x04 || subCommandParams)
    /// - subCommandParams is CBOR-encoded map: {0x01: rpIDHash}
    /// - Token may have permissions RP ID that matches the requested RP
    ///
    /// # Note
    /// Platforms SHOULD perform large-blob garbage collection during enumeration.
    pub fn enumerate_credentials_begin(
        transport: &mut Transport,
        request: EnumerateCredentialsRequest,
    ) -> Result<crate::response::CredentialEnumerationBeginResponse> {
        // Build subCommandParams: {0x01: rpIDHash}
        let sub_params = MapBuilder::new()
            .insert_bytes(0x01, request.rp_id_hash())?
            .build()
            .map_err(|_| Error::Other)?;

        // Build message for pinUvAuthParam: 0x04 || subCommandParams
        let mut message = vec![0x04u8];
        message.extend_from_slice(&sub_params);

        let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
            let pin_uv_auth_param =
                calculate_pin_uv_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

            // Build CBOR request
            let sub_params_value =
                soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                    .map_err(|_| Error::Other)?;

            MapBuilder::new()
                .insert(0x01, 0x04u8)? // subCommand: enumerateCredentialsBegin
                .insert(0x02, sub_params_value)? // subCommandParams
                .insert(0x03, pin_auth.protocol_u8())? // pinUvAuthProtocol
                .insert_bytes(0x04, &pin_uv_auth_param)? // pinUvAuthParam
                .build()
                .map_err(|_| Error::Other)?
        } else {
            // No PIN auth required
            let sub_params_value =
                soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                    .map_err(|_| Error::Other)?;

            MapBuilder::new()
                .insert(0x01, 0x04u8)? // subCommand: enumerateCredentialsBegin
                .insert(0x02, sub_params_value)? // subCommandParams
                .build()
                .map_err(|_| Error::Other)?
        };

        // Send command
        let response = transport.send_ctap_command(0x0A, &request_bytes, 30000)?;

        // Parse response
        crate::response::CredentialEnumerationBeginResponse::from_cbor(&response)
    }

    /// Get next credential in enumeration
    ///
    /// Stateful command - MUST be called after `enumerate_credentials_begin`.
    /// Call (total_credentials - 1) times to retrieve all remaining credentials.
    pub fn enumerate_credentials_get_next(
        transport: &mut Transport,
    ) -> Result<crate::response::CredentialInfo> {
        // Build CBOR request (only subCommand, no PIN auth)
        let request_bytes = MapBuilder::new()
            .insert(0x01, 0x05u8)? // subCommand: enumerateCredentialsGetNextCredential
            .build()
            .map_err(|_| Error::Other)?;

        // Send command
        let response = transport.send_ctap_command(0x0A, &request_bytes, 30000)?;

        // Parse response
        crate::response::CredentialEnumerationNextResponse::from_cbor(&response)
    }

    /// Enumerate all credentials for an RP (convenience method)
    ///
    /// Automatically handles begin + get_next calls.
    ///
    /// # Example
    /// ```no_run
    /// use soft_fido2::{Client, Transport, compute_rp_id_hash};
    /// use soft_fido2::request::{EnumerateCredentialsRequest, PinUvAuth, PinUvAuthProtocol};
    ///
    /// # fn example(transport: &mut Transport, pin_token: Vec<u8>) -> soft_fido2::error::Result<()> {
    /// let pin_uv_auth = PinUvAuth::new(pin_token, PinUvAuthProtocol::V2);
    /// let rp_id_hash = compute_rp_id_hash("example.com");
    /// let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth), rp_id_hash);
    ///
    /// let credentials = Client::enumerate_credentials(transport, request)?;
    /// for cred in credentials {
    ///     println!("User: {:?}", cred.user.name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn enumerate_credentials(
        transport: &mut Transport,
        request: EnumerateCredentialsRequest,
    ) -> Result<Vec<crate::response::CredentialInfo>> {
        // Call begin
        let begin_response = Self::enumerate_credentials_begin(transport, request)?;

        // Pre-allocate vector with known capacity to avoid reallocations
        let mut credentials = Vec::with_capacity(begin_response.total_credentials as usize);
        credentials.push(begin_response.credential);

        // Call get_next for remaining credentials
        for _ in 1..begin_response.total_credentials {
            let cred = Self::enumerate_credentials_get_next(transport)?;
            credentials.push(cred);
        }

        Ok(credentials)
    }

    /// Delete a credential
    ///
    /// Permanently removes a credential from the authenticator.
    ///
    /// # Arguments
    /// * `transport` - Transport to communicate with authenticator
    /// * `request` - Delete credential request
    ///
    /// # Returns
    /// Ok(()) on success
    ///
    /// # Spec Requirements
    /// - pinUvAuthParam = authenticate(pinUvAuthToken, 0x06 || subCommandParams)
    /// - subCommandParams: {0x02: credentialId} where credentialId is PublicKeyCredentialDescriptor
    /// - Token may have permissions RP ID matching the credential's RP
    ///
    /// # Important
    /// Platforms SHOULD also delete any associated large blobs after successful deletion.
    ///
    /// # Errors
    /// - `Error::NoCredentials` - Credential not found
    /// - `Error::UnauthorizedPermission` - Token lacks permission or wrong RP ID
    ///
    /// # Example
    /// ```no_run
    /// use soft_fido2::{Client, Transport};
    /// use soft_fido2::request::{DeleteCredentialRequest, PinUvAuth, PinUvAuthProtocol};
    ///
    /// # fn example(transport: &mut Transport, pin_token: Vec<u8>, cred_id: Vec<u8>) -> soft_fido2::error::Result<()> {
    /// let pin_uv_auth = PinUvAuth::new(pin_token, PinUvAuthProtocol::V2);
    /// let request = DeleteCredentialRequest::new(Some(pin_uv_auth), cred_id);
    ///
    /// Client::delete_credential(transport, request)?;
    /// println!("Credential deleted successfully");
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete_credential(
        transport: &mut Transport,
        request: DeleteCredentialRequest,
    ) -> Result<()> {
        // Build credential descriptor
        let cred_descriptor = build_credential_descriptor_cbor(request.credential_id())?;

        // Build subCommandParams: {0x02: credentialId}
        let sub_params = MapBuilder::new()
            .insert(0x02, cred_descriptor)?
            .build()
            .map_err(|_| Error::Other)?;

        // Build message for pinUvAuthParam: 0x06 || subCommandParams
        let mut message = vec![0x06u8];
        message.extend_from_slice(&sub_params);

        let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
            let pin_uv_auth_param =
                calculate_pin_uv_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

            // Build CBOR request
            let sub_params_value =
                soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                    .map_err(|_| Error::Other)?;

            MapBuilder::new()
                .insert(0x01, 0x06u8)? // subCommand: deleteCredential
                .insert(0x02, sub_params_value)? // subCommandParams
                .insert(0x03, pin_auth.protocol_u8())? // pinUvAuthProtocol
                .insert_bytes(0x04, &pin_uv_auth_param)? // pinUvAuthParam
                .build()
                .map_err(|_| Error::Other)?
        } else {
            // No PIN auth required
            let sub_params_value =
                soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                    .map_err(|_| Error::Other)?;

            MapBuilder::new()
                .insert(0x01, 0x06u8)? // subCommand: deleteCredential
                .insert(0x02, sub_params_value)? // subCommandParams
                .build()
                .map_err(|_| Error::Other)?
        };

        // Send command
        let _response = transport.send_ctap_command(0x0A, &request_bytes, 30000)?;

        // Response is empty CBOR map on success
        Ok(())
    }

    /// Update user information for a credential
    ///
    /// Updates the name and displayName fields of a credential's user entity.
    ///
    /// # Arguments
    /// * `transport` - Transport to communicate with authenticator
    /// * `request` - Update user request
    ///
    /// # Returns
    /// Ok(()) on success
    ///
    /// # Spec Requirements
    /// - User ID in request MUST match existing credential's user ID
    /// - Empty fields in user parameter are removed from credential
    /// - Only name and displayName are updated (id is not changed)
    /// - pinUvAuthParam = authenticate(pinUvAuthToken, 0x07 || subCommandParams)
    ///
    /// # Errors
    /// - `Error::NoCredentials` - Credential not found
    /// - `Error::InvalidParameter` - User ID mismatch
    /// - `Error::KeyStoreFull` - Insufficient storage for update
    ///
    /// # Example
    /// ```no_run
    /// use soft_fido2::{Client, Transport};
    /// use soft_fido2::request::{UpdateUserRequest, PinUvAuth, PinUvAuthProtocol};
    /// use soft_fido2::types::User;
    ///
    /// # fn example(transport: &mut Transport, pin_token: Vec<u8>, cred_id: Vec<u8>) -> soft_fido2::error::Result<()> {
    /// let pin_uv_auth = PinUvAuth::new(pin_token, PinUvAuthProtocol::V2);
    /// let user = User {
    ///     id: vec![1, 2, 3, 4],
    ///     name: Some("newname@example.com".to_string()),
    ///     display_name: Some("New Display Name".to_string()),
    /// };
    /// let request = UpdateUserRequest::new(Some(pin_uv_auth), cred_id, user);
    ///
    /// Client::update_user_information(transport, request)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn update_user_information(
        transport: &mut Transport,
        request: UpdateUserRequest,
    ) -> Result<()> {
        // Build credential descriptor
        let cred_descriptor = build_credential_descriptor_cbor(request.credential_id())?;

        // Build subCommandParams: {0x02: credentialId, 0x03: user}
        let sub_params = MapBuilder::new()
            .insert(0x02, cred_descriptor)?
            .insert(0x03, request.user())?
            .build()
            .map_err(|_| Error::Other)?;

        // Build message for pinUvAuthParam: 0x07 || subCommandParams
        let mut message = vec![0x07u8];
        message.extend_from_slice(&sub_params);

        let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
            let pin_uv_auth_param =
                calculate_pin_uv_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

            // Build CBOR request
            let sub_params_value =
                soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                    .map_err(|_| Error::Other)?;

            MapBuilder::new()
                .insert(0x01, 0x07u8)? // subCommand: updateUserInformation
                .insert(0x02, sub_params_value)? // subCommandParams
                .insert(0x03, pin_auth.protocol_u8())? // pinUvAuthProtocol
                .insert_bytes(0x04, &pin_uv_auth_param)? // pinUvAuthParam
                .build()
                .map_err(|_| Error::Other)?
        } else {
            // No PIN auth required
            let sub_params_value =
                soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                    .map_err(|_| Error::Other)?;

            MapBuilder::new()
                .insert(0x01, 0x07u8)? // subCommand: updateUserInformation
                .insert(0x02, sub_params_value)? // subCommandParams
                .build()
                .map_err(|_| Error::Other)?
        };

        // Send command
        let _response = transport.send_ctap_command(0x0A, &request_bytes, 30000)?;

        // Response is empty CBOR map on success
        Ok(())
    }
}

/// Compute SHA-256 hash of RP ID
///
/// # Arguments
/// * `rp_id` - Relying party identifier (e.g., "example.com")
///
/// # Returns
/// 32-byte SHA-256 hash
pub fn compute_rp_id_hash(rp_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    hasher.finalize().into()
}

/// Build PublicKeyCredentialDescriptor CBOR map
///
/// Creates CBOR map with "id" (bytes) and "type" (text "public-key")
/// in canonical CBOR order.
fn build_credential_descriptor_cbor(credential_id: &[u8]) -> Result<soft_fido2_ctap::cbor::Value> {
    // Must be in canonical CBOR order: "id" (len 2) before "type" (len 4)
    Ok(soft_fido2_ctap::cbor::Value::Map(vec![
        (
            soft_fido2_ctap::cbor::Value::Text("id".to_string()),
            soft_fido2_ctap::cbor::Value::Bytes(credential_id.to_vec()),
        ),
        (
            soft_fido2_ctap::cbor::Value::Text("type".to_string()),
            soft_fido2_ctap::cbor::Value::Text("public-key".to_string()),
        ),
    ]))
}

/// Helper: Calculate PIN/UV auth param
///
/// Computes HMAC-SHA-256 using the PIN/UV auth token and returns first 16 bytes.
fn calculate_pin_uv_auth_param(
    token: &[u8],
    protocol: PinUvAuthProtocol,
    message: &[u8],
) -> Result<Vec<u8>> {
    match protocol {
        PinUvAuthProtocol::V1 => {
            // Protocol V1: authenticate(key, message) = LEFT(HMAC-SHA-256(key, message), 16)
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            let mut mac = HmacSha256::new_from_slice(token).map_err(|_| Error::Other)?;
            mac.update(message);
            let result = mac.finalize();
            let bytes = result.into_bytes();

            Ok(bytes[..16].to_vec())
        }
        PinUvAuthProtocol::V2 => {
            // Protocol V2: Same as V1 for authenticate
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            let mut mac = HmacSha256::new_from_slice(token).map_err(|_| Error::Other)?;
            mac.update(message);
            let result = mac.finalize();
            let bytes = result.into_bytes();

            Ok(bytes[..16].to_vec())
        }
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

    #[test]
    fn test_compute_rp_id_hash() {
        let hash = compute_rp_id_hash("example.com");
        assert_eq!(hash.len(), 32);

        // Verify deterministic
        let hash2 = compute_rp_id_hash("example.com");
        assert_eq!(hash, hash2);

        // Verify different inputs produce different hashes
        let hash3 = compute_rp_id_hash("other.com");
        assert_ne!(hash, hash3);
    }
}
