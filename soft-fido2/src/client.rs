//! FIDO2 Client API
//!
//! High-level client interface for communicating with FIDO2 authenticators.

use crate::error::{Error, Result};
use crate::request::{GetAssertionRequest, MakeCredentialRequest};
use crate::transport::Transport;

use soft_fido2_ctap::cbor::Value;

/// Client for communicating with FIDO2 authenticators
///
/// Matches the API of the zig-ffi Client type.
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
        // Build the CTAP2 authenticatorMakeCredential request
        let mut cbor_request = Vec::new();

        // 0x01: clientDataHash (required)
        cbor_request.push((
            Value::Integer(1.into()),
            Value::Bytes(request.client_data_hash().as_slice().to_vec()),
        ));

        // 0x02: rp (required)
        let mut rp_map = Vec::new();
        rp_map.push((
            Value::Text("id".to_string()),
            Value::Text(request.rp().id.clone()),
        ));
        if let Some(name) = &request.rp().name {
            rp_map.push((Value::Text("name".to_string()), Value::Text(name.clone())));
        }
        cbor_request.push((Value::Integer(2.into()), Value::Map(rp_map)));

        // 0x03: user (required)
        let mut user_map = Vec::new();
        user_map.push((
            Value::Text("id".to_string()),
            Value::Bytes(request.user().id.clone()),
        ));
        if let Some(name) = &request.user().name {
            user_map.push((Value::Text("name".to_string()), Value::Text(name.clone())));
        }
        if let Some(display_name) = &request.user().display_name {
            user_map.push((
                Value::Text("displayName".to_string()),
                Value::Text(display_name.clone()),
            ));
        }
        cbor_request.push((Value::Integer(3.into()), Value::Map(user_map)));

        // 0x04: pubKeyCredParams (required) - ES256 only for now
        let alg_param = vec![
            (Value::Text("alg".to_string()), Value::Integer((-7).into())),
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
        ];
        cbor_request.push((
            Value::Integer(4.into()),
            Value::Array(vec![Value::Map(alg_param)]),
        ));

        // 0x05: excludeList (optional, empty for now)
        // 0x06: extensions (optional)

        // 0x07: options (optional)
        if request.resident_key.is_some() || request.user_verification.is_some() {
            let mut options_map = Vec::new();
            if let Some(rk) = request.resident_key {
                options_map.push((Value::Text("rk".to_string()), Value::Bool(rk)));
            }
            if let Some(uv) = request.user_verification {
                options_map.push((Value::Text("uv".to_string()), Value::Bool(uv)));
            }
            cbor_request.push((Value::Integer(7.into()), Value::Map(options_map)));
        }

        // 0x08: pinUvAuthParam (optional)
        if let Some(pin_auth) = request.pin_uv_auth() {
            cbor_request.push((
                Value::Integer(8.into()),
                Value::Bytes(pin_auth.param().to_vec()),
            ));

            // 0x09: pinUvAuthProtocol (required if pinUvAuthParam is present)
            cbor_request.push((
                Value::Integer(9.into()),
                Value::Integer(pin_auth.protocol_u8().into()),
            ));
        }

        // Encode request to CBOR
        let mut request_bytes = Vec::new();
        soft_fido2_ctap::cbor::into_writer(&Value::Map(cbor_request), &mut request_bytes)
            .map_err(|_| Error::Other)?;

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
        // Build the CTAP2 authenticatorGetAssertion request
        let mut cbor_request = Vec::new();

        // 0x01: rpId (required)
        cbor_request.push((
            Value::Integer(1.into()),
            Value::Text(request.rp_id().to_string()),
        ));

        // 0x02: clientDataHash (required)
        cbor_request.push((
            Value::Integer(2.into()),
            Value::Bytes(request.client_data_hash().as_slice().to_vec()),
        ));

        // 0x03: allowList (optional)
        if !request.allow_list().is_empty() {
            let allow_list: Vec<Value> = request
                .allow_list()
                .iter()
                .map(|cred| {
                    let cred_map = vec![
                        (Value::Text("id".to_string()), Value::Bytes(cred.id.clone())),
                        (
                            Value::Text("type".to_string()),
                            Value::Text(cred.credential_type.as_str().to_string()),
                        ),
                    ];
                    Value::Map(cred_map)
                })
                .collect();
            cbor_request.push((Value::Integer(3.into()), Value::Array(allow_list)));
        }

        // 0x04: extensions (optional)

        // 0x05: options (optional)
        if request.user_verification.is_some() {
            let mut options_map = Vec::new();
            if let Some(uv) = request.user_verification {
                options_map.push((Value::Text("uv".to_string()), Value::Bool(uv)));
            }
            cbor_request.push((Value::Integer(5.into()), Value::Map(options_map)));
        }

        // 0x06: pinUvAuthParam (optional)
        if let Some(pin_auth) = request.pin_uv_auth() {
            cbor_request.push((
                Value::Integer(6.into()),
                Value::Bytes(pin_auth.param().to_vec()),
            ));

            // 0x07: pinUvAuthProtocol (required if pinUvAuthParam is present)
            cbor_request.push((
                Value::Integer(7.into()),
                Value::Integer(pin_auth.protocol_u8().into()),
            ));
        }

        // Encode request to CBOR
        let mut request_bytes = Vec::new();
        soft_fido2_ctap::cbor::into_writer(&Value::Map(cbor_request), &mut request_bytes)
            .map_err(|_| Error::Other)?;

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
    /// This method still performs internal allocations for CBOR encoding (using ciborium).
    /// To achieve fully zero-allocation operation, a custom CBOR encoder would be needed.
    /// However, it eliminates the final response allocation by writing directly to the caller's buffer.
    pub fn make_credential_buf(
        transport: &mut Transport,
        request: MakeCredentialRequest,
        response: &mut [u8],
    ) -> Result<usize> {
        // Build the CTAP2 authenticatorMakeCredential request
        let mut cbor_request = Vec::new();

        // 0x01: clientDataHash (required)
        cbor_request.push((
            Value::Integer(1.into()),
            Value::Bytes(request.client_data_hash().as_slice().to_vec()),
        ));

        // 0x02: rp (required)
        let mut rp_map = Vec::new();
        rp_map.push((
            Value::Text("id".to_string()),
            Value::Text(request.rp().id.clone()),
        ));
        if let Some(name) = &request.rp().name {
            rp_map.push((Value::Text("name".to_string()), Value::Text(name.clone())));
        }
        cbor_request.push((Value::Integer(2.into()), Value::Map(rp_map)));

        // 0x03: user (required)
        let mut user_map = Vec::new();
        user_map.push((
            Value::Text("id".to_string()),
            Value::Bytes(request.user().id.clone()),
        ));
        if let Some(name) = &request.user().name {
            user_map.push((Value::Text("name".to_string()), Value::Text(name.clone())));
        }
        if let Some(display_name) = &request.user().display_name {
            user_map.push((
                Value::Text("displayName".to_string()),
                Value::Text(display_name.clone()),
            ));
        }
        cbor_request.push((Value::Integer(3.into()), Value::Map(user_map)));

        // 0x04: pubKeyCredParams (required) - ES256 only for now
        let alg_param = vec![
            (Value::Text("alg".to_string()), Value::Integer((-7).into())),
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
        ];
        cbor_request.push((
            Value::Integer(4.into()),
            Value::Array(vec![Value::Map(alg_param)]),
        ));

        // 0x05: excludeList (optional, empty for now)
        // 0x06: extensions (optional)

        // 0x07: options (optional)
        if request.resident_key.is_some() || request.user_verification.is_some() {
            let mut options_map = Vec::new();
            if let Some(rk) = request.resident_key {
                options_map.push((Value::Text("rk".to_string()), Value::Bool(rk)));
            }
            if let Some(uv) = request.user_verification {
                options_map.push((Value::Text("uv".to_string()), Value::Bool(uv)));
            }
            cbor_request.push((Value::Integer(7.into()), Value::Map(options_map)));
        }

        // 0x08: pinUvAuthParam (optional)
        if let Some(pin_auth) = request.pin_uv_auth() {
            cbor_request.push((
                Value::Integer(8.into()),
                Value::Bytes(pin_auth.param().to_vec()),
            ));

            // 0x09: pinUvAuthProtocol (required if pinUvAuthParam is present)
            cbor_request.push((
                Value::Integer(9.into()),
                Value::Integer(pin_auth.protocol_u8().into()),
            ));
        }

        // Encode request to CBOR
        let mut request_bytes = Vec::new();
        soft_fido2_ctap::cbor::into_writer(&Value::Map(cbor_request), &mut request_bytes)
            .map_err(|_| Error::Other)?;

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
    /// This method still performs internal allocations for CBOR encoding (using ciborium).
    /// To achieve fully zero-allocation operation, a custom CBOR encoder would be needed.
    /// However, it eliminates the final response allocation by writing directly to the caller's buffer.
    pub fn get_assertion_buf(
        transport: &mut Transport,
        request: GetAssertionRequest,
        response: &mut [u8],
    ) -> Result<usize> {
        // Build the CTAP2 authenticatorGetAssertion request
        let mut cbor_request = Vec::new();

        // 0x01: rpId (required)
        cbor_request.push((
            Value::Integer(1.into()),
            Value::Text(request.rp_id().to_string()),
        ));

        // 0x02: clientDataHash (required)
        cbor_request.push((
            Value::Integer(2.into()),
            Value::Bytes(request.client_data_hash().as_slice().to_vec()),
        ));

        // 0x03: allowList (optional)
        if !request.allow_list().is_empty() {
            let allow_list: Vec<Value> = request
                .allow_list()
                .iter()
                .map(|cred| {
                    let cred_map = vec![
                        (Value::Text("id".to_string()), Value::Bytes(cred.id.clone())),
                        (
                            Value::Text("type".to_string()),
                            Value::Text(cred.credential_type.as_str().to_string()),
                        ),
                    ];
                    Value::Map(cred_map)
                })
                .collect();
            cbor_request.push((Value::Integer(3.into()), Value::Array(allow_list)));
        }

        // 0x04: extensions (optional)

        // 0x05: options (optional)
        if request.user_verification.is_some() {
            let mut options_map = Vec::new();
            if let Some(uv) = request.user_verification {
                options_map.push((Value::Text("uv".to_string()), Value::Bool(uv)));
            }
            cbor_request.push((Value::Integer(5.into()), Value::Map(options_map)));
        }

        // 0x06: pinUvAuthParam (optional)
        if let Some(pin_auth) = request.pin_uv_auth() {
            cbor_request.push((
                Value::Integer(6.into()),
                Value::Bytes(pin_auth.param().to_vec()),
            ));

            // 0x07: pinUvAuthProtocol (required if pinUvAuthParam is present)
            cbor_request.push((
                Value::Integer(7.into()),
                Value::Integer(pin_auth.protocol_u8().into()),
            ));
        }

        // Encode request to CBOR
        let mut request_bytes = Vec::new();
        soft_fido2_ctap::cbor::into_writer(&Value::Map(cbor_request), &mut request_bytes)
            .map_err(|_| Error::Other)?;

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
