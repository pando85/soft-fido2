//! authenticatorGetNextAssertion command
//!
//! Continues an assertion operation when there are multiple credentials
//! for a given RP. Must be called after authenticatorGetAssertion.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetNextAssertion>

use crate::{
    authenticator::{AssertionContext, Authenticator},
    callbacks::AuthenticatorCallbacks,
    cbor::MapBuilder,
    extensions::compute_hmac_secret,
    key_provider::CredentialKeyProvider,
    status::{Result, StatusCode},
    types::{CredentialBackupState, PublicKeyCredentialDescriptor, auth_data_flags},
};

use alloc::{string::ToString, vec::Vec};

use sha2::{Digest, Sha256};

mod resp_keys {
    pub const CREDENTIAL: i32 = 0x01;
    pub const AUTH_DATA: i32 = 0x02;
    pub const SIGNATURE: i32 = 0x03;
    pub const USER: i32 = 0x04;
}

/// Handle authenticatorGetNextAssertion command
///
/// Returns the next assertion from the batch created by authenticatorGetAssertion.
pub fn handle<C: AuthenticatorCallbacks, K: CredentialKeyProvider>(
    auth: &mut Authenticator<C, K>,
    _data: &[u8],
) -> Result<Vec<u8>> {
    let (credential, context, _remaining) = auth.get_next_assertion()?;
    build_assertion_response(auth, credential, context)
}

fn build_assertion_response<C: AuthenticatorCallbacks, K: CredentialKeyProvider>(
    auth: &mut Authenticator<C, K>,
    credential: crate::types::Credential,
    context: AssertionContext,
) -> Result<Vec<u8>> {
    // Wrapped credentials have no durable mutable state. Reporting zero is
    // correct; repeatedly returning the same positive value is not.
    let new_sign_count = if auth.config().constant_sign_count || !credential.discoverable {
        0
    } else {
        credential.sign_count.saturating_add(1)
    };

    if !auth.config().constant_sign_count && credential.discoverable {
        let mut updated_cred = credential.clone();
        updated_cred.sign_count = new_sign_count;
        auth.callbacks().update_credential(&updated_cred)?;
    }

    let mut extension_outputs = context.extensions.build_outputs();
    if context.extensions.has_hmac_secret()
        && let Some(hmac_input) = context.extensions.get_hmac_secret()
        && let Some(keypair) = auth.get_pin_protocol_keypair(hmac_input.pin_uv_auth_protocol)
        && let Some(cred_random) = &credential.cred_random
        && let Some(encrypted_output) =
            compute_hmac_secret(hmac_input, cred_random.as_slice(), keypair)
    {
        let output = (
            crate::cbor::Value::Text(crate::extensions::ext_ids::HMAC_SECRET.to_string()),
            crate::cbor::Value::Bytes(encrypted_output),
        );

        if let Some(crate::cbor::Value::Map(ref mut map)) = extension_outputs {
            map.push(output);
        } else {
            extension_outputs = Some(crate::cbor::Value::Map(alloc::vec![output]));
        }
    }

    let auth_data = build_authenticator_data(
        &context.rp_id,
        context.up,
        context.uv,
        credential.backup_state,
        new_sign_count,
        extension_outputs.as_ref(),
    )?;
    let sig_data = [&auth_data[..], &context.client_data_hash[..]].concat();

    let signature = auth
        .key_provider()
        .sign(&credential.key, credential.algorithm, &sig_data)
        .map_err(StatusCode::from)?;

    let credential_desc = PublicKeyCredentialDescriptor {
        id: credential.id.clone(),
        r#type: "public-key".to_string(),
        transports: None,
    };

    let mut builder = MapBuilder::new()
        .insert(resp_keys::CREDENTIAL, credential_desc)?
        .insert_bytes(resp_keys::AUTH_DATA, &auth_data)?
        .insert_bytes(resp_keys::SIGNATURE, &signature)?;

    if credential.discoverable {
        let user = crate::types::User {
            id: credential.user_id.clone(),
            name: if context.uv {
                credential.user_name.clone()
            } else {
                None
            },
            display_name: if context.uv {
                credential.user_display_name.clone()
            } else {
                None
            },
        };
        builder = builder.insert(resp_keys::USER, user)?;
    }

    // numberOfCredentials is intentionally omitted from continuation responses.
    builder.build()
}

fn build_authenticator_data(
    rp_id: &str,
    up: bool,
    uv: bool,
    backup_state: CredentialBackupState,
    sign_count: u32,
    extensions: Option<&crate::cbor::Value>,
) -> Result<Vec<u8>> {
    let mut auth_data = Vec::new();

    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    auth_data.extend_from_slice(&hasher.finalize());

    let mut flags = 0u8;
    if up {
        flags |= auth_data_flags::UP;
    }
    if uv {
        flags |= auth_data_flags::UV;
    }
    flags |= backup_state.flags();
    if extensions.is_some() {
        flags |= auth_data_flags::ED;
    }
    auth_data.push(flags);

    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    if let Some(extension_value) = extensions {
        let mut encoded = Vec::new();
        crate::cbor::into_writer(extension_value, &mut encoded)?;
        auth_data.extend_from_slice(&encoded);
    }

    Ok(auth_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        authenticator::{Authenticator, AuthenticatorConfig},
        test_utils::MockCallbacks,
    };

    #[test]
    fn test_get_next_assertion_no_state() {
        let config = AuthenticatorConfig::new();
        let mut auth = Authenticator::new(config, MockCallbacks);

        let result = handle(&mut auth, &[]);
        assert_eq!(result, Err(StatusCode::NotAllowed));
    }
}
