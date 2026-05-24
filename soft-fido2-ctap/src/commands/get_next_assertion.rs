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
    status::{Result, StatusCode},
    types::{PublicKeyCredentialDescriptor, auth_data_flags},
};

use soft_fido2_crypto::{ecdsa, eddsa};

use alloc::{string::ToString, vec::Vec};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod resp_keys {
    pub const CREDENTIAL: i32 = 0x01;
    pub const AUTH_DATA: i32 = 0x02;
    pub const SIGNATURE: i32 = 0x03;
    pub const USER: i32 = 0x04;
    pub const NUMBER_OF_CREDENTIALS: i32 = 0x05;
}

/// Handle authenticatorGetNextAssertion command
///
/// Returns the next assertion from the batch created by authenticatorGetAssertion.
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    _data: &[u8],
) -> Result<Vec<u8>> {
    let (credential, context, remaining) = auth.get_next_assertion()?;
    build_assertion_response(auth, credential, context, remaining)
}

fn build_assertion_response<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    credential: crate::types::Credential,
    context: AssertionContext,
    remaining: usize,
) -> Result<Vec<u8>> {
    let new_sign_count = if auth.config().constant_sign_count {
        credential.sign_count
    } else {
        credential.sign_count + 1
    };

    if !auth.config().constant_sign_count && credential.discoverable {
        let mut updated_cred = credential.clone();
        updated_cred.sign_count = new_sign_count;
        auth.callbacks().update_credential(&updated_cred)?;
    }

    let auth_data =
        build_authenticator_data(&context.rp_id, context.up, context.uv, new_sign_count);
    let sig_data = [&auth_data[..], &context.client_data_hash[..]].concat();

    let key_bytes = credential.private_key.as_slice();
    if key_bytes.len() != 32 {
        return Err(StatusCode::InvalidCredential);
    }

    let priv_key_array = Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key_bytes);
        arr
    });

    let signature = match credential.algorithm {
        -8 | -19 => eddsa::sign(&priv_key_array, &sig_data)?,
        _ => ecdsa::sign(&priv_key_array, &sig_data)?,
    };

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

    if remaining > 0 {
        builder = builder.insert(resp_keys::NUMBER_OF_CREDENTIALS, remaining)?;
    }

    builder.build()
}

fn build_authenticator_data(rp_id: &str, up: bool, uv: bool, sign_count: u32) -> Vec<u8> {
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
    auth_data.push(flags);

    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data
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

        // Should return error when no assertion is in progress
        let result = handle(&mut auth, &[]);
        assert_eq!(result, Err(StatusCode::NoCredentials));
    }
}
