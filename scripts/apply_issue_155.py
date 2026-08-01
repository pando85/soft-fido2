from pathlib import Path

path = Path("soft-fido2-ctap/src/commands/make_credential.rs")
text = path.read_text()

call = """    check_exclude_list(
        auth,
        &exclude_list,
        &response_state,
        &pin_uv_auth_param,
        evidence_from_step_11,
    )?;
"""
call_fixed = """    check_exclude_list(
        auth,
        &exclude_list,
        &rp.id,
        &response_state,
        &pin_uv_auth_param,
        evidence_from_step_11,
    )?;
"""
assert text.count(call) == 1
text = text.replace(call, call_fixed, 1)

start = text.index("fn check_exclude_list<")
end = text.index("/// Step 14: Collect user presence", start)
replacement = r'''fn excluded_credential_policy<
    C: AuthenticatorCallbacks,
    K: CredentialKeyProvider,
>(
    auth: &Authenticator<C, K>,
    credential: &PublicKeyCredentialDescriptor,
    rp_id: &str,
) -> Option<u8> {
    // Discoverable credentials are resolved through callback-managed storage.
    if let Ok(stored) = auth.callbacks().get_credential(&credential.id)
        && stored.rp_id == rp_id
    {
        return Some(stored.cred_protect);
    }

    // Non-discoverable credentials are self-contained authenticated blobs. A
    // successful unwrap proves that this authenticator created the credential;
    // the embedded RP ID still has to match the current request.
    if let Ok((_key, wrapped_rp_id, _algorithm)) = auth.unwrap_credential(&credential.id)
        && wrapped_rp_id == rp_id
    {
        // The current wrapped formats predate embedded credProtect metadata and
        // therefore use the default optional policy, matching GetAssertion.
        return Some(CredProtect::UserVerificationOptional as u8);
    }

    None
}

/// Step 12: Check excludeList for credential exclusion.
fn check_exclude_list<C: AuthenticatorCallbacks, K: CredentialKeyProvider>(
    auth: &Authenticator<C, K>,
    exclude_list: &Option<Vec<PublicKeyCredentialDescriptor>>,
    rp_id: &str,
    response_state: &ResponseState,
    pin_uv_auth_param: &Option<Vec<u8>>,
    evidence_from_step_11: bool,
) -> Result<()> {
    if let Some(exclude) = exclude_list {
        for cred_desc in exclude {
            let Some(cred_protect) = excluded_credential_policy(auth, cred_desc, rp_id) else {
                continue;
            };

            if cred_protect != CredProtect::UserVerificationRequired as u8 {
                let user_present = if pin_uv_auth_param.is_some() {
                    get_user_present_flag_value(auth)
                } else {
                    evidence_from_step_11
                };

                if !user_present {
                    // Preserve the existing privacy behaviour: the caller does
                    // not learn about the credential until user interaction has
                    // been established.
                    return Err(StatusCode::CredentialExcluded);
                }

                return Err(StatusCode::CredentialExcluded);
            }

            // UV-required credentials are only disclosed after successful UV.
            if response_state.uv {
                let user_present = if pin_uv_auth_param.is_some() {
                    get_user_present_flag_value(auth)
                } else {
                    evidence_from_step_11
                };

                if !user_present {
                    return Err(StatusCode::CredentialExcluded);
                }

                return Err(StatusCode::CredentialExcluded);
            }
        }
    }

    Ok(())
}

'''
text = text[:start] + replacement + text[end:]

new_tests = r'''

    #[test]
    fn wrapped_credential_matches_same_rp_exclude_list() {
        use crate::{
            authenticator::{Authenticator, AuthenticatorConfig},
            key_provider::CredentialKey,
            test_utils::MockCallbacks,
            SecBytes,
        };

        let config = AuthenticatorConfig::new().with_force_resident_keys(false);
        let auth = Authenticator::new(config, MockCallbacks);
        let key = CredentialKey::software(SecBytes::from_slice(&[0x42; 32]));
        let id = auth.wrap_credential(&key, "example.com", -7).unwrap();
        let descriptor = PublicKeyCredentialDescriptor {
            r#type: "public-key".to_string(),
            id,
            transports: None,
        };

        assert_eq!(
            excluded_credential_policy(&auth, &descriptor, "example.com"),
            Some(CredProtect::UserVerificationOptional as u8)
        );
    }

    #[test]
    fn wrapped_credential_does_not_match_another_rp() {
        use crate::{
            authenticator::{Authenticator, AuthenticatorConfig},
            key_provider::CredentialKey,
            test_utils::MockCallbacks,
            SecBytes,
        };

        let config = AuthenticatorConfig::new().with_force_resident_keys(false);
        let auth = Authenticator::new(config, MockCallbacks);
        let key = CredentialKey::software(SecBytes::from_slice(&[0x43; 32]));
        let id = auth.wrap_credential(&key, "example.com", -7).unwrap();
        let descriptor = PublicKeyCredentialDescriptor {
            r#type: "public-key".to_string(),
            id,
            transports: None,
        };

        assert_eq!(
            excluded_credential_policy(&auth, &descriptor, "other.example"),
            None
        );
    }

    #[test]
    fn tampered_wrapped_credential_is_not_an_exclude_match() {
        use crate::{
            authenticator::{Authenticator, AuthenticatorConfig},
            key_provider::CredentialKey,
            test_utils::MockCallbacks,
            SecBytes,
        };

        let config = AuthenticatorConfig::new().with_force_resident_keys(false);
        let auth = Authenticator::new(config, MockCallbacks);
        let key = CredentialKey::software(SecBytes::from_slice(&[0x44; 32]));
        let mut id = auth.wrap_credential(&key, "example.com", -7).unwrap();
        let last = id.len() - 1;
        id[last] ^= 0x01;
        let descriptor = PublicKeyCredentialDescriptor {
            r#type: "public-key".to_string(),
            id,
            transports: None,
        };

        assert_eq!(
            excluded_credential_policy(&auth, &descriptor, "example.com"),
            None
        );
    }
'''
last = text.rfind("\n}")
assert last != -1
text = text[:last] + new_tests + text[last:]

path.write_text(text)
