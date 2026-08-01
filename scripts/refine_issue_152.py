from pathlib import Path

client_pin = Path("soft-fido2-ctap/src/commands/client_pin.rs")
text = client_pin.read_text()

old_helper = '''const DEFAULT_PERMISSION_MASK: u8 =
    Permission::MakeCredential as u8 | Permission::GetAssertion as u8;

const KNOWN_PERMISSION_MASK: u8 = Permission::MakeCredential as u8
    | Permission::GetAssertion as u8
    | Permission::CredentialManagement as u8
    | Permission::BioEnrollment as u8
    | Permission::LargeBlobWrite as u8
    | Permission::AuthenticatorConfiguration as u8;

fn validate_requested_permissions<
    C: AuthenticatorCallbacks,
    K: crate::key_provider::CredentialKeyProvider,
>(
    auth: &Authenticator<C, K>,
    permissions: u8,
) -> Result<()> {
    if permissions == 0 || permissions & !KNOWN_PERMISSION_MASK != 0 {
        return Err(StatusCode::InvalidParameter);
    }

    let options = &auth.config().options;

    if Permission::CredentialManagement.is_set_in(permissions) && !options.cred_mgmt {
        return Err(StatusCode::UnauthorizedPermission);
    }
    if Permission::BioEnrollment.is_set_in(permissions) && options.bio_enroll != Some(true) {
        return Err(StatusCode::UnauthorizedPermission);
    }
    if Permission::LargeBlobWrite.is_set_in(permissions) && options.large_blobs != Some(true) {
        return Err(StatusCode::UnauthorizedPermission);
    }
    if Permission::AuthenticatorConfiguration.is_set_in(permissions) && !options.authnr_cfg {
        return Err(StatusCode::UnauthorizedPermission);
    }

    Ok(())
}
'''
new_helper = '''const DEFAULT_PERMISSION_MASK: u8 =
    Permission::MakeCredential as u8 | Permission::GetAssertion as u8;

const DEFINED_PERMISSION_MASK: u8 = Permission::MakeCredential as u8
    | Permission::GetAssertion as u8
    | Permission::CredentialManagement as u8
    | Permission::BioEnrollment as u8
    | Permission::LargeBlobWrite as u8
    | Permission::AuthenticatorConfiguration as u8
    | Permission::PersistentCredentialManagementReadOnly as u8;

fn validate_requested_permissions<
    C: AuthenticatorCallbacks,
    K: crate::key_provider::CredentialKeyProvider,
>(
    auth: &Authenticator<C, K>,
    requested_permissions: u8,
) -> Result<u8> {
    if requested_permissions == 0 {
        return Err(StatusCode::InvalidParameter);
    }

    // CTAP 2.3 requires undefined permission bits to be ignored when the
    // token's permissions are assigned.
    let permissions = requested_permissions & DEFINED_PERMISSION_MASK;
    let options = &auth.config().options;

    if Permission::CredentialManagement.is_set_in(permissions) && !options.cred_mgmt {
        return Err(StatusCode::UnauthorizedPermission);
    }
    if Permission::BioEnrollment.is_set_in(permissions) && options.bio_enroll != Some(true) {
        return Err(StatusCode::UnauthorizedPermission);
    }
    if Permission::LargeBlobWrite.is_set_in(permissions) && options.large_blobs != Some(true) {
        return Err(StatusCode::UnauthorizedPermission);
    }
    if Permission::AuthenticatorConfiguration.is_set_in(permissions) && !options.authnr_cfg {
        return Err(StatusCode::UnauthorizedPermission);
    }
    if Permission::PersistentCredentialManagementReadOnly.is_set_in(permissions) {
        return Err(StatusCode::UnauthorizedPermission);
    }

    Ok(permissions)
}
'''
assert text.count(old_helper) == 1
text = text.replace(old_helper, new_helper, 1)

legacy_start = text.index("fn handle_get_pin_token<")
legacy_anchor = '''    let protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let pin_hash_enc: Vec<u8> = parser.get_bytes(req_keys::PIN_HASH_ENC)?;

    // Get platform's key agreement key
'''
legacy_replacement = '''    let protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let pin_hash_enc: Vec<u8> = parser.get_bytes(req_keys::PIN_HASH_ENC)?;

    if parser.get_raw(req_keys::PERMISSIONS).is_some()
        || parser.get_raw(req_keys::RP_ID).is_some()
    {
        return Err(StatusCode::InvalidParameter);
    }

    // Get platform's key agreement key
'''
legacy_pos = text.index(legacy_anchor, legacy_start)
text = text[:legacy_pos] + text[legacy_pos:].replace(legacy_anchor, legacy_replacement, 1)

pin_old = '''    let permissions: u8 = parser.get(req_keys::PERMISSIONS)?;
    let rp_id: Option<String> = parser.get_opt(req_keys::RP_ID)?;

    validate_requested_permissions(auth, permissions)?;

    // Get platform's key agreement key
'''
pin_new = '''    let requested_permissions: u8 = parser.get(req_keys::PERMISSIONS)?;
    let rp_id: Option<String> = parser.get_opt(req_keys::RP_ID)?;

    let permissions = validate_requested_permissions(auth, requested_permissions)?;
    if (Permission::MakeCredential.is_set_in(permissions)
        || Permission::GetAssertion.is_set_in(permissions))
        && rp_id.is_none()
    {
        return Err(StatusCode::MissingParameter);
    }

    // Get platform's key agreement key
'''
assert text.count(pin_old) == 1
text = text.replace(pin_old, pin_new, 1)

uv_old = '''    let permissions: u8 = parser
        .get(req_keys::PERMISSIONS)
        .map_err(|_| StatusCode::MissingParameter)?;
    let rp_id: Option<String> = parser.get_opt(req_keys::RP_ID)?;
'''
uv_new = '''    let requested_permissions: u8 = parser
        .get(req_keys::PERMISSIONS)
        .map_err(|_| StatusCode::MissingParameter)?;
    let rp_id: Option<String> = parser.get_opt(req_keys::RP_ID)?;
'''
assert text.count(uv_old) == 1
text = text.replace(uv_old, uv_new, 1)

uv_validate_old = '''    validate_requested_permissions(auth, permissions)?;

    let config = auth.config();
'''
uv_validate_new = '''    let permissions = validate_requested_permissions(auth, requested_permissions)?;
    if (Permission::MakeCredential.is_set_in(permissions)
        || Permission::GetAssertion.is_set_in(permissions))
        && rp_id.is_none()
    {
        return Err(StatusCode::MissingParameter);
    }

    let config = auth.config();
'''
assert text.count(uv_validate_old) == 1
text = text.replace(uv_validate_old, uv_validate_new, 1)

old_test = '''    fn permission_validation_rejects_zero_and_unknown_bits() {
        let auth = create_test_authenticator();

        assert_eq!(
            validate_requested_permissions(&auth, 0),
            Err(StatusCode::InvalidParameter)
        );
        assert_eq!(
            validate_requested_permissions(&auth, 0x40),
            Err(StatusCode::InvalidParameter)
        );
    }
'''
new_test = '''    fn permission_validation_rejects_zero_and_ignores_undefined_bits() {
        let auth = create_test_authenticator();

        assert_eq!(
            validate_requested_permissions(&auth, 0),
            Err(StatusCode::InvalidParameter)
        );
        assert_eq!(validate_requested_permissions(&auth, 0x80), Ok(0));
        assert_eq!(
            validate_requested_permissions(
                &auth,
                Permission::MakeCredential as u8 | 0x80,
            ),
            Ok(Permission::MakeCredential as u8)
        );
        assert_eq!(
            validate_requested_permissions(
                &auth,
                Permission::PersistentCredentialManagementReadOnly as u8,
            ),
            Err(StatusCode::UnauthorizedPermission)
        );
    }
'''
assert text.count(old_test) == 1
text = text.replace(old_test, new_test, 1)

text = text.replace(
    '''            .insert(req_keys::PERMISSIONS, 0x40u8)
''',
    '''            .insert(
                req_keys::PERMISSIONS,
                Permission::PersistentCredentialManagementReadOnly as u8,
            )
''',
)

# Both existing path tests expected InvalidParameter for 0x40; it is a defined
# but unsupported permission, so both must expect UnauthorizedPermission.
text = text.replace(
    '''            handle(&mut auth, &request),
            Err(StatusCode::InvalidParameter)
        );
    }

    #[test]
    fn pin_with_permissions_path_rejects_unsupported_permissions()''',
    '''            handle(&mut auth, &request),
            Err(StatusCode::UnauthorizedPermission)
        );
    }

    #[test]
    fn pin_with_permissions_path_rejects_unsupported_permissions()''',
    1,
)
needle = '''            handle(&mut auth, &request),
            Err(StatusCode::InvalidParameter)
        );
    }
}'''
replacement = '''            handle(&mut auth, &request),
            Err(StatusCode::UnauthorizedPermission)
        );
    }

    #[test]
    fn legacy_get_pin_token_rejects_permissions_and_rp_id() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();

        for (key, value) in [
            (req_keys::PERMISSIONS, crate::cbor::Value::Integer(1.into())),
            (
                req_keys::RP_ID,
                crate::cbor::Value::Text("example.com".to_string()),
            ),
        ] {
            let request = MapBuilder::new()
                .insert(req_keys::SUBCOMMAND, 0x05u8)
                .unwrap()
                .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
                .unwrap()
                .insert_bytes(req_keys::PIN_HASH_ENC, &[0u8; 16])
                .unwrap()
                .insert(key, value)
                .unwrap()
                .build()
                .unwrap();
            assert_eq!(handle(&mut auth, &request), Err(StatusCode::InvalidParameter));
        }
    }

    #[test]
    fn explicit_mc_or_ga_permissions_require_an_rp_id() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();

        for (subcommand, permission) in [
            (0x09u8, Permission::MakeCredential),
            (0x09u8, Permission::GetAssertion),
            (0x06u8, Permission::MakeCredential),
            (0x06u8, Permission::GetAssertion),
        ] {
            let mut builder = MapBuilder::new()
                .insert(req_keys::SUBCOMMAND, subcommand)
                .unwrap()
                .insert(req_keys::PIN_UV_AUTH_PROTOCOL, 1u8)
                .unwrap()
                .insert(req_keys::PERMISSIONS, permission as u8)
                .unwrap();
            if subcommand == 0x09 {
                builder = builder
                    .insert_bytes(req_keys::PIN_HASH_ENC, &[0u8; 16])
                    .unwrap();
            }
            let request = builder.build().unwrap();
            assert_eq!(handle(&mut auth, &request), Err(StatusCode::MissingParameter));
        }
    }
}'''
assert text.count(needle) == 1
text = text.replace(needle, replacement, 1)
client_pin.write_text(text)

pin_token = Path("soft-fido2-ctap/src/pin_token.rs")
pin_text = pin_token.read_text()
old_variant = '''    /// Authenticator configuration permission (0x20)
    ///
    /// Allows authenticatorConfig operations
    AuthenticatorConfiguration = 0x20,
}'''
new_variant = '''    /// Authenticator configuration permission (0x20)
    ///
    /// Allows authenticatorConfig operations
    AuthenticatorConfiguration = 0x20,

    /// Persistent read-only credential management permission (0x40)
    PersistentCredentialManagementReadOnly = 0x40,
}'''
assert pin_text.count(old_variant) == 1
pin_text = pin_text.replace(old_variant, new_variant, 1)
old_assert = '''        assert_eq!(Permission::AuthenticatorConfiguration.to_u8(), 0x20);
'''
new_assert = '''        assert_eq!(Permission::AuthenticatorConfiguration.to_u8(), 0x20);
        assert_eq!(
            Permission::PersistentCredentialManagementReadOnly.to_u8(),
            0x40
        );
'''
assert pin_text.count(old_assert) == 1
pin_text = pin_text.replace(old_assert, new_assert, 1)
pin_token.write_text(pin_text)
