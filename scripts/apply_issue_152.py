from pathlib import Path

path = Path("soft-fido2-ctap/src/commands/client_pin.rs")
text = path.read_text()

old_import = """use crate::{
    authenticator::Authenticator,
    callbacks::AuthenticatorCallbacks,
    cbor::{MapBuilder, MapParser},
    status::{Result, StatusCode},
};
"""
new_import = """use crate::{
    authenticator::Authenticator,
    callbacks::AuthenticatorCallbacks,
    cbor::{MapBuilder, MapParser},
    pin_token::Permission,
    status::{Result, StatusCode},
};
"""
assert text.count(old_import) == 1
text = text.replace(old_import, new_import, 1)

response_keys = """mod resp_keys {
    pub const KEY_AGREEMENT: i32 = 0x01;
    pub const PIN_UV_AUTH_TOKEN: i32 = 0x02;
    pub const PIN_RETRIES: i32 = 0x03;
    pub const POWER_CYCLE_STATE: i32 = 0x04;
    pub const UV_RETRIES: i32 = 0x05;
}
"""
helpers = response_keys + """
const DEFAULT_PERMISSION_MASK: u8 =
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
    if Permission::BioEnrollment.is_set_in(permissions)
        && options.bio_enroll != Some(true)
    {
        return Err(StatusCode::UnauthorizedPermission);
    }
    if Permission::LargeBlobWrite.is_set_in(permissions)
        && options.large_blobs != Some(true)
    {
        return Err(StatusCode::UnauthorizedPermission);
    }
    if Permission::AuthenticatorConfiguration.is_set_in(permissions) && !options.authnr_cfg {
        return Err(StatusCode::UnauthorizedPermission);
    }

    Ok(())
}
"""
assert text.count(response_keys) == 1
text = text.replace(response_keys, helpers, 1)

legacy = """    // Get PIN token (CTAP 2.0 uses all permissions)
    let token = auth.get_pin_token_after_verification(0xFF, None)?;
"""
legacy_fixed = """    // The superseded CTAP 2.0 getPinToken command grants only the
    // default makeCredential and getAssertion permissions.
    let token = auth.get_pin_token_after_verification(DEFAULT_PERMISSION_MASK, None)?;
"""
assert text.count(legacy) == 1
text = text.replace(legacy, legacy_fixed, 1)

pin_anchor = """    let permissions: u8 = parser.get(req_keys::PERMISSIONS)?;
    let rp_id: Option<String> = parser.get_opt(req_keys::RP_ID)?;

    // Get platform's key agreement key
"""
pin_replacement = """    let permissions: u8 = parser.get(req_keys::PERMISSIONS)?;
    let rp_id: Option<String> = parser.get_opt(req_keys::RP_ID)?;

    validate_requested_permissions(auth, permissions)?;

    // Get platform's key agreement key
"""
assert text.count(pin_anchor) == 1
text = text.replace(pin_anchor, pin_replacement, 1)

uv_start = text.index("    // Validate permissions (must not be 0)\n", text.index("fn handle_get_pin_uv_auth_token_using_uv_with_permissions"))
uv_end_marker = "    // Check if built-in UV is configured\n"
uv_end = text.index(uv_end_marker, uv_start)
text = (
    text[:uv_start]
    + "    validate_requested_permissions(auth, permissions)?;\n\n"
    + "    let config = auth.config();\n\n"
    + text[uv_end:]
)

new_tests = r'''

    #[test]
    fn legacy_get_pin_token_permissions_are_mc_and_ga_only() {
        assert_eq!(DEFAULT_PERMISSION_MASK, 0x03);

        let mut auth = create_test_authenticator();
        auth.get_pin_token_after_verification(DEFAULT_PERMISSION_MASK, None)
            .unwrap();

        assert!(
            auth.verify_pin_uv_auth_token(Permission::MakeCredential, Some("example.com"))
                .is_ok()
        );
        assert!(
            auth.verify_pin_uv_auth_token(Permission::GetAssertion, Some("example.com"))
                .is_ok()
        );
        assert_eq!(
            auth.verify_pin_uv_auth_token(Permission::CredentialManagement, None),
            Err(StatusCode::UnauthorizedPermission)
        );
        assert_eq!(
            auth.verify_pin_uv_auth_token(Permission::BioEnrollment, None),
            Err(StatusCode::UnauthorizedPermission)
        );
        assert_eq!(
            auth.verify_pin_uv_auth_token(Permission::LargeBlobWrite, None),
            Err(StatusCode::UnauthorizedPermission)
        );
        assert_eq!(
            auth.verify_pin_uv_auth_token(Permission::AuthenticatorConfiguration, None),
            Err(StatusCode::UnauthorizedPermission)
        );
    }

    #[test]
    fn permission_validation_rejects_zero_and_unknown_bits() {
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

    #[test]
    fn permission_validation_enforces_advertised_capabilities() {
        let auth = create_test_authenticator();

        assert!(
            validate_requested_permissions(
                &auth,
                Permission::MakeCredential as u8 | Permission::GetAssertion as u8,
            )
            .is_ok()
        );
        assert_eq!(
            validate_requested_permissions(&auth, Permission::BioEnrollment as u8),
            Err(StatusCode::UnauthorizedPermission)
        );
        assert_eq!(
            validate_requested_permissions(&auth, Permission::LargeBlobWrite as u8),
            Err(StatusCode::UnauthorizedPermission)
        );
        assert_eq!(
            validate_requested_permissions(
                &auth,
                Permission::AuthenticatorConfiguration as u8,
            ),
            Err(StatusCode::UnauthorizedPermission)
        );
    }
'''
last = text.rfind("\n}")
assert last != -1
text = text[:last] + new_tests + text[last:]

path.write_text(text)
