from pathlib import Path

path = Path("soft-fido2/tests/authenticator_crate_compat_test.rs")
text = path.read_text()

old_initial_token = '''    // Get PIN token with both makeCredential and credentialManagement permissions
    // Don't specify rp_id to make the token valid for all RPs
    let permissions = 0x01 | 0x04; // makeCredential + credentialManagement
    let rp_id = None;
    let get_pin_token_cbor = build_get_pin_uv_auth_token_using_pin_with_permissions_request(
        2,
        &platform_cose_key_bytes,
        &pin_hash_enc,
        permissions,
        rp_id,
    );
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_pin_token_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getPinUvAuthTokenUsingPinWithPermissions failed");

    let pin_token_enc = extract_pin_token(&response).expect("Failed to extract PIN token");
    let mut pin_token = v2::decrypt(&enc_key, &pin_token_enc).expect("Failed to decrypt PIN token");

    eprintln!("[Test] ✓ Got PIN token\\n");

    let mut credential_ids = Vec::new();
'''
new_initial_token = '''    let mut credential_ids = Vec::new();
'''
assert text.count(old_initial_token) == 1
text = text.replace(old_initial_token, new_initial_token, 1)

old_loop_token = '''        // Per FIDO2 spec, PIN token permissions are cleared after each makeCredential
        // Get a new PIN token for each credential
        if idx > 0 {
            let permissions = 0x01; // makeCredential
            let rp_id_param = None; // No RP ID restriction for multiple RPs
            let get_pin_token_cbor = build_get_pin_uv_auth_token_using_pin_with_permissions_request(
                2,
                &platform_cose_key_bytes,
                &pin_hash_enc,
                permissions,
                rp_id_param,
            );
            let mut ctap_request = vec![0x06];
            ctap_request.extend_from_slice(&get_pin_token_cbor);

            let mut response = Vec::new();
            auth.handle(&ctap_request, &mut response)
                .expect("getPinUvAuthTokenUsingPinWithPermissions failed");

            let pin_token_enc = extract_pin_token(&response).expect("Failed to extract PIN token");
            pin_token = v2::decrypt(&enc_key, &pin_token_enc).expect("Failed to decrypt PIN token");
        }
'''
new_loop_token = '''        // Explicit makeCredential permission tokens are scoped to the RP ID.
        // Get a fresh token for every registration because makeCredential clears
        // non-large-blob permissions after use.
        let permissions = 0x01; // makeCredential
        let get_pin_token_cbor = build_get_pin_uv_auth_token_using_pin_with_permissions_request(
            2,
            &platform_cose_key_bytes,
            &pin_hash_enc,
            permissions,
            Some(rp_id),
        );
        let mut ctap_request = vec![0x06];
        ctap_request.extend_from_slice(&get_pin_token_cbor);

        let mut response = Vec::new();
        auth.handle(&ctap_request, &mut response)
            .expect("getPinUvAuthTokenUsingPinWithPermissions failed");

        let pin_token_enc = extract_pin_token(&response).expect("Failed to extract PIN token");
        let pin_token =
            v2::decrypt(&enc_key, &pin_token_enc).expect("Failed to decrypt PIN token");
'''
assert text.count(old_loop_token) == 1
text = text.replace(old_loop_token, new_loop_token, 1)

# The PIN-persistence test is verifying retry behavior, so provide the RP ID
# required by an explicit makeCredential permission and allow the request to
# reach the PIN hash comparison.
old_wrong = '''        permissions,
        None,
    );
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_pin_token_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getPinUvAuthToken call failed");

    // Should fail with PIN invalid
'''
new_wrong = '''        permissions,
        Some("example.com"),
    );
    let mut ctap_request = vec![0x06];
    ctap_request.extend_from_slice(&get_pin_token_cbor);

    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)
        .expect("getPinUvAuthToken call failed");

    // Should fail with PIN invalid
'''
assert text.count(old_wrong) == 1
text = text.replace(old_wrong, new_wrong, 1)

old_correct = '''        &correct_pin_hash_enc,
        permissions,
        None,
    );
'''
new_correct = '''        &correct_pin_hash_enc,
        permissions,
        Some("example.com"),
    );
'''
assert text.count(old_correct) == 1
text = text.replace(old_correct, new_correct, 1)

path.write_text(text)
