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
# required by an explicit makeCredential permission and allow every request to
# reach the PIN hash comparison, including the post-restart request.
wrong_start = text.index("    // Send WRONG PIN hash")
wrong_end = text.index("    // Should fail with PIN invalid", wrong_start)
wrong_segment = text[wrong_start:wrong_end]
assert wrong_segment.count("        None,\n") == 1
wrong_segment = wrong_segment.replace(
    "        None,\n", '        Some("example.com"),\n', 1
)
text = text[:wrong_start] + wrong_segment + text[wrong_end:]

correct_start = text.index("    // Send correct PIN hash")
correct_end = text.index("    let mut ctap_request", correct_start)
correct_segment = text[correct_start:correct_end]
assert correct_segment.count("        None,\n") == 1
correct_segment = correct_segment.replace(
    "        None,\n", '        Some("example.com"),\n', 1
)
text = text[:correct_start] + correct_segment + text[correct_end:]

loaded_start = text.index(
    "    // Verify we can authenticate with the loaded PIN by trying to get a PIN token"
)
loaded_end = text.index(
    "    let mut ctap_request = vec![0x06];",
    text.index(
        "    let get_pin_token_cbor = build_get_pin_uv_auth_token_using_pin_with_permissions_request(",
        loaded_start,
    ),
)
loaded_segment = text[loaded_start:loaded_end]
assert loaded_segment.count("        None,\n") == 1
loaded_segment = loaded_segment.replace(
    "        None,\n", '        Some("example.com"),\n', 1
)
text = text[:loaded_start] + loaded_segment + text[loaded_end:]

path.write_text(text)
