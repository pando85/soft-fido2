//! Credential Management Example
//!
//! This example demonstrates CTAP 2.1 credential management operations:
//! - Getting credential metadata (total count)
//! - Enumerating relying parties
//! - Enumerating credentials for a specific RP
//! - Deleting credentials
//! - Updating user information
//!
//! # Prerequisites
//! - A FIDO2 authenticator with credential management support
//! - PIN configured on the authenticator
//! - Some credentials already registered
//!
//! # Usage
//! ```bash
//! cargo run --example credential_management
//! ```

use soft_fido2::request::Permission;
use soft_fido2::{Client, PinProtocol, PinUvAuthEncapsulation, Result, TransportList};

const PIN: &str = "123456";

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════╗");
    println!("║      Credential Management Example             ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Connect to authenticator
    println!("[1] Looking for authenticators...");
    let list = TransportList::enumerate()?;

    if list.is_empty() {
        eprintln!("❌ No authenticators found!");
        return Ok(());
    }

    println!("    ✓ Found {} authenticator(s)\n", list.len());

    let mut transport = list.get(0).ok_or(soft_fido2::Error::Other)?;
    transport.open()?;
    println!("[2] Connected to authenticator\n");

    // Check authenticator capabilities
    println!("[3] Checking authenticator capabilities...");
    let info_data = Client::authenticator_get_info(&mut transport)?;

    match soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(info_data.as_slice()) {
        Ok(soft_fido2_ctap::cbor::Value::Map(map)) => {
            let has_cred_mgmt = map.iter().any(|(key, value)| {
                matches!(key, soft_fido2_ctap::cbor::Value::Integer(k) if *k == 4)
                    && matches!(value, soft_fido2_ctap::cbor::Value::Map(opts) if opts.iter().any(|(opt_key, opt_val)| {
                        matches!(opt_key, soft_fido2_ctap::cbor::Value::Text(k) if k == "credMgmt")
                            && matches!(opt_val, soft_fido2_ctap::cbor::Value::Bool(true))
                    }))
            });

            if has_cred_mgmt {
                println!("    ✓ Credential management supported");
            } else {
                println!("    ⚠ Credential management NOT supported");
                println!();
                println!("This authenticator does not support credential management.");
                println!("You need a CTAP 2.1 compliant authenticator.");
                return Ok(());
            }
        }
        _ => {
            eprintln!("    ⚠ Failed to parse authenticator info");
        }
    }
    println!();

    // Establish PIN protocol
    println!("[4] Establishing PIN protocol...");
    let protocol = PinProtocol::V2;
    let mut encapsulation = PinUvAuthEncapsulation::new(&mut transport, protocol)?;
    println!("    ✓ PIN protocol V2 established\n");

    // Get PIN token with credential management permission
    println!("[5] Getting PIN token (PIN: {})...", PIN);
    let permissions = Permission::CredentialManagement as u8;
    let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        PIN,
        permissions,
        None, // No specific RP for credential management
    )?;
    println!("    ✓ PIN token obtained with credMgmt permission\n");

    // Create PIN auth object for credential management operations
    let pin_uv_auth =
        soft_fido2::request::PinUvAuth::new(pin_token, soft_fido2::request::PinUvAuthProtocol::V2);

    // Get credentials metadata
    println!("[6] Getting credentials metadata...");
    let metadata_request =
        soft_fido2::request::CredentialManagementRequest::new(Some(pin_uv_auth.clone()));
    match Client::get_credentials_metadata(&mut transport, metadata_request) {
        Ok(metadata) => {
            println!(
                "    ✓ Total credentials: {}",
                metadata.existing_resident_credentials_count
                    + metadata.max_possible_remaining_resident_credentials_count
            );
            println!(
                "    ✓ Existing resident credentials: {}",
                metadata.existing_resident_credentials_count
            );
            println!(
                "    ✓ Maximum resident credentials: {}",
                metadata.max_possible_remaining_resident_credentials_count
            );
        }
        Err(e) => {
            println!("    ⚠ Failed to get metadata: {:?}", e);
        }
    }
    println!();

    // Enumerate relying parties
    println!("[7] Enumerating relying parties...");
    let rps_request =
        soft_fido2::request::CredentialManagementRequest::new(Some(pin_uv_auth.clone()));
    match Client::enumerate_rps(&mut transport, rps_request) {
        Ok(rps) => {
            println!("    ✓ Found {} relying parties:", rps.len());
            for (i, rp) in rps.iter().enumerate() {
                println!(
                    "      {}. {} ({})",
                    i + 1,
                    rp.name.as_deref().unwrap_or("Unknown"),
                    rp.id
                );
            }
            println!();

            // If we have RPs, enumerate credentials for the first one
            if !rps.is_empty() {
                let rp_id = &rps[0].id;
                println!("[8] Enumerating credentials for RP: {}...", rp_id);

                let rp_id_hash = soft_fido2::compute_rp_id_hash(rp_id);
                let creds_request = soft_fido2::request::EnumerateCredentialsRequest::new(
                    Some(pin_uv_auth.clone()),
                    rp_id_hash,
                );

                match Client::enumerate_credentials(&mut transport, creds_request) {
                    Ok(credentials) => {
                        println!("    ✓ Found {} credentials:", credentials.len());
                        for (i, cred) in credentials.iter().enumerate() {
                            println!(
                                "      {}. User: {} (ID: {})",
                                i + 1,
                                cred.user.name.as_deref().unwrap_or("Unknown"),
                                hex::encode(&cred.user.id)
                            );
                        }
                        println!();

                        // If we have credentials, demonstrate deletion (commented out for safety)
                        if !credentials.is_empty() {
                            println!(
                                "[9] Credential deletion example (commented out for safety)..."
                            );
                            println!("    // To delete a credential:");
                            println!(
                                "    // let delete_request = soft_fido2::request::DeleteCredentialRequest::new("
                            );
                            println!("    //     pin_uv_auth.clone(),");
                            println!("    //     credentials[0].id.clone(),");
                            println!("    // );");
                            println!(
                                "    // Client::delete_credential(&mut transport, delete_request)?;"
                            );
                            println!("    ✓ Example shown (not executed)");
                        }
                    }
                    Err(e) => {
                        println!("    ⚠ Failed to enumerate credentials: {:?}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!("    ⚠ Failed to enumerate RPs: {:?}", e);
        }
    }

    // Summary
    println!("╔════════════════════════════════════════════════╗");
    println!("║      Credential Management Demo Complete       ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();
    println!("This example demonstrated:");
    println!("  • Checking credential management support");
    println!("  • Getting PIN token with credMgmt permission");
    println!("  • Retrieving credential metadata");
    println!("  • Enumerating relying parties");
    println!("  • Enumerating credentials for an RP");
    println!("  • Safe credential deletion pattern");
    println!();
    println!("CTAP 2.1 Credential Management Operations:");
    println!("  ✅ getCredsMetadata - Get credential counts");
    println!("  ✅ enumerateRPs - List all relying parties");
    println!("  ✅ enumerateCredentials - List credentials per RP");
    println!("  ✅ deleteCredential - Remove specific credentials");
    println!("  ✅ updateUserInformation - Update user info");

    transport.close();

    Ok(())
}
