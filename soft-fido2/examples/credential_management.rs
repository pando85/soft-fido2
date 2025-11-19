//! Credential Management Example
//!
//! This example demonstrates CTAP 2.1 credential management operations:
//! - Getting credential metadata (total count)
//! - Enumerating relying parties
//! - Enumerating credentials for a specific RP
//! - Deleting credentials
//!
//! **Note**: Full credential management API is still being developed for pure-rust.
//! This example shows the basic pattern using direct CBOR commands.
//!
//! # Prerequisites
//! - A FIDO2 authenticator with credential management support
//! - PIN configured on the authenticator
//! - Some credentials already registered
//!
//! # Usage
//! ```bash
//! cargo run --example credential_management --features pure-rust
//! ```

use soft_fido2::Result;
use soft_fido2::client::Client;
use soft_fido2::transport::TransportList;
use soft_fido2::{PinProtocol, PinUvAuthEncapsulation};

use soft_fido2_ctap::cbor::Value;

const PIN: &str = "123456";

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════╗");
    println!("║      Credential Management Example             ║");
    println!("╚════════════════════════════════════════════════╝\n");

    println!("⚠  Note: This example demonstrates the basic pattern.");
    println!("   Full credential management API is under development.\n");

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

    match soft_fido2_ctap::cbor::decode::<Value>(info_data.as_slice()) {
        Ok(Value::Map(map)) => {
            for (key, value) in &map {
                if let (Value::Integer(k), Value::Map(opts)) = (key, value)
                    && k == &4.into()
                {
                    // Options
                    let has_cred_mgmt = opts.iter().any(|(opt_key, opt_val)| {
                        matches!(opt_key, Value::Text(k) if k == "credMgmt")
                            && matches!(opt_val, Value::Bool(true))
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
    let permissions = 0x04; // credentialManagement
    let _pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        PIN,
        permissions,
        None, // No specific RP for credential management
    )?;
    println!("    ✓ PIN token obtained with credMgmt permission\n");

    // Get credentials metadata
    println!("[6] Getting credentials metadata...");
    println!("    (This would show total credential count)");
    println!("    ⚠ Full API implementation pending\n");

    // Enumerate RPs
    println!("[7] Enumerating relying parties...");
    println!("    (This would list all RPs with credentials)");
    println!("    ⚠ Full API implementation pending\n");

    // Summary
    println!("╔════════════════════════════════════════════════╗");
    println!("║      Credential Management Pattern Shown       ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();
    println!("This example demonstrated:");
    println!("  • Checking credential management support");
    println!("  • Getting PIN token with credMgmt permission (0x04)");
    println!();
    println!("CTAP 2.1 Credential Management Operations:");
    println!("  0x01 - getCredsMetadata (total count)");
    println!("  0x02 - enumerateRPsBegin");
    println!("  0x03 - enumerateRPsGetNextRP");
    println!("  0x04 - enumerateCredentialsBegin");
    println!("  0x05 - enumerateCredentialsGetNextCredential");
    println!("  0x06 - deleteCredential");
    println!("  0x07 - updateUserInformation");
    println!();
    println!("💡 Full implementation coming soon!");

    transport.close();

    Ok(())
}
