//! PIN Protocol Example
//!
//! This example demonstrates how to use the PIN/UV authentication protocol
//! with a FIDO2 authenticator.
//!
//! It shows:
//! - Establishing PIN protocol connection
//! - Getting PIN retry counter
//! - Retrieving PIN token with permissions
//! - Using PIN token for operations
//!
//! # Prerequisites
//! - A FIDO2 authenticator connected via USB
//! - The authenticator must have a PIN configured
//!
//! # Usage
//! ```bash
//! cargo run --example pin_protocol --features pure-rust
//! ```

use soft_fido2::Result;
use soft_fido2::transport::TransportList;
use soft_fido2::{PinProtocol, PinUvAuthEncapsulation};

const PIN: &str = "123456";

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════╗");
    println!("║        PIN Protocol Usage Example              ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Enumerate transports
    println!("[1] Enumerating authenticators...");
    let list = TransportList::enumerate()?;

    if list.is_empty() {
        eprintln!("❌ No authenticators found!");
        eprintln!("   Make sure you have a FIDO2 device connected.");
        return Ok(());
    }

    println!("    ✓ Found {} authenticator(s)\n", list.len());

    // Open transport
    let mut transport = list.get(0).ok_or(soft_fido2::Error::Other)?;
    transport.open()?;
    println!("[2] Connected to authenticator\n");

    // Establish PIN protocol
    println!("[3] Establishing PIN protocol...");
    let protocol = PinProtocol::V2;
    let mut encapsulation = PinUvAuthEncapsulation::new(&mut transport, protocol)?;
    println!("    ✓ Using PIN protocol V2\n");

    // Note: PIN retries API is not yet implemented
    println!("[4] PIN retry counter feature coming soon...\n");

    // Get PIN token with makeCredential permission
    println!("[5] Getting PIN token (PIN: {})...", PIN);
    let permissions = 0x01; // makeCredential
    let rp_id = Some("example.com");

    match encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        PIN,
        permissions,
        rp_id,
    ) {
        Ok(pin_token) => {
            println!("    ✓ PIN token obtained!");
            println!("    Token: {}", hex::encode(&pin_token[..16]));
            println!("    Permission: makeCredential (0x01)");
            println!("    RP ID: {:?}", rp_id);
        }
        Err(e) => {
            eprintln!("    ✗ Failed to get PIN token: {:?}", e);
            eprintln!();
            eprintln!("Common issues:");
            eprintln!("  - Wrong PIN (check authenticator)");
            eprintln!("  - PIN not set (set PIN first)");
            eprintln!("  - Too many failed attempts (PIN blocked)");
            return Err(e);
        }
    }
    println!();

    // Get PIN token with getAssertion permission
    println!("[6] Getting PIN token with getAssertion permission...");
    let permissions = 0x02; // getAssertion

    match encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        PIN,
        permissions,
        rp_id,
    ) {
        Ok(pin_token) => {
            println!("    ✓ PIN token obtained!");
            println!("    Token: {}", hex::encode(&pin_token[..16]));
            println!("    Permission: getAssertion (0x02)");
        }
        Err(e) => {
            eprintln!("    ✗ Failed to get PIN token: {:?}", e);
        }
    }
    println!();

    // Demonstrate PIN/UV auth parameter generation
    println!("[7] Generating PIN/UV auth parameter...");
    let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        PIN,
        0x01,
        rp_id,
    )?;

    // Simulate a client data hash (32 bytes)
    let client_data_hash = [0u8; 32];
    let pin_uv_auth_param = encapsulation.authenticate(&client_data_hash, &pin_token)?;

    println!("    ✓ PIN/UV auth parameter generated");
    println!("    Param: {}", hex::encode(&pin_uv_auth_param));
    println!();

    // Success summary
    println!("╔════════════════════════════════════════════════╗");
    println!("║         ✓ PIN Protocol Demo Complete          ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();
    println!("Summary:");
    println!("  • Connected to authenticator");
    println!("  • Established PIN protocol V2");
    println!("  • Retrieved PIN tokens with different permissions");
    println!("  • Generated PIN/UV auth parameters");
    println!();
    println!("Available Permissions:");
    println!("  0x01 - makeCredential");
    println!("  0x02 - getAssertion");
    println!("  0x04 - credentialManagement");
    println!("  0x08 - biometricEnrollment");
    println!("  0x10 - largeBlobs");
    println!("  0x20 - authenticatorConfig");

    transport.close();

    Ok(())
}
