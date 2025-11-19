//! Client Example
//!
//! This example demonstrates basic client operations with a FIDO2 authenticator.
//!
//! # Usage
//! ```bash
//! cargo run --example client --features pure-rust
//! ```

use soft_fido2::client::Client;
use soft_fido2::transport::TransportList;

fn main() {
    println!("Keylib Rust Client Example");

    // Enumerate available transports
    println!("Enumerating available transports...");
    let transport_list = match TransportList::enumerate() {
        Ok(list) => list,
        Err(e) => {
            eprintln!("Failed to enumerate transports: {:?}", e);
            return;
        }
    };

    println!("Found {} transport(s)", transport_list.len());

    if transport_list.is_empty() {
        println!("No transports available. Make sure you have FIDO2 devices connected.");
        return;
    }

    // Try to use the first available transport
    let mut transport = match transport_list.get(0) {
        Some(t) => t,
        None => {
            eprintln!("Failed to get transport");
            return;
        }
    };

    println!(
        "Description: {}",
        transport.get_description().unwrap_or("n.a.".to_string())
    );

    // Open the transport
    if let Err(e) = transport.open() {
        eprintln!("Failed to open transport: {:?}", e);
        return;
    }

    println!("Transport opened successfully!");

    // Send authenticatorGetInfo command
    println!("Sending authenticatorGetInfo command...");
    let info_data = match Client::authenticator_get_info(&mut transport) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to get authenticator info: {:?}", e);
            return;
        }
    };

    println!("Received authenticator info: {} bytes", info_data.len());

    // Parse CBOR data
    match soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(info_data.as_slice()) {
        Ok(info) => {
            println!("Parsed authenticator info successfully");

            // Extract and display key information
            if let soft_fido2_ctap::cbor::Value::Map(map) = info {
                for (key, value) in map {
                    if let (soft_fido2_ctap::cbor::Value::Integer(k), v) = (key, value) {
                        match k {
                            1 => println!("  Versions: {:?}", v),
                            2 => println!("  Extensions: {:?}", v),
                            3 => println!("  AAGUID: {:?}", v),
                            4 => {
                                println!("  Options: {:?}", v);
                                // Check for credMgmt support
                                if let soft_fido2_ctap::cbor::Value::Map(opts) = &v {
                                    let has_cred_mgmt = opts.iter().any(|(opt_key, opt_val)| {
                                        matches!(opt_key, soft_fido2_ctap::cbor::Value::Text(k) if k == "credMgmt" || k == "credentialMgmtPreview")
                                            && matches!(opt_val, soft_fido2_ctap::cbor::Value::Bool(true))
                                    });
                                    println!("  Supports credential management: {}", has_cred_mgmt);
                                }
                            }
                            6 => println!("  PIN/UV protocols: {:?}", v),
                            _ => println!("  {:?}: {:?}", k, v),
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to parse CBOR: {:?}", e);
        }
    }

    // Close the transport
    transport.close();
    println!("Transport closed");

    println!("Client example completed successfully!");
}
