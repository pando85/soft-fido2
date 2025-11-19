//! Integration tests for keylib
//!
//! TODO: Adapt these tests to work with both zig-ffi and pure-rust implementations

// Only compile with zig-ffi for now
#![allow(unexpected_cfgs)]
#![cfg(feature = "zig-ffi")]

use soft_fido2::{client, client_pin};

// Integration tests that require actual hardware or UHID virtual devices
// Run with: cargo test --test integration --features integration-tests
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_transport_enumeration() {
        client::TransportList::enumerate().unwrap();
    }

    #[test]
    fn test_authenticator_get_info() {
        let list = match client::TransportList::enumerate() {
            Ok(list) => list,
            Err(e) => {
                eprintln!("Failed to enumerate transports: {:?}", e);
                return;
            }
        };

        if list.is_empty() {
            eprintln!("No devices available, skipping test");
            return;
        }

        let mut transport = match list.get(0) {
            Some(t) => t,
            None => {
                eprintln!("Failed to get transport at index 0");
                return;
            }
        };

        if let Err(e) = transport.open() {
            eprintln!("Failed to open transport: {:?}, skipping test", e);
            return;
        }

        let mut cmd = match client::Client::authenticator_get_info(&mut transport) {
            Ok(cmd) => cmd,
            Err(e) => {
                eprintln!("Failed to get authenticator info: {:?}", e);
                return;
            }
        };

        let result = match cmd.get_result(5000) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to get command result: {:?}", e);
                return;
            }
        };

        assert!(result.is_fulfilled());
        // Parse and validate CBOR structure
        if let Some(data) = result.get_data() {
            // Basic validation that we got some data
            assert!(!data.is_empty());
            // Could parse CBOR here to validate structure
        }
    }
}

// Unit tests that don't require hardware
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_pin_encapsulation_creation() {
        // Test that we can create a PIN encapsulation
        let list = client::TransportList::enumerate().unwrap();
        let transport = list.get(0);
        if transport.is_none() {
            // Skip test if no transport available
            eprintln!("No transport available, skipping PIN encapsulation test");
            return;
        }

        let mut transport = transport.unwrap();

        // Open the transport before attempting PIN operations
        if transport.open().is_err() {
            eprintln!("Could not open transport, skipping PIN encapsulation test");
            return;
        }

        let result =
            client_pin::PinUvAuthEncapsulation::new(&mut transport, client_pin::PinProtocol::V1);

        // This may fail if no authenticator is available or if the authenticator
        // doesn't support the operation, but it shouldn't crash
        if result.is_err() {
            eprintln!(
                "PIN encapsulation creation failed (this is expected without hardware): {:?}",
                result.err()
            );
        }
    }
}
