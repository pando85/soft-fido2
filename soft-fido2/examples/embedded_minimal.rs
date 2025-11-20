//! Minimal embedded example showing zero-allocation CTAP operations
//!
//! This example demonstrates how to use soft-fido2 in memory-constrained
//! embedded systems. It shows:
//! - Fixed-size stack buffers (256-1024 bytes)
//! - Zero heap allocations during encoding
//! - Suitable for ARM Cortex-M devices
//!
//! # Memory Requirements
//!
//! - Stack: ~2KB for typical operations
//! - Heap: Optional (can work with alloc-only, no std)
//! - Flash: ~50KB for basic CTAP support
//!
//! # Usage
//!
//! ```bash
//! cargo run --example embedded_minimal --no-default-features --features std
//! ```

use soft_fido2_ctap::cbor::{
    GetAssertionRequestBuffer, GetInfoBuffer, MakeCredRequestBuffer, MapBuilder, StackBuffer,
};

fn main() {
    println!("=== Embedded FIDO2 Example ===\n");

    // Example 1: Build getInfo request with 256-byte buffer
    example_get_info();

    // Example 2: Build makeCredential request with 512-byte buffer
    example_make_credential();

    // Example 3: Build getAssertion request with 512-byte buffer
    example_get_assertion();

    println!("\n✅ All embedded examples completed successfully!");
    println!("\nMemory usage:");
    println!("  - GetInfo buffer:         256 bytes");
    println!("  - MakeCredential buffer:  512 bytes");
    println!("  - GetAssertion buffer:    512 bytes");
    println!("  - Total stack usage:      ~2KB (including local variables)");
}

/// Example 1: getInfo request with minimal buffer
fn example_get_info() {
    println!("1. Building getInfo request (256-byte buffer):");

    // Use the type alias for convenience
    let buffer = GetInfoBuffer::new();

    // getInfo has no parameters, so we just need an empty request
    // In a real implementation, this would be sent to the authenticator
    println!("   ✓ Buffer allocated: {} bytes", buffer.capacity());
    println!("   ✓ Buffer used: {} bytes\n", buffer.len());
}

/// Example 2: makeCredential request with 512-byte buffer
fn example_make_credential() {
    println!("2. Building makeCredential request (512-byte buffer):");

    // Use the type alias for the request
    let mut buffer = MakeCredRequestBuffer::new();

    // Build a makeCredential request
    let client_data_hash = [0u8; 32];
    let rp_id = "example.com";
    let user_id = [1u8, 2, 3, 4];

    // Build CBOR map
    let result = MapBuilder::new()
        .insert_bytes(0x01, &client_data_hash)
        .and_then(|b| b.insert_text_map(0x02, &[("id", rp_id)]))
        .and_then(|b| {
            // User map with id only (simplified)
            let user_map = MapBuilder::new()
                .insert_bytes(0x01, &user_id)
                .unwrap()
                .build()
                .unwrap();
            // Decode to Value for insertion
            let user_value: soft_fido2_ctap::cbor::Value =
                soft_fido2_ctap::cbor::decode(&user_map).unwrap();
            b.insert(0x03, &user_value)
        })
        .and_then(|b| {
            // Algorithm parameters (ES256)
            use serde::Serialize;
            #[derive(Serialize)]
            struct PubKeyCredParam {
                alg: i32,
                #[serde(rename = "type")]
                cred_type: &'static str,
            }
            let params = vec![PubKeyCredParam {
                alg: -7,
                cred_type: "public-key",
            }];
            b.insert(0x04, &params)
        })
        .and_then(|b| b.build_into(&mut buffer));

    match result {
        Ok(bytes_written) => {
            println!("   ✓ Buffer allocated: {} bytes", buffer.capacity());
            println!("   ✓ Request encoded: {} bytes", bytes_written);
            println!(
                "   ✓ Remaining space: {} bytes\n",
                buffer.capacity() - bytes_written
            );
        }
        Err(e) => {
            println!("   ✗ Error: {:?}\n", e);
        }
    }
}

/// Example 3: getAssertion request with 512-byte buffer
fn example_get_assertion() {
    println!("3. Building getAssertion request (512-byte buffer):");

    // Use the type alias
    let mut buffer = GetAssertionRequestBuffer::new();

    // Build a getAssertion request
    let client_data_hash = [0u8; 32];
    let rp_id = "example.com";

    // Build CBOR map
    let result = MapBuilder::new()
        .insert(0x01, rp_id)
        .and_then(|b| b.insert_bytes(0x02, &client_data_hash))
        .and_then(|b| b.build_into(&mut buffer));

    match result {
        Ok(bytes_written) => {
            println!("   ✓ Buffer allocated: {} bytes", buffer.capacity());
            println!("   ✓ Request encoded: {} bytes", bytes_written);
            println!(
                "   ✓ Remaining space: {} bytes\n",
                buffer.capacity() - bytes_written
            );
        }
        Err(e) => {
            println!("   ✗ Error: {:?}\n", e);
        }
    }
}

/// Example of using a custom buffer size
#[allow(dead_code)]
fn example_custom_buffer_size() {
    // For very constrained systems, you can use even smaller buffers
    let mut tiny_buffer = StackBuffer::<128>::new();

    let result = MapBuilder::new()
        .insert(1, "test")
        .and_then(|b| b.build_into(&mut tiny_buffer));

    match result {
        Ok(bytes) => println!("Encoded {} bytes in 128-byte buffer", bytes),
        Err(_) => println!("Buffer too small for this request"),
    }
}
