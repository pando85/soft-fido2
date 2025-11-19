//! Complete WebAuthn Flow Example
//!
//! This example demonstrates a full WebAuthn registration and authentication flow:
//! 1. Register a new credential (makeCredential)
//! 2. Authenticate using the registered credential (getAssertion)
//!
//! # Prerequisites
//! - A FIDO2 authenticator connected (physical device or virtual)
//! - Authenticator configured with PIN "123456"
//!
//! # Usage
//! ```bash
//! cargo run --example webauthn_flow --features pure-rust
//! ```

use base64::Engine;
use sha2::{Digest, Sha256};
use soft_fido2::client::Client;
use soft_fido2::transport::TransportList;
use soft_fido2::{
    ClientDataHash, GetAssertionRequest, MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol,
    RelyingParty, Result, User,
};
use soft_fido2::{PinProtocol, PinUvAuthEncapsulation};

const PIN: &str = "123456";
const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════╗");
    println!("║   Complete WebAuthn Registration & Auth Flow   ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // ============================================================
    // PHASE 1: REGISTRATION (makeCredential)
    // ============================================================
    println!("📱 [1/2] REGISTRATION PHASE");
    println!("{}", "═".repeat(48));
    println!();

    // Connect to authenticator
    println!("[1.1] Looking for FIDO2 authenticators...");
    let list = TransportList::enumerate()?;

    if list.is_empty() {
        eprintln!("❌ No FIDO2 authenticators found!");
        eprintln!("   Make sure you have a compatible device connected.");
        return Ok(());
    }

    println!("      ✓ Found {} authenticator(s)", list.len());

    let mut transport = list.get(0).ok_or(soft_fido2::Error::Other)?;
    transport.open()?;
    println!("      ✓ Connected to authenticator\n");

    // Establish PIN protocol
    println!("[1.2] Establishing PIN protocol...");
    let protocol = PinProtocol::V2;
    let mut encapsulation = match PinUvAuthEncapsulation::new(&mut transport, protocol) {
        Ok(enc) => {
            println!("      ✓ PIN protocol V2 established");
            println!("      [DEBUG] Key agreement completed successfully");
            enc
        }
        Err(e) => {
            eprintln!("      ✗ Failed to establish PIN protocol: {:?}", e);
            eprintln!("      [DEBUG] Error details: {:?}", e);
            eprintln!("      [DEBUG] Possible causes:");
            eprintln!("        - Authenticator doesn't support PIN protocol V2");
            eprintln!("        - Communication error with authenticator");
            return Err(e);
        }
    };
    println!();

    // Get PIN token for makeCredential
    println!("[1.3] Getting PIN token (PIN: {})...", PIN);
    println!("      [DEBUG] Requesting permissions: 0x01 (makeCredential)");
    println!("      [DEBUG] RP ID: {}", RP_ID);
    let permissions = 0x01; // makeCredential
    let pin_token = match encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        PIN,
        permissions,
        Some(RP_ID),
    ) {
        Ok(token) => {
            println!("      ✓ PIN token obtained ({} bytes)", token.len());
            println!(
                "      [DEBUG] PIN token (first 8 bytes): {:02x?}",
                &token[..8.min(token.len())]
            );
            token
        }
        Err(e) => {
            eprintln!("      ✗ Failed to get PIN token: {:?}", e);
            eprintln!("      [DEBUG] Error details: {:?}", e);
            eprintln!("      [DEBUG] Common causes:");
            eprintln!("        - Incorrect PIN (expected: {})", PIN);
            eprintln!("        - PIN not set on authenticator");
            eprintln!("        - Authenticator returned CTAP error");
            eprintln!("        - Permission/RP ID mismatch");
            return Err(e);
        }
    };
    println!();

    // Prepare registration request
    println!("[1.4] Preparing registration request...");
    let challenge = b"random-registration-challenge-12345";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");

    // Relying party information
    let rp = RelyingParty {
        id: RP_ID.to_string(),
        name: Some("Example Corporation".to_string()),
    };

    // User information
    let user = User {
        id: vec![1, 2, 3, 4], // User ID (should be unique per user)
        name: Some("alice@example.com".to_string()),
        display_name: Some("Alice".to_string()),
    };

    println!("      RP: {}", rp.id);
    println!(
        "      User: {}",
        user.name.as_deref().unwrap_or("(unnamed)")
    );

    // Compute PIN/UV auth parameter
    let pin_uv_auth_param = encapsulation.authenticate(client_data_hash.as_slice(), &pin_token)?;
    let pin_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);
    println!("      ✓ Auth parameter computed\n");

    // Create credential using the new builder API
    println!("[1.5] Calling authenticatorMakeCredential...");
    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_pin_uv_auth(pin_auth)
        .with_resident_key(true);

    let attestation = Client::make_credential(&mut transport, request)?;
    println!("      ✓ Credential created ({} bytes)\n", attestation.len());

    // ============================================================
    // PHASE 2: AUTHENTICATION (getAssertion)
    // ============================================================
    println!("🔐 [2/2] AUTHENTICATION PHASE");
    println!("{}", "═".repeat(48));
    println!();

    // Reconnect to authenticator (in real scenario, this would be a new session)
    println!("[2.1] Re-establishing connection...");
    let mut encapsulation = PinUvAuthEncapsulation::new(&mut transport, protocol)?;
    println!("      ✓ Connection established\n");

    // Get PIN token for getAssertion
    println!("[2.2] Getting PIN token for authentication...");
    let permissions = 0x02; // getAssertion
    let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        PIN,
        permissions,
        Some(RP_ID),
    )?;
    println!("      ✓ PIN token obtained\n");

    // Prepare authentication request
    println!("[2.3] Preparing authentication request...");
    let challenge = b"random-authentication-challenge-67890";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.get");

    let pin_uv_auth_param = encapsulation.authenticate(client_data_hash.as_slice(), &pin_token)?;
    let pin_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);
    println!("      ✓ Auth parameter computed\n");

    // Get assertion using the new builder API
    println!("[2.4] Calling authenticatorGetAssertion...");
    let request = GetAssertionRequest::new(client_data_hash, RP_ID).with_pin_uv_auth(pin_auth);

    let assertion = Client::get_assertion(&mut transport, request)?;
    println!("      ✓ Assertion obtained ({} bytes)\n", assertion.len());

    // Success!
    println!("╔════════════════════════════════════════════════╗");
    println!("║             ✓ Flow Completed Successfully      ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();
    println!("Summary:");
    println!("  • Registered new credential for alice@example.com");
    println!("  • Successfully authenticated using the credential");
    println!("  • Both operations used PIN protocol V2");

    Ok(())
}

/// Compute clientDataHash from a challenge
fn compute_client_data_hash(challenge: &[u8], origin: &str, ceremony_type: &str) -> ClientDataHash {
    // In a real WebAuthn implementation, this would be:
    // SHA-256(JSON.stringify({type, challenge, origin}))
    let client_data_json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
        ceremony_type,
        base64::prelude::BASE64_STANDARD.encode(challenge),
        origin
    );

    let hash = Sha256::digest(client_data_json.as_bytes());
    ClientDataHash::from_slice(&hash).expect("Valid 32-byte hash")
}
