//! Transport Layer End-to-End Test
//!
//! This test validates the complete transport stack by running an authenticator
//! via UHID and connecting to it through the Client API.
//!
//! # Architecture
//!
//! ```text
//! [Test] → [Client] → [USB HID Transport] → [UHID Device] → [CTAP HID Handler] → [Authenticator]
//! ```
//!
//! This closely simulates how passless works and should catch issues like:
//! - CBOR encoding/decoding problems
//! - Transport-level protocol issues
//! - Missing required parameters
//! - Response format problems
//!
//! # Requirements
//!
//! - Linux with UHID support
//! - User must have UHID permissions
//!
//! Run with: cargo test --test transport_e2e_test -- --ignored

#![cfg(all(target_os = "linux", feature = "std"))]

mod common;

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Client,
    GetAssertionRequest, MakeCredentialRequest, RelyingParty, TransportList, User,
};

use common::VerboseTestCallbacks;
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use soft_fido2_transport::{CommandHandler, CtapHidHandler, Packet, UhidDevice};

const TEST_RP_ID: &str = "transport-test.example.com";
const TEST_ORIGIN: &str = "https://transport-test.example.com";

/// Helper to create client data hash for registration
fn make_client_data_hash_for_registration(challenge: &[u8]) -> [u8; 32] {
    use base64::Engine;
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);

    let client_data = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        challenge_b64, TEST_ORIGIN
    );

    let mut hasher = Sha256::new();
    hasher.update(client_data.as_bytes());
    hasher.finalize().into()
}

/// Helper to create client data hash for authentication
fn make_client_data_hash_for_authentication(challenge: &[u8]) -> [u8; 32] {
    use base64::Engine;
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);

    let client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
        challenge_b64, TEST_ORIGIN
    );

    let mut hasher = Sha256::new();
    hasher.update(client_data.as_bytes());
    hasher.finalize().into()
}

/// Wrapper that implements CommandHandler for the high-level Authenticator
struct AuthenticatorHandler<C: AuthenticatorCallbacks> {
    authenticator: Mutex<Authenticator<C>>,
}

impl<C: AuthenticatorCallbacks> AuthenticatorHandler<C> {
    fn new(authenticator: Authenticator<C>) -> Self {
        Self {
            authenticator: Mutex::new(authenticator),
        }
    }
}

impl<C: AuthenticatorCallbacks> CommandHandler for AuthenticatorHandler<C> {
    fn handle_command(
        &mut self,
        cmd: soft_fido2_transport::Cmd,
        data: &[u8],
    ) -> soft_fido2_transport::Result<Vec<u8>> {
        // Only handle CBOR commands (CTAP2)
        if cmd != soft_fido2_transport::Cmd::Cbor {
            return Err(soft_fido2_transport::Error::InvalidCommand);
        }

        let mut auth = self.authenticator.lock().map_err(|_| {
            soft_fido2_transport::Error::Other("Failed to lock authenticator".to_string())
        })?;

        let mut response = Vec::new();
        auth.handle(data, &mut response)
            .map_err(|e| soft_fido2_transport::Error::Other(format!("Command failed: {:?}", e)))?;

        Ok(response)
    }
}

/// Helper struct to manage authenticator in a background thread
struct AuthenticatorRunner<C: AuthenticatorCallbacks> {
    _device: Arc<Mutex<UhidDevice>>,
    _handler: Arc<Mutex<CtapHidHandler<AuthenticatorHandler<C>>>>,
    running: Arc<Mutex<bool>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl<C: AuthenticatorCallbacks + 'static> AuthenticatorRunner<C> {
    fn start(authenticator: Authenticator<C>) -> Result<Self, Box<dyn std::error::Error>> {
        eprintln!("\n[Runner] Creating UHID device...");
        let device = UhidDevice::create_fido_device()?;
        let device = Arc::new(Mutex::new(device));

        eprintln!("[Runner] Creating CTAP HID handler...");
        let auth_handler = AuthenticatorHandler::new(authenticator);
        let handler = CtapHidHandler::new(auth_handler);
        let handler = Arc::new(Mutex::new(handler));

        let running = Arc::new(Mutex::new(true));

        // Spawn authenticator thread
        let device_clone = Arc::clone(&device);
        let handler_clone = Arc::clone(&handler);
        let running_clone = Arc::clone(&running);

        let handle = thread::spawn(move || {
            eprintln!("[Runner] Authenticator thread started");
            let mut buffer = [0u8; 64];

            while *running_clone.lock().unwrap() {
                let device = device_clone.lock().unwrap();
                let bytes_read = match device.read_packet(&mut buffer) {
                    Ok(Some(n)) => n,
                    Ok(None) => {
                        drop(device);
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => {
                        eprintln!("[Runner] Read error: {:?}", e);
                        drop(device);
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };

                if bytes_read == 0 {
                    drop(device);
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }

                eprintln!("[Runner] Received {} bytes", bytes_read);
                let packet = Packet::from_bytes(buffer);

                // Process through CTAP HID handler
                let mut handler = handler_clone.lock().unwrap();
                let response_packets = match handler.process_packet(packet) {
                    Ok(packets) => packets,
                    Err(e) => {
                        eprintln!("[Runner] Process error: {:?}", e);
                        drop(handler);
                        drop(device);
                        continue;
                    }
                };
                drop(handler);

                // Write response packets
                for response_packet in response_packets {
                    if let Err(e) = device.write_packet(response_packet.as_bytes()) {
                        eprintln!("[Runner] Write error: {:?}", e);
                    }
                }
                drop(device);
            }

            eprintln!("[Runner] Authenticator thread stopped");
        });

        Ok(Self {
            _device: device,
            _handler: handler,
            running,
            thread_handle: Some(handle),
        })
    }

    fn stop(mut self) {
        eprintln!("\n[Runner] Stopping authenticator...");
        *self.running.lock().unwrap() = false;
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
        eprintln!("[Runner] Stopped");
    }
}

#[test]
#[ignore]
#[serial]
fn test_transport_registration_and_authentication() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║  Transport E2E: Registration + Authentication ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    // Create authenticator
    eprintln!("[Test] Creating authenticator...");
    let callbacks = VerboseTestCallbacks::new();
    let config = AuthenticatorConfig {
        aaguid: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ],
        options: Some(AuthenticatorOptions {
            rk: true,
            up: true,
            uv: Some(false),
            plat: true,
            client_pin: Some(false),
            pin_uv_auth_token: Some(false),
            cred_mgmt: Some(true),
            bio_enroll: None,
            large_blobs: None,
            ep: None,
            always_uv: Some(false),
            make_cred_uv_not_required: None,
        }),
        ..Default::default()
    };

    let authenticator = Authenticator::with_config(callbacks, config)?;

    // Start authenticator in background
    let runner = AuthenticatorRunner::start(authenticator)?;

    // Give UHID device time to enumerate
    eprintln!("[Test] Waiting for device to be ready...");
    thread::sleep(Duration::from_secs(1));

    // Enumerate transports
    eprintln!("[Test] Enumerating transports...");
    let list = TransportList::enumerate()?;

    if list.is_empty() {
        eprintln!("[Test] ⚠️  No transports found, skipping test");
        runner.stop();
        return Ok(());
    }

    eprintln!("[Test] Found {} transport(s)", list.len());
    let mut transport = list.get(0).expect("Failed to get transport");
    transport.open()?;

    // ========================================
    // PHASE 1: REGISTRATION
    // ========================================
    eprintln!("\n[Test] ═══ REGISTRATION ═══");

    let challenge: [u8; 32] = rand::random();
    let client_data_hash = make_client_data_hash_for_registration(&challenge);

    let rp = RelyingParty {
        id: TEST_RP_ID.to_string(),
        name: Some("Transport Test RP".to_string()),
    };

    let user = User {
        id: vec![1, 2, 3, 4],
        name: Some("user@transport-test.example.com".to_string()),
        display_name: Some("Transport Test User".to_string()),
    };

    let request = MakeCredentialRequest::new(
        soft_fido2::request::ClientDataHash::new(client_data_hash),
        rp,
        user,
    );

    eprintln!("[Test] Sending makeCredential...");
    let attestation = Client::make_credential(&mut transport, request)?;

    eprintln!(
        "[Test] ✓ Received attestation ({} bytes)",
        attestation.len()
    );
    if attestation.len() <= 10 {
        eprintln!("[Test] ⚠️  Response bytes: {:02x?}", attestation);
        if attestation.len() == 1 {
            eprintln!("[Test] ⚠️  Error code: 0x{:02x}", attestation[0]);
        }
    }
    assert!(
        attestation.len() > 10,
        "Attestation response too short (got {} bytes)",
        attestation.len()
    );

    // Parse attestation to verify it's valid CBOR
    // First byte is status code (0x00 = success)
    assert_eq!(
        attestation[0], 0x00,
        "Registration failed with status: 0x{:02x}",
        attestation[0]
    );

    match ciborium::from_reader::<ciborium::value::Value, _>(&attestation[1..]) {
        Ok(ciborium::value::Value::Map(map)) => {
            eprintln!("[Test] ✓ Valid CBOR map with {} fields", map.len());
        }
        Ok(_) => panic!("Attestation should be a CBOR map"),
        Err(e) => panic!("Failed to parse attestation CBOR: {}", e),
    }

    // ========================================
    // PHASE 2: AUTHENTICATION
    // ========================================
    eprintln!("\n[Test] ═══ AUTHENTICATION ═══");

    let challenge: [u8; 32] = rand::random();
    let client_data_hash = make_client_data_hash_for_authentication(&challenge);

    let request = GetAssertionRequest::new(
        soft_fido2::request::ClientDataHash::new(client_data_hash),
        TEST_RP_ID,
    );

    eprintln!("[Test] Sending getAssertion...");
    let assertion = Client::get_assertion(&mut transport, request)?;

    eprintln!("[Test] ✓ Received assertion ({} bytes)", assertion.len());
    assert!(
        assertion.len() > 10,
        "Assertion response too short (got {} bytes)",
        assertion.len()
    );

    // Parse assertion to verify it's valid CBOR
    // First byte is status code (0x00 = success)
    assert_eq!(
        assertion[0], 0x00,
        "Authentication failed with status: 0x{:02x}",
        assertion[0]
    );

    match ciborium::from_reader::<ciborium::value::Value, _>(&assertion[1..]) {
        Ok(ciborium::value::Value::Map(map)) => {
            eprintln!("[Test] ✓ Valid CBOR map with {} fields", map.len());

            // Check for required fields
            let has_auth_data = map.iter().any(|(k, _)| {
                matches!(k, ciborium::value::Value::Integer(i) if Into::<i128>::into(*i) == 2)
            });
            let has_signature = map.iter().any(|(k, _)| {
                matches!(k, ciborium::value::Value::Integer(i) if Into::<i128>::into(*i) == 3)
            });

            assert!(has_auth_data, "Response should contain authData (key 0x02)");
            assert!(
                has_signature,
                "Response should contain signature (key 0x03)"
            );
            eprintln!("[Test] ✓ Response contains required fields");
        }
        Ok(_) => panic!("Assertion should be a CBOR map"),
        Err(e) => panic!("Failed to parse assertion CBOR: {}", e),
    }

    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║              ✓ Test Passed!                    ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    // Clean up
    drop(transport);
    runner.stop();

    Ok(())
}
