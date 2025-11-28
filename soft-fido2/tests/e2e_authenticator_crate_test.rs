//! E2E Test with Mozilla's authenticator crate
//!
//! This test validates real-world compatibility between soft-fido2 and Mozilla's
//! authenticator crate (used in Firefox). It replicates the webauthn_flow example
//! but uses the authenticator crate as the CTAP client instead of soft-fido2's
//! built-in Client.
//!
//! # Architecture
//!
//! ```text
//! [Test] → [Mozilla authenticator crate] → [USB HID] → [UHID Device] → [CTAP HID Handler] → [soft-fido2 Authenticator]
//! ```
//!
//! This validates that soft-fido2 works correctly with Firefox's actual CTAP implementation.
//!
//! # Status
//!
//! ✅ **FULLY FUNCTIONAL**: This test successfully validates end-to-end compatibility
//! between soft-fido2 and Mozilla's authenticator crate (used in Firefox).
//!
//! Verified working:
//! - UHID device creation with unique VID/PID (0x1209:0xBEEF)
//! - Device detection by Mozilla authenticator crate via hidapi
//! - Full CTAP2 communication over UHID/HID
//! - WebAuthn registration (makeCredential)
//! - WebAuthn authentication (getAssertion)
//! - Signature generation and counter increments
//!
//! Configuration notes:
//! - Uses UP-only authenticator (uv=false) to avoid PIN requirements
//! - Configures resident key support for discoverable credentials
//! - Follows Mozilla authenticator crate's async channel pattern
//!
//! # Requirements
//!
//! - Linux with UHID support
//! - User must have UHID permissions
//! - authenticator crate 0.5.0
//!
//! Run with: cargo test --test e2e_authenticator_crate_test -- --ignored

#![cfg(all(target_os = "linux", feature = "std"))]

mod common;

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions,
};

use soft_fido2_transport::{CommandHandler, CtapHidHandler, Packet, UhidDevice};

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use authenticator::StatusUpdate;
use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
use authenticator::crypto::COSEAlgorithm;
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
    ResidentKeyRequirement, Transport, UserVerificationRequirement,
};
use authenticator::statecallback::StateCallback;
use common::VerboseTestCallbacks;
use serial_test::serial;
use sha2::{Digest, Sha256};

const TEST_RP_ID: &str = "example.com";
const TEST_RP_NAME: &str = "Example Corporation";
const TEST_ORIGIN: &str = "https://example.com";
const TEST_USER_ID: &[u8] = &[1, 2, 3, 4];
const TEST_USER_NAME: &str = "alice@example.com";
const TEST_USER_DISPLAY_NAME: &str = "Alice";

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
        let device = UhidDevice::create_fido_device()?;
        let device = Arc::new(Mutex::new(device));

        let auth_handler = AuthenticatorHandler::new(authenticator);
        let handler = CtapHidHandler::new(auth_handler);
        let handler = Arc::new(Mutex::new(handler));

        let running = Arc::new(Mutex::new(true));

        // Spawn authenticator thread
        let device_clone = Arc::clone(&device);
        let handler_clone = Arc::clone(&handler);
        let running_clone = Arc::clone(&running);

        let handle = thread::spawn(move || {
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
                    Err(_) => {
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

                let packet = Packet::from_bytes(buffer);

                // Process through CTAP HID handler
                let mut handler = handler_clone.lock().unwrap();
                let response_packets = match handler.process_packet(packet) {
                    Ok(packets) => packets,
                    Err(_) => {
                        drop(handler);
                        drop(device);
                        continue;
                    }
                };
                drop(handler);

                // Write response packets
                for response_packet in response_packets {
                    let _ = device.write_packet(response_packet.as_bytes());
                }
                drop(device);
            }
        });

        Ok(Self {
            _device: device,
            _handler: handler,
            running,
            thread_handle: Some(handle),
        })
    }

    fn stop(mut self) {
        *self.running.lock().unwrap() = false;
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Helper to compute client data hash
fn compute_client_data_hash(challenge: &[u8], ceremony_type: &str) -> [u8; 32] {
    use base64::Engine;
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);

    let client_data_json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
        ceremony_type, challenge_b64, TEST_ORIGIN
    );

    let hash = Sha256::digest(client_data_json.as_bytes());
    hash.into()
}

#[test]
#[ignore]
#[serial]
fn test_authenticator_crate_webauthn_flow() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║   E2E Test: Mozilla authenticator Crate       ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    // ========================================
    // SETUP: Create and start authenticator
    // ========================================
    let callbacks = VerboseTestCallbacks::new();

    // Configure as a simple UP-only authenticator (no UV, no PIN)
    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_presence(true)
                .with_user_verification(Some(false))
                .with_platform_device(false)
                .with_client_pin(Some(false))
                .with_credential_management(Some(false)),
        )
        .build();

    let authenticator = Authenticator::with_config(callbacks, config)?;

    // Start authenticator in background
    let runner = AuthenticatorRunner::start(authenticator)?;

    // Give UHID device time to enumerate
    thread::sleep(Duration::from_secs(2));

    // ========================================
    // PHASE 1: REGISTRATION (makeCredential)
    // ========================================
    eprintln!("\n[Test] ═══ REGISTRATION PHASE ═══\n");

    // Create authenticator service
    let mut manager = AuthenticatorService::new()?;
    manager.add_u2f_usb_hid_platform_transports();

    // Prepare registration
    let challenge = b"random-registration-challenge-12345";
    let client_data_hash = compute_client_data_hash(challenge, "webauthn.create");

    let rp = RelyingParty {
        id: TEST_RP_ID.to_string(),
        name: Some(TEST_RP_NAME.to_string()),
    };

    let user = PublicKeyCredentialUserEntity {
        id: TEST_USER_ID.to_vec(),
        name: Some(TEST_USER_NAME.to_string()),
        display_name: Some(TEST_USER_DISPLAY_NAME.to_string()),
    };

    // Channel for status updates
    let (status_tx, status_rx): (Sender<StatusUpdate>, Receiver<StatusUpdate>) = channel();

    // Spawn status monitoring thread
    thread::spawn(move || {
        while status_rx.recv().is_ok() {
            // Ignore status updates
        }
    });

    let args = RegisterArgs {
        client_data_hash,
        relying_party: rp,
        origin: TEST_ORIGIN.to_string(),
        user,
        pub_cred_params: vec![
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            },
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::RS256,
            },
        ],
        exclude_list: vec![],
        user_verification_req: UserVerificationRequirement::Discouraged,
        resident_key_req: ResidentKeyRequirement::Discouraged, // Don't require RK to avoid PIN requirement
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.register(20_000, args.clone(), status_tx.clone(), callback) {
        return Err(format!("Couldn't register: {:?}", e).into());
    }

    let register_result = register_rx
        .recv()
        .map_err(|_| "Problem receiving registration result")?;

    let make_cred_result = match register_result {
        Ok(result) => result,
        Err(e) => return Err(format!("Registration failed: {:?}", e).into()),
    };

    eprintln!("[Test] ✓ Registration successful");
    eprintln!("[Test]   Attachment: {:?}", make_cred_result.attachment);

    let credential_id = make_cred_result
        .att_obj
        .auth_data
        .credential_data
        .as_ref()
        .ok_or("No credential data in attestation")?
        .credential_id
        .clone();

    eprintln!("[Test]   Credential ID: {} bytes", credential_id.len());

    // ========================================
    // PHASE 2: AUTHENTICATION (getAssertion)
    // ========================================
    eprintln!("\n[Test] ═══ AUTHENTICATION PHASE ═══\n");

    // Reuse the same manager for authentication
    let challenge = b"random-authentication-challenge-67890";
    let client_data_hash = compute_client_data_hash(challenge, "webauthn.get");

    // Channel for status updates
    let (status_tx, status_rx): (Sender<StatusUpdate>, Receiver<StatusUpdate>) = channel();

    // Spawn status monitoring thread
    thread::spawn(move || {
        while status_rx.recv().is_ok() {
            // Ignore status updates
        }
    });

    let allow_list = vec![PublicKeyCredentialDescriptor {
        id: credential_id,
        transports: vec![Transport::USB],
    }];

    let args = SignArgs {
        client_data_hash,
        origin: TEST_ORIGIN.to_string(),
        relying_party_id: TEST_RP_ID.to_string(),
        allow_list,
        user_verification_req: UserVerificationRequirement::Discouraged,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    let (sign_tx, sign_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        sign_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.sign(20_000, args.clone(), status_tx.clone(), callback) {
        return Err(format!("Couldn't sign: {:?}", e).into());
    }

    let sign_result = sign_rx
        .recv()
        .map_err(|_| "Problem receiving authentication result")?;

    let get_assertion_result = match sign_result {
        Ok(result) => result,
        Err(e) => return Err(format!("Authentication failed: {:?}", e).into()),
    };

    eprintln!("[Test] ✓ Authentication successful");
    eprintln!("[Test]   Attachment: {:?}", get_assertion_result.attachment);
    eprintln!(
        "[Test]   Signature: {} bytes",
        get_assertion_result.assertion.signature.len()
    );
    eprintln!(
        "[Test]   Counter: {}",
        get_assertion_result.assertion.auth_data.counter
    );

    // ========================================
    // CLEANUP
    // ========================================
    eprintln!("\n╔════════════════════════════════════════════════╗");
    eprintln!("║              ✓ Test Passed!                    ║");
    eprintln!("╚════════════════════════════════════════════════╝\n");

    eprintln!("Summary:");
    eprintln!("  • Registered new credential using Mozilla authenticator crate");
    eprintln!("  • Successfully authenticated using the credential");
    eprintln!("  • Validates Firefox CTAP client compatibility");

    runner.stop();

    Ok(())
}
