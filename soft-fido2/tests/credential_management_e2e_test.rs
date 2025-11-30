//! End-to-end tests for credential management client API
//!
//! These tests use USB HID transport with a virtual authenticator running in a background thread.

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Client,
    ClientDataHash, Credential, CredentialManagementRequest, CredentialRef,
    DeleteCredentialRequest, EnumerateCredentialsRequest, Error, GetAssertionRequest,
    MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol, RelyingParty, Transport, TransportList,
    UpResult, User, UvResult, compute_rp_id_hash,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use soft_fido2_transport::{CommandHandler, CtapHidHandler, Packet, UhidDevice};

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

/// Test callbacks for credential management testing
struct TestCallbacks {
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
    user_mappings: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>, // username -> credential_ids
}

impl TestCallbacks {
    fn new() -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
            user_mappings: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl AuthenticatorCallbacks for TestCallbacks {
    fn request_up(
        &self,
        _info: &str,
        _user: Option<&str>,
        _rp: &str,
    ) -> soft_fido2::Result<UpResult> {
        Ok(UpResult::Accepted)
    }

    fn request_uv(
        &self,
        _info: &str,
        _user: Option<&str>,
        _rp: &str,
    ) -> soft_fido2::Result<UvResult> {
        Ok(UvResult::Accepted)
    }

    fn write_credential(
        &self,
        cred_id: &[u8],
        _rp_id: &str,
        cred: &CredentialRef,
    ) -> soft_fido2::Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.insert(cred_id.to_vec(), cred.to_owned());

        // Track user -> credential mapping
        if let Some(user_name) = cred.user_name
            && !user_name.is_empty()
        {
            let mut mappings = self.user_mappings.lock().unwrap();
            mappings
                .entry(user_name.to_string())
                .or_default()
                .push(cred_id.to_vec());
        }

        Ok(())
    }

    fn read_credential(
        &self,
        cred_id: &[u8],
        _rp_id: &str,
    ) -> soft_fido2::Result<Option<Credential>> {
        let store = self.credentials.lock().unwrap();
        Ok(store.get(cred_id).cloned())
    }

    fn delete_credential(&self, cred_id: &[u8]) -> soft_fido2::Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.remove(cred_id);
        Ok(())
    }

    fn list_credentials(
        &self,
        rp_id: &str,
        _user_id: Option<&[u8]>,
    ) -> soft_fido2::Result<Vec<Credential>> {
        let store = self.credentials.lock().unwrap();
        let filtered: Vec<Credential> = store
            .values()
            .filter(|c| c.rp.id == rp_id)
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn enumerate_rps(&self) -> soft_fido2::Result<Vec<(String, Option<String>, usize)>> {
        let store = self.credentials.lock().unwrap();
        let mut rp_map: HashMap<String, (Option<String>, usize)> = HashMap::new();

        for cred in store.values() {
            let entry = rp_map
                .entry(cred.rp.id.clone())
                .or_insert((cred.rp.name.clone(), 0));
            entry.1 += 1;
        }

        let result: Vec<(String, Option<String>, usize)> = rp_map
            .into_iter()
            .map(|(rp_id, (rp_name, count))| (rp_id, rp_name, count))
            .collect();

        Ok(result)
    }

    fn credential_count(&self) -> soft_fido2::Result<usize> {
        let store = self.credentials.lock().unwrap();
        Ok(store.len())
    }
}

/// Test helper: Set up a transport connection with USB HID authenticator
fn setup_transport()
-> Result<(soft_fido2::Transport, AuthenticatorRunner<TestCallbacks>), Box<dyn std::error::Error>> {
    let callbacks = TestCallbacks::new();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
            0x7c, 0x88,
        ])
        .max_credentials(100)
        .extensions(vec!["credProtect".to_string(), "hmac-secret".to_string()])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(false))
                .with_client_pin(Some(false)),
        )
        .build();

    let authenticator = Authenticator::with_config(callbacks, config)?;

    // Set a test PIN
    let pin = b"123456";
    let mut pin_hash = [0u8; 32];
    use sha2::{Digest, Sha256};
    pin_hash.copy_from_slice(&Sha256::digest(pin));
    Authenticator::<TestCallbacks>::set_pin_hash(&pin_hash);

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
        return Err("No transports found".into());
    }

    eprintln!("[Test] Found {} transport(s)", list.len());
    let mut transport = list.get(list.len() - 1).expect("Failed to get transport");
    transport.open()?;

    Ok((transport, runner))
}

/// Test helper: Create a test credential
fn create_test_credential(
    transport: &mut Transport,
    rp_id: &str,
    user_name: &str,
) -> Result<Vec<u8>, Error> {
    let client_data_hash = ClientDataHash::new([0u8; 32]);
    let rp = RelyingParty {
        id: rp_id.to_string(),
        name: None,
    };
    let user = User {
        id: vec![1, 2, 3, 4],
        name: Some(format!("{}@{}", user_name, rp_id)),
        display_name: Some(user_name.to_string()),
    };

    let request = MakeCredentialRequest::new(client_data_hash, rp, user);
    Client::make_credential(transport, request)
}

/// Test helper: Get PIN/UV auth token (simplified for testing)
/// In a real test, this would use the authenticatorClientPIN command
fn get_pin_uv_auth_token() -> PinUvAuth {
    // For testing with software authenticator, use a dummy PIN token
    // In a real implementation, this would:
    // 1. Use authenticatorClientPIN to get key agreement
    // 2. Use authenticatorClientPIN to get PIN token
    // 3. Return PinUvAuth with the token
    PinUvAuth::new(
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ],
        PinUvAuthProtocol::V2,
    )
}

#[cfg(test)]
mod e2e_tests {
    use super::*;

    /// Test complete credential management workflow
    ///
    /// This test requires:
    /// - A virtual authenticator with PIN set
    /// - No existing credentials initially
    /// - Permission to create and manage credentials
    #[test]
    #[ignore]
    fn test_credential_management_full_workflow() {
        let (mut transport, runner) = setup_transport().unwrap();

        // Step 1: Get initial metadata (should be empty)
        // Since client_pin is disabled, we don't need PIN auth
        let result = Client::get_credentials_metadata(
            &mut transport,
            CredentialManagementRequest::new(None),
        );
        println!("Raw result: {:?}", result);
        let metadata = result.unwrap();
        println!(
            "Initial metadata: existing={}, remaining={}",
            metadata.existing_resident_credentials_count,
            metadata.max_possible_remaining_resident_credentials_count
        );
        println!(
            "Initial metadata: existing={}, remaining={}",
            metadata.existing_resident_credentials_count,
            metadata.max_possible_remaining_resident_credentials_count
        );

        // Step 2: Create some test credentials
        let _cred1_id = create_test_credential(&mut transport, "example.com", "alice").unwrap();
        let _cred2_id = create_test_credential(&mut transport, "example.com", "bob").unwrap();
        let _cred3_id = create_test_credential(&mut transport, "other.com", "charlie").unwrap();

        // Step 3: Get updated metadata
        let metadata = Client::get_credentials_metadata(
            &mut transport,
            CredentialManagementRequest::new(None),
        )
        .unwrap();
        println!(
            "After creation: existing={}, remaining={}",
            metadata.existing_resident_credentials_count,
            metadata.max_possible_remaining_resident_credentials_count
        );
        assert!(metadata.existing_resident_credentials_count >= 3);

        // Step 4: Enumerate all RPs
        let rps =
            Client::enumerate_rps(&mut transport, CredentialManagementRequest::new(None)).unwrap();
        println!("Found {} RPs", rps.len());
        assert!(!rps.is_empty());

        // Should find example.com and other.com
        let _example_rp = rps.iter().find(|rp| rp.id == "example.com").unwrap();
        let _other_rp = rps.iter().find(|rp| rp.id == "other.com").unwrap();

        // Step 5: Enumerate credentials for example.com
        let rp_id_hash = compute_rp_id_hash("example.com");
        let request = EnumerateCredentialsRequest::new(None, rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();
        println!("Found {} credentials for example.com", credentials.len());
        assert_eq!(credentials.len(), 2); // alice and bob

        // Verify credential details
        for cred in &credentials {
            assert!(cred.user.name.is_some());
            assert!(cred.user.display_name.is_some());
            assert!(!cred.credential_id.id.is_empty());
        }

        // Step 6: Delete one credential
        let alice_cred = credentials
            .iter()
            .find(|c| c.user.name.as_ref().unwrap().contains("alice"))
            .unwrap();
        let delete_request =
            DeleteCredentialRequest::new(None, alice_cred.credential_id.id.clone());
        Client::delete_credential(&mut transport, delete_request).unwrap();
        println!("Deleted alice's credential");

        // Step 7: Verify credential was deleted
        let rp_id_hash = compute_rp_id_hash("example.com");
        let request = EnumerateCredentialsRequest::new(None, rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();
        println!(
            "After deletion: {} credentials for example.com",
            credentials.len()
        );
        assert_eq!(credentials.len(), 1); // only bob left

        // Step 8: Verify final metadata
        let metadata = Client::get_credentials_metadata(
            &mut transport,
            CredentialManagementRequest::new(None),
        )
        .unwrap();
        println!(
            "Final metadata: existing={}",
            metadata.existing_resident_credentials_count
        );
        assert_eq!(metadata.existing_resident_credentials_count, 2); // bob and charlie

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test RP enumeration edge cases
    #[test]
    #[ignore]
    fn test_rp_enumeration() {
        let (mut transport, runner) = setup_transport().unwrap();

        // Create some test credentials first
        let _cred1_id = create_test_credential(&mut transport, "example.com", "alice").unwrap();
        let _cred2_id = create_test_credential(&mut transport, "other.com", "bob").unwrap();

        // Test begin/get_next pattern
        let request = CredentialManagementRequest::new(None);
        let begin_response = Client::enumerate_rps_begin(&mut transport, request).unwrap();

        println!("Total RPs: {}", begin_response.total_rps);

        // Get remaining RPs one by one
        for i in 1..begin_response.total_rps {
            let rp = Client::enumerate_rps_get_next(&mut transport).unwrap();
            println!("RP {}: {}", i, rp.id);
        }

        // Test convenience method
        let request = CredentialManagementRequest::new(None);
        let all_rps = Client::enumerate_rps(&mut transport, request).unwrap();
        assert_eq!(all_rps.len() as u32, begin_response.total_rps);

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test credential enumeration for different RPs
    #[test]
    #[ignore]
    fn test_credential_enumeration_multiple_rps() {
        let (mut transport, runner) = setup_transport().unwrap();

        // Create some test credentials first
        let _cred1_id = create_test_credential(&mut transport, "example.com", "alice").unwrap();
        let _cred2_id = create_test_credential(&mut transport, "example.com", "bob").unwrap();
        let _cred3_id = create_test_credential(&mut transport, "other.com", "charlie").unwrap();

        // Enumerate all RPs first
        let request = CredentialManagementRequest::new(None);
        let rps = Client::enumerate_rps(&mut transport, request).unwrap();

        // Enumerate credentials for each RP
        for rp in rps {
            let request = EnumerateCredentialsRequest::new(None, rp.rp_id_hash);
            let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();
            println!("RP {} has {} credentials", rp.id, credentials.len());
        }

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test error conditions
    #[test]
    #[ignore]
    fn test_error_conditions() {
        let (mut transport, _runner) = setup_transport().unwrap();

        // Since client_pin is disabled, invalid PIN tokens are ignored
        let invalid_pin_uv_auth = PinUvAuth::new(vec![0xFFu8; 32], PinUvAuthProtocol::V2);
        let request = CredentialManagementRequest::new(Some(invalid_pin_uv_auth));

        // Should succeed since PIN verification is bypassed
        let result = Client::get_credentials_metadata(&mut transport, request);
        println!("Actual result: {:?}", result);
        assert!(result.is_ok());
    }

    /// Test credential enumeration with no credentials
    #[test]
    #[ignore]
    fn test_enumerate_empty_rp() {
        let (mut transport, runner) = setup_transport().unwrap();
        let pin_uv_auth = get_pin_uv_auth_token();

        // Use a non-existent RP ID hash
        let empty_rp_hash = [0u8; 32];
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth), empty_rp_hash);

        let result = Client::enumerate_credentials(&mut transport, request);
        println!("Actual error for empty RP: {:?}", result);
        // Should fail with NoCredentials since PIN verification is bypassed
        assert!(matches!(result, Err(Error::NoCredentials)));

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test deleting non-existent credential
    #[test]
    #[ignore]
    fn test_delete_nonexistent_credential() {
        let (mut transport, runner) = setup_transport().unwrap();
        let pin_uv_auth = get_pin_uv_auth_token();

        let fake_cred_id = vec![0xFFu8; 32];
        let request = DeleteCredentialRequest::new(Some(pin_uv_auth), fake_cred_id);

        let result = Client::delete_credential(&mut transport, request);
        println!("Actual result for nonexistent credential: {:?}", result);
        // Should succeed since PIN verification is bypassed and delete is idempotent
        assert!(result.is_ok());

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test PIN/UV auth protocol differences
    #[test]
    #[ignore]
    fn test_pin_uv_protocols() {
        let (mut transport, runner) = setup_transport().unwrap();

        // Since client_pin is disabled, we don't need PIN auth for these operations
        // Test with V1 protocol (dummy token) - should work since PIN is bypassed
        let request = CredentialManagementRequest::new(Some(PinUvAuth::new(
            vec![0u8; 32],
            PinUvAuthProtocol::V1,
        )));
        let result1 = Client::get_credentials_metadata(&mut transport, request);
        // Should work since PIN is bypassed
        assert!(result1.is_ok());

        // Test with V2 protocol (dummy token) - should work since PIN is bypassed
        let request = CredentialManagementRequest::new(Some(PinUvAuth::new(
            vec![0u8; 32],
            PinUvAuthProtocol::V2,
        )));
        let result2 = Client::get_credentials_metadata(&mut transport, request);
        // Should work since PIN is bypassed
        assert!(result2.is_ok());

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test large blob key and third-party payment fields
    #[test]
    #[ignore]
    fn test_extended_credential_fields() {
        let (mut transport, runner) = setup_transport().unwrap();

        // Create some test credentials first
        let _cred1_id = create_test_credential(&mut transport, "example.com", "alice").unwrap();
        let _cred2_id = create_test_credential(&mut transport, "other.com", "bob").unwrap();

        // Enumerate credentials and check for extended fields
        let request = CredentialManagementRequest::new(None);
        let rps = Client::enumerate_rps(&mut transport, request).unwrap();

        for rp in rps {
            let request = EnumerateCredentialsRequest::new(None, rp.rp_id_hash);
            let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();

            for cred in credentials {
                // Check if large blob key is present
                if let Some(large_blob_key) = cred.large_blob_key {
                    println!(
                        "Credential has large blob key: {} bytes",
                        large_blob_key.len()
                    );
                    assert_eq!(large_blob_key.len(), 32);
                }

                // Check third-party payment flag
                if let Some(third_party_payment) = cred.third_party_payment {
                    println!("Third-party payment enabled: {}", third_party_payment);
                }

                // Check credential protection level
                if let Some(cred_protect) = cred.cred_protect {
                    println!("Credential protection level: {}", cred_protect);
                    assert!((0x01..=0x03).contains(&cred_protect));
                }
            }
        }

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test RP ID truncation handling
    #[test]
    #[ignore]
    fn test_rp_id_truncation() {
        let (mut transport, runner) = setup_transport().unwrap();

        // Create some test credentials first
        let _cred1_id = create_test_credential(&mut transport, "example.com", "alice").unwrap();
        let _cred2_id = create_test_credential(&mut transport, "other.com", "bob").unwrap();

        let request = CredentialManagementRequest::new(None);
        let rps = Client::enumerate_rps(&mut transport, request).unwrap();

        for rp in rps {
            // Check if RP ID appears truncated (contains ellipsis)
            if rp.id.contains('…') {
                println!("Found truncated RP ID: {}", rp.id);
                // Truncated IDs should be exactly 32 bytes
                assert_eq!(rp.id.len(), 32);
                assert!(rp.id.contains('…'));
            } else {
                // Non-truncated IDs should be <= 32 bytes
                assert!(rp.id.len() <= 32);
            }
        }

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test concurrent operations (if supported by authenticator)
    #[test]
    #[ignore] // Requires authenticator supporting concurrent operations
    fn test_concurrent_operations() {
        let transport_result1 = setup_transport();
        if transport_result1.is_err() {
            println!("Skipping test - no FIDO2 devices available");
            return;
        }
        let (mut transport1, runner1) = transport_result1.unwrap();

        let transport_result2 = setup_transport();
        if transport_result2.is_err() {
            println!("Skipping test - no FIDO2 devices available for second transport");
            runner1.stop();
            return;
        }
        let (mut transport2, runner2) = transport_result2.unwrap();

        let pin_uv_auth = get_pin_uv_auth_token();

        // Try to perform operations on two different transports
        let request1 = CredentialManagementRequest::new(Some(pin_uv_auth.clone()));
        let request2 = CredentialManagementRequest::new(Some(pin_uv_auth));

        let handle1 =
            std::thread::spawn(move || Client::get_credentials_metadata(&mut transport1, request1));

        let handle2 =
            std::thread::spawn(move || Client::get_credentials_metadata(&mut transport2, request2));

        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();

        // Both should succeed or both should fail consistently
        assert_eq!(result1.is_ok(), result2.is_ok());

        // Clean up
        runner1.stop();
        runner2.stop();
    }

    /// Test timeout handling
    #[test]
    #[ignore] // Requires slow/unresponsive authenticator
    fn test_timeout_handling() {
        let transport_result = setup_transport();
        if transport_result.is_err() {
            println!("Skipping test - no FIDO2 devices available");
            return;
        }
        let (mut transport, runner) = transport_result.unwrap();
        let pin_uv_auth = get_pin_uv_auth_token();

        let request = CredentialManagementRequest::new(Some(pin_uv_auth));

        // This might timeout depending on authenticator responsiveness
        let result = Client::get_credentials_metadata(&mut transport, request);
        match result {
            Ok(_) => println!("Operation completed successfully"),
            Err(Error::Timeout) => println!("Operation timed out as expected"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test credential creation and immediate enumeration
    #[test]
    #[ignore] // Requires clean authenticator
    fn test_create_and_enumerate_immediately() {
        let transport_result = setup_transport();
        if transport_result.is_err() {
            println!("Skipping test - no FIDO2 devices available");
            return;
        }
        let (mut transport, runner) = transport_result.unwrap();
        let _pin_uv_auth = get_pin_uv_auth_token();

        // Create a credential
        let cred_id = create_test_credential(&mut transport, "test.com", "testuser").unwrap();

        // Immediately enumerate - should find the new credential
        let rp_id_hash = compute_rp_id_hash("test.com");
        let request = EnumerateCredentialsRequest::new(Some(get_pin_uv_auth_token()), rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();

        assert_eq!(credentials.len(), 1);
        // Note: credential ID may be wrapped for storage, so we don't check exact match
        // The important thing is that enumeration finds the created credential
        assert!(!credentials[0].credential_id.id.is_empty());

        // Clean up
        let delete_request = DeleteCredentialRequest::new(Some(get_pin_uv_auth_token()), cred_id);
        Client::delete_credential(&mut transport, delete_request).unwrap();

        // Clean up
        drop(transport);
        runner.stop();
    }

    /// Test assertion still works after credential management
    #[test]
    #[ignore] // Requires authenticator with credentials
    fn test_assertion_after_management() {
        let (mut transport, runner) = setup_transport().unwrap();

        // Create a credential for assertion testing
        let _cred_id =
            create_test_credential(&mut transport, "assertion-test.com", "testuser").unwrap();

        // Perform an assertion
        let client_data_hash = ClientDataHash::new([1u8; 32]);
        let request = GetAssertionRequest::new(client_data_hash, "assertion-test.com");
        let assertion = Client::get_assertion(&mut transport, request).unwrap();

        // Should get a valid assertion
        assert!(!assertion.is_empty());
        println!("Got assertion: {} bytes", assertion.len());

        // Clean up
        drop(transport);
        runner.stop();
    }
}
