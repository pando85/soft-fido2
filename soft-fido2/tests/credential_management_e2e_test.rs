//! End-to-end tests for credential management client API
//!
//! These tests use USB HID transport with a virtual authenticator running in a background thread.

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Client,
    ClientDataHash, Credential, CredentialManagementRequest, CredentialRef,
    DeleteCredentialRequest, EnumerateCredentialsRequest, Error, GetAssertionRequest,
    MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol, Transport, TransportList, UpResult,
    UvResult, compute_rp_id_hash,
};
use soft_fido2_ctap::types::{RelyingParty, User};
use soft_fido2_transport::{CommandHandler, CtapHidHandler, Packet, UhidDevice};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;

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
    _handler: Arc<Mutex<CtapHidHandler<AuthenticatorHandler<C>>>>,
    running: Arc<Mutex<bool>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl<C: AuthenticatorCallbacks> Drop for AuthenticatorRunner<C> {
    fn drop(&mut self) {
        *self.running.lock().unwrap() = false;
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
        thread::sleep(Duration::from_secs(2));
    }
}

impl<C: AuthenticatorCallbacks + 'static> AuthenticatorRunner<C> {
    fn start(authenticator: Authenticator<C>) -> Result<Self, Box<dyn std::error::Error>> {
        let device = UhidDevice::create_fido_device()?;
        let device = Arc::new(Mutex::new(device));

        let auth_handler = AuthenticatorHandler::new(authenticator);
        let handler = CtapHidHandler::new(auth_handler);
        let handler = Arc::new(Mutex::new(handler));

        let running = Arc::new(Mutex::new(true));

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

                for response_packet in response_packets {
                    let _ = device.write_packet(response_packet.as_bytes());
                }
                drop(device);
            }
        });

        Ok(Self {
            _handler: handler,
            running,
            thread_handle: Some(handle),
        })
    }
}

/// Test callbacks for credential management testing
struct TestCallbacks {
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
}

impl TestCallbacks {
    fn new() -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
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

    fn write_credential(&self, cred: &CredentialRef) -> soft_fido2::Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.insert(cred.id.to_vec(), cred.to_owned());
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8]) -> soft_fido2::Result<Option<Credential>> {
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
            .filter(|c| c.rp.id == rp_id && c.discoverable)
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn enumerate_rps(&self) -> soft_fido2::Result<Vec<(String, Option<String>, usize)>> {
        let store = self.credentials.lock().unwrap();
        let mut rp_map: HashMap<String, (Option<String>, usize)> = HashMap::new();

        for cred in store.values().filter(|c| c.discoverable) {
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
        Ok(store.values().filter(|c| c.discoverable).count())
    }
}

/// Set up a transport connection with USB HID authenticator
fn setup_transport()
-> Result<(Transport, AuthenticatorRunner<TestCallbacks>), Box<dyn std::error::Error>> {
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
                .with_user_verification(Some(true))
                .with_client_pin(None)
                .with_pin_uv_auth_token(Some(true))
                .with_credential_management(Some(true))
                .with_make_cred_uv_not_required(Some(true)),
        )
        .build();

    let authenticator = Authenticator::with_config(callbacks, config)?;
    let runner = AuthenticatorRunner::start(authenticator)?;

    thread::sleep(Duration::from_millis(500));

    let mut prev_count = 0;
    let mut stable_iterations = 0;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        let count = TransportList::enumerate()?.len();

        if count == prev_count && count > 0 {
            stable_iterations += 1;
            if stable_iterations >= 3 {
                break;
            }
        } else {
            stable_iterations = 0;
        }
        prev_count = count;
    }

    let list = TransportList::enumerate()?;

    if list.is_empty() {
        return Err("No transports found".into());
    }

    let device_index = list.len() - 1;
    let mut transport = list.get(device_index).expect("Failed to get transport");
    transport.open()?;

    Ok((transport, runner))
}

/// Helper to obtain a UV-based PIN/UV auth token with makeCredential permission
fn get_uv_token_for_make_credential(
    transport: &mut Transport,
    rp_id: &str,
) -> Result<Vec<u8>, Error> {
    let protocol = soft_fido2::PinProtocol::V2;
    let mut encapsulation = soft_fido2::pin::PinUvAuthEncapsulation::new(transport, protocol)?;

    let permissions = soft_fido2::request::Permission::MakeCredential as u8;
    let token = encapsulation.get_pin_uv_auth_token_using_uv_with_permissions(
        transport,
        permissions,
        Some(rp_id),
    )?;

    Ok(token)
}

/// Helper to obtain a UV-based PIN/UV auth token with getAssertion permission
fn get_uv_token_for_get_assertion(
    transport: &mut Transport,
    rp_id: &str,
) -> Result<Vec<u8>, Error> {
    let protocol = soft_fido2::PinProtocol::V2;
    let mut encapsulation = soft_fido2::pin::PinUvAuthEncapsulation::new(transport, protocol)?;

    let permissions = soft_fido2::request::Permission::GetAssertion as u8;
    let token = encapsulation.get_pin_uv_auth_token_using_uv_with_permissions(
        transport,
        permissions,
        Some(rp_id),
    )?;

    Ok(token)
}

/// Helper to obtain a UV-based PIN/UV auth for CredentialManagement
fn get_uv_auth_for_credential_management(transport: &mut Transport) -> Result<PinUvAuth, Error> {
    // Use the client library's helper function which returns PinUvAuth
    // containing the raw PIN token (not a computed HMAC)
    Client::get_uv_token_for_credential_management(transport, soft_fido2::PinProtocol::V2)
}

/// Create a test credential with UV-based PIN/UV auth
fn create_test_credential(
    transport: &mut Transport,
    rp_id: &str,
    user_name: &str,
) -> Result<Vec<u8>, Error> {
    // Get UV-based PIN token for makeCredential
    let pin_token = get_uv_token_for_make_credential(transport, rp_id)?;

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

    // Compute pinUvAuthParam = HMAC-SHA256(pinToken, clientDataHash)
    let mut mac = Hmac::<Sha256>::new_from_slice(&pin_token).map_err(|_| Error::Other)?;
    mac.update(client_data_hash.as_slice());
    let pin_uv_auth_param = mac.finalize().into_bytes().to_vec();

    let pin_uv_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);

    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_resident_key(true)
        .with_pin_uv_auth(pin_uv_auth);

    Client::make_credential(transport, request)
}

#[cfg(test)]
mod e2e_tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_credential_management_full_workflow() {
        let (mut transport, _runner) = setup_transport().unwrap();

        // Get PIN/UV auth for credential management
        let pin_uv_auth = get_uv_auth_for_credential_management(&mut transport).unwrap();

        // Get initial metadata
        let _metadata = Client::get_credentials_metadata(
            &mut transport,
            CredentialManagementRequest::new(Some(pin_uv_auth.clone())),
        )
        .unwrap();

        create_test_credential(&mut transport, "example.com", "alice").unwrap();
        create_test_credential(&mut transport, "example.com", "bob").unwrap();
        create_test_credential(&mut transport, "other.com", "charlie").unwrap();

        // Get fresh PIN/UV auth after creating credentials
        // (create_test_credential replaces the token with a MakeCredential token)
        let pin_uv_auth = get_uv_auth_for_credential_management(&mut transport).unwrap();

        // Get metadata with auth
        let metadata = Client::get_credentials_metadata(
            &mut transport,
            CredentialManagementRequest::new(Some(pin_uv_auth.clone())),
        )
        .unwrap();
        assert!(metadata.existing_resident_credentials_count >= 3);

        // Enumerate RPs with auth
        let rps = Client::enumerate_rps(
            &mut transport,
            CredentialManagementRequest::new(Some(pin_uv_auth.clone())),
        )
        .unwrap();
        assert!(!rps.is_empty());

        // Enumerate credentials with auth
        let rp_id_hash = compute_rp_id_hash("example.com");
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth.clone()), rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();
        assert_eq!(credentials.len(), 2);

        // Delete credential with auth
        let alice_cred = credentials
            .iter()
            .find(|c| c.user.name.as_ref().unwrap().contains("alice"))
            .unwrap();
        let delete_request = DeleteCredentialRequest::new(
            Some(pin_uv_auth.clone()),
            alice_cred.credential_id.id.clone(),
        );
        Client::delete_credential(&mut transport, delete_request).unwrap();

        // Verify deletion with auth
        let rp_id_hash = compute_rp_id_hash("example.com");
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth.clone()), rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();
        assert_eq!(credentials.len(), 1);

        // Final metadata check with auth
        let metadata = Client::get_credentials_metadata(
            &mut transport,
            CredentialManagementRequest::new(Some(pin_uv_auth)),
        )
        .unwrap();
        assert_eq!(metadata.existing_resident_credentials_count, 2);
    }

    #[test]
    #[ignore]
    fn test_rp_enumeration() {
        let (mut transport, _runner) = setup_transport().unwrap();

        create_test_credential(&mut transport, "example.com", "alice").unwrap();
        create_test_credential(&mut transport, "other.com", "bob").unwrap();

        let pin_uv_auth = get_uv_auth_for_credential_management(&mut transport).unwrap();
        let request = CredentialManagementRequest::new(Some(pin_uv_auth.clone()));
        let begin_response = Client::enumerate_rps_begin(&mut transport, request).unwrap();

        for _ in 1..begin_response.total_rps {
            Client::enumerate_rps_get_next(&mut transport).unwrap();
        }

        // Enumerate all RPs with auth
        let request = CredentialManagementRequest::new(Some(pin_uv_auth));
        let all_rps = Client::enumerate_rps(&mut transport, request).unwrap();
        assert_eq!(all_rps.len() as u32, begin_response.total_rps);
    }

    #[test]
    #[ignore]
    fn test_credential_enumeration_multiple_rps() {
        let (mut transport, _runner) = setup_transport().unwrap();

        create_test_credential(&mut transport, "example.com", "alice").unwrap();
        create_test_credential(&mut transport, "example.com", "bob").unwrap();
        create_test_credential(&mut transport, "other.com", "charlie").unwrap();

        let pin_uv_auth = get_uv_auth_for_credential_management(&mut transport).unwrap();
        let request = CredentialManagementRequest::new(Some(pin_uv_auth.clone()));
        let rps = Client::enumerate_rps(&mut transport, request).unwrap();

        for rp in rps {
            let request =
                EnumerateCredentialsRequest::new(Some(pin_uv_auth.clone()), rp.rp_id_hash);
            let _credentials = Client::enumerate_credentials(&mut transport, request).unwrap();
        }
    }

    #[test]
    #[ignore]
    fn test_enumerate_empty_rp() {
        let (mut transport, _runner) = setup_transport().unwrap();

        // Get PIN/UV auth for credential management
        let pin_uv_auth = get_uv_auth_for_credential_management(&mut transport).unwrap();

        let empty_rp_hash = [0u8; 32];
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth), empty_rp_hash);

        let result = Client::enumerate_credentials(&mut transport, request);
        assert!(matches!(result, Err(Error::NoCredentials)));
    }

    #[test]
    #[ignore]
    fn test_create_and_enumerate_immediately() {
        let (mut transport, _runner) = setup_transport().unwrap();

        let _cred_id = create_test_credential(&mut transport, "test.com", "testuser")
            .map_err(|e| eprintln!("Failed to create credential: {:?}", e))
            .unwrap();

        let pin_uv_auth = get_uv_auth_for_credential_management(&mut transport).unwrap();

        let rp_id_hash = compute_rp_id_hash("test.com");
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth.clone()), rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();

        // Each test run creates a fresh authenticator, so we should have exactly 1 credential
        assert_eq!(credentials.len(), 1);
        assert!(!credentials[0].credential_id.id.is_empty());

        // Clean up - delete the credential
        let delete_request = DeleteCredentialRequest::new(
            Some(pin_uv_auth),
            credentials[0].credential_id.id.clone(),
        );
        Client::delete_credential(&mut transport, delete_request).unwrap();
    }

    #[test]
    #[ignore]
    fn test_assertion_after_management() {
        let (mut transport, _runner) = setup_transport().unwrap();

        create_test_credential(&mut transport, "assertion-test.com", "testuser").unwrap();

        // Get UV-based PIN token for getAssertion
        // Note: Credential was created with UV, so it requires UV for assertion
        let pin_token =
            get_uv_token_for_get_assertion(&mut transport, "assertion-test.com").unwrap();

        let client_data_hash = ClientDataHash::new([1u8; 32]);

        // Compute pinUvAuthParam = HMAC-SHA256(pinToken, clientDataHash)
        let mut mac = Hmac::<Sha256>::new_from_slice(&pin_token).unwrap();
        mac.update(client_data_hash.as_slice());
        let pin_uv_auth_param = mac.finalize().into_bytes().to_vec();

        let pin_uv_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);

        let request = GetAssertionRequest::new(client_data_hash, "assertion-test.com")
            .with_pin_uv_auth(pin_uv_auth);
        let assertion = Client::get_assertion(&mut transport, request).unwrap();

        assert!(!assertion.is_empty());
    }

    #[test]
    #[ignore]
    fn test_update_user_information() {
        let (mut transport, _runner) = setup_transport().unwrap();

        // Create a test credential
        let _cred_id = create_test_credential(&mut transport, "update-test.com", "alice").unwrap();

        // Get PIN/UV auth for credential management
        let pin_uv_auth = get_uv_auth_for_credential_management(&mut transport).unwrap();

        // Enumerate credentials to get the credential ID
        let rp_id_hash = compute_rp_id_hash("update-test.com");
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth.clone()), rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();

        assert_eq!(credentials.len(), 1);
        let credential = &credentials[0];

        // Verify original user information
        assert_eq!(
            credential.user.name.as_ref().unwrap(),
            "alice@update-test.com"
        );
        assert_eq!(credential.user.display_name.as_ref().unwrap(), "alice");

        // Update user information with new name and display name
        let updated_user = User {
            id: credential.user.id.clone(), // Must match existing user ID
            name: Some("alice.smith@update-test.com".to_string()),
            display_name: Some("Alice Smith".to_string()),
        };

        let update_request = soft_fido2::request::UpdateUserRequest::new(
            Some(pin_uv_auth.clone()),
            credential.credential_id.id.clone(),
            updated_user,
        );

        Client::update_user_information(&mut transport, update_request).unwrap();

        // Re-enumerate credentials to verify the update
        let rp_id_hash = compute_rp_id_hash("update-test.com");
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth.clone()), rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();

        assert_eq!(credentials.len(), 1);
        let updated_credential = &credentials[0];

        // Verify updated user information
        assert_eq!(
            updated_credential.user.name.as_ref().unwrap(),
            "alice.smith@update-test.com"
        );
        assert_eq!(
            updated_credential.user.display_name.as_ref().unwrap(),
            "Alice Smith"
        );
        assert_eq!(
            updated_credential.user.id, credential.user.id,
            "User ID should remain unchanged"
        );

        // Clean up - delete the credential
        let delete_request = DeleteCredentialRequest::new(
            Some(pin_uv_auth),
            updated_credential.credential_id.id.clone(),
        );
        Client::delete_credential(&mut transport, delete_request).unwrap();
    }

    #[test]
    #[ignore]
    fn test_update_user_information_with_empty_fields() {
        let (mut transport, _runner) = setup_transport().unwrap();

        // Create a test credential with full user info
        let _cred_id =
            create_test_credential(&mut transport, "empty-fields-test.com", "bob").unwrap();

        // Get PIN/UV auth for credential management
        let pin_uv_auth = get_uv_auth_for_credential_management(&mut transport).unwrap();

        // Enumerate credentials to get the credential ID
        let rp_id_hash = compute_rp_id_hash("empty-fields-test.com");
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth.clone()), rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();

        assert_eq!(credentials.len(), 1);
        let credential = &credentials[0];

        // Update user information with empty name and display name
        // Per spec: empty fields should be removed from the credential
        let updated_user = User {
            id: credential.user.id.clone(),
            name: None,         // Remove name field
            display_name: None, // Remove display name field
        };

        let update_request = soft_fido2::request::UpdateUserRequest::new(
            Some(pin_uv_auth.clone()),
            credential.credential_id.id.clone(),
            updated_user,
        );

        Client::update_user_information(&mut transport, update_request).unwrap();

        // Re-enumerate credentials to verify the update
        let rp_id_hash = compute_rp_id_hash("empty-fields-test.com");
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth.clone()), rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();

        assert_eq!(credentials.len(), 1);
        let updated_credential = &credentials[0];

        // Verify fields were removed
        assert!(
            updated_credential.user.name.is_none(),
            "Name should be removed when updated with None"
        );
        assert!(
            updated_credential.user.display_name.is_none(),
            "Display name should be removed when updated with None"
        );
        assert_eq!(
            updated_credential.user.id, credential.user.id,
            "User ID should remain unchanged"
        );

        // Clean up
        let delete_request = DeleteCredentialRequest::new(
            Some(pin_uv_auth),
            updated_credential.credential_id.id.clone(),
        );
        Client::delete_credential(&mut transport, delete_request).unwrap();
    }

    #[test]
    #[ignore]
    fn test_update_user_information_wrong_user_id() {
        let (mut transport, _runner) = setup_transport().unwrap();

        // Create a test credential
        let _cred_id =
            create_test_credential(&mut transport, "wrong-id-test.com", "carol").unwrap();

        // Get PIN/UV auth for credential management
        let pin_uv_auth = get_uv_auth_for_credential_management(&mut transport).unwrap();

        // Enumerate credentials to get the credential ID
        let rp_id_hash = compute_rp_id_hash("wrong-id-test.com");
        let request = EnumerateCredentialsRequest::new(Some(pin_uv_auth.clone()), rp_id_hash);
        let credentials = Client::enumerate_credentials(&mut transport, request).unwrap();

        assert_eq!(credentials.len(), 1);
        let credential = &credentials[0];

        // Try to update with a different user ID (should fail per spec)
        let wrong_user = User {
            id: vec![9, 9, 9, 9], // Different from original user ID
            name: Some("invalid".to_string()),
            display_name: Some("Invalid".to_string()),
        };

        let update_request = soft_fido2::request::UpdateUserRequest::new(
            Some(pin_uv_auth.clone()),
            credential.credential_id.id.clone(),
            wrong_user,
        );

        // Should return InvalidParameter error (CTAP error 0x02)
        let result = Client::update_user_information(&mut transport, update_request);
        assert!(
            matches!(result, Err(Error::CtapError(0x02))),
            "Should fail with InvalidParameter (0x02) when user ID doesn't match"
        );

        // Clean up
        let delete_request =
            DeleteCredentialRequest::new(Some(pin_uv_auth), credential.credential_id.id.clone());
        Client::delete_credential(&mut transport, delete_request).unwrap();
    }
}
