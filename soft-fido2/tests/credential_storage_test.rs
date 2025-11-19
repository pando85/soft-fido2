// Compile with either feature
#![allow(unexpected_cfgs)]
#![cfg(any(feature = "zig-ffi", feature = "pure-rust"))]

//! Test for credential storage and retrieval
//!
//! This tests the full cycle: create credential -> store -> retrieve -> authenticate
//! Works with both zig-ffi and pure-rust implementations

#[cfg(feature = "zig-ffi")]
use soft_fido2::credential::{Credential, Extensions, RelyingParty, User};

#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
use soft_fido2::{Credential, Extensions, RelyingParty, User};

use soft_fido2::Result;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct TestCredentialStore {
    credentials: HashMap<Vec<u8>, Credential>,
}

impl TestCredentialStore {
    fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    fn write(&mut self, cred: Credential) -> Result<()> {
        println!("💾 Storing credential:");
        println!("   User ID: {:?}", cred.user.id);
        println!("   RP ID: {}", cred.rp.id);
        self.credentials.insert(cred.id.clone(), cred);
        Ok(())
    }

    fn read_by_rp(&self, rp_id: &str) -> Option<Credential> {
        println!("📖 Looking for credential with RP: {}", rp_id);
        for cred in self.credentials.values() {
            if cred.rp.id == rp_id {
                println!("   ✅ Found matching credential!");
                return Some(cred.clone());
            }
        }
        println!("   ❌ No matching credential found");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_storage_and_retrieval() {
        println!("\n🧪 Testing Credential Storage and Retrieval");
        println!("============================================\n");

        // Create storage
        let store = Arc::new(Mutex::new(TestCredentialStore::new()));
        let store_clone = Arc::clone(&store);

        // Create a test credential
        let test_cred = Credential {
            id: b"cred_id_12345".to_vec(),
            user: User {
                id: b"test_user_123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
            },
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example Corp".to_string()),
            },
            private_key: vec![0x01; 32], // Private key for ES256
            alg: -7,                     // ES256
            sign_count: 0,
            created: 1234567890,
            discoverable: true,
            extensions: Extensions::default(),
        };

        println!("1️⃣ Creating test credential:");
        println!(
            "   User: {} ({:?})",
            test_cred.user.name.clone().unwrap(),
            test_cred.user.display_name
        );
        println!("   RP: {} ({:?})", test_cred.rp.id, test_cred.rp.name);
        println!("   Credential ID: {:?}", test_cred.id);
        println!();

        // Store the credential
        println!("2️⃣ Storing credential...");
        {
            let mut store = store.lock().unwrap();
            store
                .write(test_cred.clone())
                .expect("Failed to write credential");
        }
        println!("   ✅ Credential stored\n");

        // Retrieve the credential
        println!("3️⃣ Retrieving credential by RP ID...");
        let retrieved_cred = {
            let store = store_clone.lock().unwrap();
            store.read_by_rp("example.com")
        };

        match retrieved_cred {
            Some(cred) => {
                println!("   ✅ Credential retrieved successfully!");
                println!(
                    "   User: {} ({:?})",
                    cred.user.name.clone().unwrap(),
                    cred.user.display_name
                );
                println!("   RP: {} ({:?})", cred.rp.id, cred.rp.name);
                println!();

                // Verify the data matches
                println!("4️⃣ Verifying credential data...");
                assert_eq!(cred.user.id, test_cred.user.id, "User ID mismatch");
                assert_eq!(cred.user.name, test_cred.user.name, "User name mismatch");
                assert_eq!(cred.rp.id, test_cred.rp.id, "RP ID mismatch");
                assert_eq!(cred.id, test_cred.id, "Credential ID mismatch");
                assert_eq!(cred.sign_count, test_cred.sign_count, "Sign count mismatch");
                assert_eq!(cred.alg, test_cred.alg, "Algorithm mismatch");
                println!("   ✅ All fields match!\n");

                // Simulate authentication: increment sign count
                println!("5️⃣ Simulating authentication (incrementing sign count)...");
                let mut auth_cred = cred.clone();
                auth_cred.sign_count += 1;
                println!(
                    "   Sign count: {} -> {}",
                    cred.sign_count, auth_cred.sign_count
                );

                // Store updated credential
                {
                    let mut store = store_clone.lock().unwrap();
                    store
                        .write(auth_cred.clone())
                        .expect("Failed to update credential");
                }
                println!("   ✅ Updated credential stored\n");

                // Verify update
                println!("6️⃣ Verifying sign count was updated...");
                let updated_cred = {
                    let store = store_clone.lock().unwrap();
                    store
                        .read_by_rp("example.com")
                        .expect("Failed to retrieve updated credential")
                };
                assert_eq!(updated_cred.sign_count, 1, "Sign count not updated");
                println!("   ✅ Sign count successfully updated!\n");

                println!(
                    "🎉 All tests passed! Credential storage and retrieval working correctly."
                );
            }
            None => {
                panic!("❌ Failed to retrieve credential!");
            }
        }
    }

    #[test]
    fn test_multiple_credentials() {
        println!("\n🧪 Testing Multiple Credential Storage");
        println!("========================================\n");

        let store = Arc::new(Mutex::new(TestCredentialStore::new()));

        // Create multiple credentials for different RPs
        let creds = [
            Credential {
                id: b"cred1".to_vec(),
                user: User {
                    id: b"user1".to_vec(),
                    name: Some("user1".to_string()),
                    display_name: Some("User One".to_string()),
                },
                rp: RelyingParty {
                    id: "example.com".to_string(),
                    name: Some("Example".to_string()),
                },
                private_key: vec![0x01; 32],
                alg: -7,
                sign_count: 0,
                created: 1000,
                discoverable: true,
                extensions: Extensions::default(),
            },
            Credential {
                id: b"cred2".to_vec(),
                user: User {
                    id: b"user2".to_vec(),
                    name: Some("user2".to_string()),
                    display_name: Some("User Two".to_string()),
                },
                rp: RelyingParty {
                    id: "another.com".to_string(),
                    name: Some("Another".to_string()),
                },
                private_key: vec![0x02; 32],
                alg: -7,
                sign_count: 0,
                created: 2000,
                discoverable: true,
                extensions: Extensions::default(),
            },
            Credential {
                id: b"cred3".to_vec(),
                user: User {
                    id: b"user3".to_vec(),
                    name: Some("user3".to_string()),
                    display_name: Some("User Three".to_string()),
                },
                rp: RelyingParty {
                    id: "example.com".to_string(),
                    name: Some("Example".to_string()),
                },
                private_key: vec![0x03; 32],
                alg: -7,
                sign_count: 0,
                created: 3000,
                discoverable: true,
                extensions: Extensions::default(),
            },
        ];

        println!("1️⃣ Storing {} credentials...", creds.len());
        for (i, cred) in creds.iter().enumerate() {
            println!(
                "   {}. User: {}, RP: {}",
                i + 1,
                cred.user.name.as_ref().unwrap(),
                cred.rp.id
            );
            let mut store = store.lock().unwrap();
            store
                .write(cred.clone())
                .expect("Failed to write credential");
        }
        println!("   ✅ All credentials stored\n");

        println!("2️⃣ Retrieving credentials by RP...");

        // Test retrieval for example.com (should find cred1 or cred3)
        let cred_example = {
            let store = store.lock().unwrap();
            store.read_by_rp("example.com")
        };
        assert!(
            cred_example.is_some(),
            "Should find credential for example.com"
        );
        println!("   ✅ Found credential for example.com");

        // Test retrieval for another.com (should find cred2)
        let cred_another = {
            let store = store.lock().unwrap();
            store.read_by_rp("another.com")
        };
        assert!(
            cred_another.is_some(),
            "Should find credential for another.com"
        );
        println!("   ✅ Found credential for another.com");

        // Test retrieval for non-existent RP
        let cred_none = {
            let store = store.lock().unwrap();
            store.read_by_rp("nonexistent.com")
        };
        assert!(
            cred_none.is_none(),
            "Should not find credential for nonexistent.com"
        );
        println!("   ✅ Correctly returns None for non-existent RP\n");

        println!("🎉 Multiple credential test passed!");
    }
}
