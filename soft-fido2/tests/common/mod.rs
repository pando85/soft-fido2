//! Common test utilities for soft-fido2 integration tests
//!
//! This module provides shared implementations of test callbacks, constants,
//! and helper functions to reduce code duplication across test files.

#![allow(dead_code)]

use soft_fido2::{AuthenticatorCallbacks, Credential, CredentialRef, Result, UpResult, UvResult};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Standard test callbacks with in-memory credential storage
///
/// Automatically accepts all user presence and verification requests.
#[derive(Clone)]
pub struct TestCallbacks {
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
}

impl TestCallbacks {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get the number of stored credentials
    #[allow(dead_code)]
    pub fn credential_count(&self) -> usize {
        self.credentials.lock().unwrap().len()
    }

    /// Clear all stored credentials
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.credentials.lock().unwrap().clear();
    }
}

impl Default for TestCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthenticatorCallbacks for TestCallbacks {
    fn request_up(&self, _info: &str, _user: Option<&str>, _rp: &str) -> Result<UpResult> {
        Ok(UpResult::Accepted)
    }

    fn request_uv(&self, _info: &str, _user: Option<&str>, _rp: &str) -> Result<UvResult> {
        Ok(UvResult::Accepted)
    }

    fn write_credential(&self, cred: &CredentialRef) -> Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.insert(cred.id.to_vec(), cred.to_owned());
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8]) -> Result<Option<Credential>> {
        let store = self.credentials.lock().unwrap();
        Ok(store.get(cred_id).cloned())
    }

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.remove(cred_id);
        Ok(())
    }

    fn list_credentials(&self, rp_id: &str, _user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        let store = self.credentials.lock().unwrap();
        let filtered: Vec<Credential> = store
            .values()
            .filter(|c| c.rp.id == rp_id)
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
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

    fn credential_count(&self) -> Result<usize> {
        Ok(self.credentials.lock().unwrap().len())
    }
}

/// Test callbacks with verbose logging for debugging
///
/// Same as TestCallbacks but prints debug information for each callback.
pub struct VerboseTestCallbacks {
    inner: TestCallbacks,
}

impl VerboseTestCallbacks {
    pub fn new() -> Self {
        Self {
            inner: TestCallbacks::new(),
        }
    }
}

impl Default for VerboseTestCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthenticatorCallbacks for VerboseTestCallbacks {
    fn request_up(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UpResult> {
        eprintln!(
            "[Callback] request_up: info='{}', user={:?}, rp='{}'",
            info, user, rp
        );
        self.inner.request_up(info, user, rp)
    }

    fn request_uv(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UvResult> {
        eprintln!(
            "[Callback] request_uv: info='{}', user={:?}, rp='{}'",
            info, user, rp
        );
        self.inner.request_uv(info, user, rp)
    }

    fn write_credential(&self, cred: &CredentialRef) -> Result<()> {
        eprintln!(
            "[Callback] write_credential: cred_id={}, user_name={:?}",
            hex::encode(cred.id),
            cred.user_name
        );
        self.inner.write_credential(cred)
    }

    fn read_credential(&self, cred_id: &[u8]) -> Result<Option<Credential>> {
        let result = self.inner.read_credential(cred_id)?;
        eprintln!(
            "[Callback] read_credential: cred_id={}, found={}",
            hex::encode(cred_id),
            result.is_some()
        );
        Ok(result)
    }

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        eprintln!(
            "[Callback] delete_credential: cred_id={}",
            hex::encode(cred_id)
        );
        self.inner.delete_credential(cred_id)
    }

    fn list_credentials(&self, rp_id: &str, user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        let result = self.inner.list_credentials(rp_id, user_id)?;
        eprintln!(
            "[Callback] list_credentials: rp_id='{}', user_id={:?}, count={}",
            rp_id,
            user_id.map(hex::encode),
            result.len()
        );
        Ok(result)
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
        let result = self.inner.enumerate_rps()?;
        eprintln!("[Callback] enumerate_rps: count={}", result.len());
        Ok(result)
    }

    fn credential_count(&self) -> Result<usize> {
        let count = self.inner.credentials.lock().unwrap().len();
        eprintln!("[Callback] credential_count: {}", count);
        Ok(count)
    }
}
