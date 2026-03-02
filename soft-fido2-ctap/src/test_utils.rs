//! Test utilities for CTAP testing
//!
//! This module provides shared mock implementations for testing purposes.

use crate::callbacks::{
    CredentialStorageCallbacks, PinStorageCallbacks, PlatformCallbacks, UpResult,
    UserInteractionCallbacks, UvResult,
};
use crate::status::StatusCode;
use crate::types::{Credential, PinState};

use alloc::string::String;
use alloc::vec::Vec;

/// Mock callback implementation for testing
///
/// This struct provides no-op implementations of all callback traits,
/// suitable for unit tests that don't require real user interaction
/// or persistent storage.
pub struct MockCallbacks;

impl PlatformCallbacks for MockCallbacks {
    fn get_timestamp_ms(&self) -> u64 {
        0
    }
}

impl UserInteractionCallbacks for MockCallbacks {
    fn request_up(
        &self,
        _info: &str,
        _user_name: Option<&str>,
        _rp_id: &str,
    ) -> Result<UpResult, StatusCode> {
        Ok(UpResult::Accepted)
    }

    fn request_uv(
        &self,
        _info: &str,
        _user_name: Option<&str>,
        _rp_id: &str,
    ) -> Result<UvResult, StatusCode> {
        Ok(UvResult::Accepted)
    }

    fn select_credential(&self, _rp_id: &str, _user_names: &[String]) -> Result<usize, StatusCode> {
        Ok(0)
    }
}

impl CredentialStorageCallbacks for MockCallbacks {
    fn write_credential(&self, _credential: &Credential) -> Result<(), StatusCode> {
        Ok(())
    }

    fn delete_credential(&self, _credential_id: &[u8]) -> Result<(), StatusCode> {
        Ok(())
    }

    fn read_credentials(
        &self,
        _rp_id: &str,
        _user_id: Option<&[u8]>,
    ) -> Result<Vec<Credential>, StatusCode> {
        Ok(Vec::new())
    }

    fn credential_exists(&self, _credential_id: &[u8]) -> Result<bool, StatusCode> {
        Ok(false)
    }

    fn get_credential(&self, _credential_id: &[u8]) -> Result<Credential, StatusCode> {
        Err(StatusCode::NoCredentials)
    }

    fn update_credential(&self, _credential: &Credential) -> Result<(), StatusCode> {
        Ok(())
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>, StatusCode> {
        Ok(Vec::new())
    }

    fn credential_count(&self) -> Result<usize, StatusCode> {
        Ok(0)
    }
}

impl PinStorageCallbacks for MockCallbacks {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        Ok(PinState::new())
    }

    fn save_pin_state(&self, _state: &PinState) -> Result<(), StatusCode> {
        Ok(())
    }
}
