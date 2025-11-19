//! Pure Rust cryptographic primitives for FIDO2/CTAP
//!
//! This crate provides the cryptographic operations required by the CTAP protocol:
//!
//! - **ECDH**: P-256 key agreement for PIN protocol
//! - **ECDSA**: ES256 signatures for attestation and assertions
//! - **PIN Protocols**: V1 (AES-256-CBC + HMAC) and V2 (HMAC-only)
//!
//! All implementations follow the FIDO2 specification:
//! <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html>

#![cfg_attr(not(feature = "std"), no_std)]

pub mod ecdh;
pub mod ecdsa;
pub mod error;
pub mod pin_protocol;

// Re-export commonly used types
pub use error::{CryptoError, Result};
