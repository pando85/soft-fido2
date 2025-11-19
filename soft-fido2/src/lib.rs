#![warn(unused_extern_crates)]
#![cfg_attr(not(feature = "std"), no_std)]

//! # soft-fido2
//!
//! A pure Rust FIDO2/WebAuthn CTAP2 implementation providing virtual authenticator
//! capabilities for testing and development.
//!
//! ## no_std Support
//!
//! This crate supports `no_std` environments. To use without the standard library:
//!
//! ```toml
//! [dependencies]
//! soft-fido2 = { version = "0.2", default-features = false }
//! ```
//!
//! **Note**: Transport layers (USB HID, UHID) require `std` and are not available in `no_std`.
//! The core CTAP protocol and authenticator logic work in `no_std` with `alloc`.
//!
//! ## Architecture
//!
//! - **Authenticator**: Virtual FIDO2 authenticator with callback-based user interaction
//! - **Client**: High-level API for communicating with authenticators (requires `std`)
//! - **Transport**: USB HID and Linux UHID transport layers (requires `std`)
//! - **PIN Protocol**: CTAP2 PIN/UV authentication
//!
//! ## Example (with std)
//!
//! ```no_run
//! # #[cfg(feature = "std")]
//! # fn main() -> Result<(), soft_fido2::Error> {
//! use soft_fido2::{TransportList, Client};
//!
//! let mut list = TransportList::enumerate()?;
//! let mut transport = list.get(0).unwrap();
//! transport.open()?;
//!
//! let info = Client::authenticator_get_info(&mut transport)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```

extern crate alloc;

// Core modules (no_std compatible)
pub mod authenticator;
pub mod ctap;
pub mod error;
pub mod options;
pub mod request;
pub mod types;

// Modules that require std
#[cfg(feature = "std")]
pub mod client;
#[cfg(feature = "std")]
pub mod pin;
#[cfg(feature = "std")]
pub mod transport;

#[cfg(all(target_os = "linux", feature = "std"))]
pub mod uhid;

// Re-export main types at root level for convenience
pub use authenticator::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorConfigBuilder,
    UpResult, UvResult,
};
pub use ctap::CtapCommand;
pub use error::{Error, Result};
pub use options::AuthenticatorOptions;
pub use request::{
    ClientDataHash, CredentialDescriptor, CredentialType, GetAssertionRequest,
    MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol,
};
pub use types::{Credential, CredentialRef, Extensions, RelyingParty, User};

// std-only re-exports
#[cfg(feature = "std")]
pub use client::Client;
#[cfg(feature = "std")]
pub use pin::{PinProtocol, PinUvAuthEncapsulation};
#[cfg(feature = "std")]
pub use transport::{Transport, TransportList};

#[cfg(all(target_os = "linux", feature = "std"))]
pub use uhid::Uhid;
