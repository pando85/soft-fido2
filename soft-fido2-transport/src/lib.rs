//! Pure Rust CTAP Transport Layer
//!
//! This crate provides transport implementations for CTAP (Client to Authenticator Protocol):
//! - CTAP HID protocol (message framing, fragmentation, reassembly)
//! - Channel management (CID allocation, message assembly, timeouts)
//! - Command handler abstraction for processing CTAP messages
//! - USB HID transport (via hidapi) - requires "usb" feature
//! - Linux UHID virtual device support (for testing)
//!
//! # Features
//!
//! - `usb`: Enable USB HID transport (requires libudev on Linux)
//! - `uhid`: Enable Linux UHID virtual device support (Linux only)
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#usb>

pub mod channel;
pub mod ctaphid;
pub mod error;
pub mod handler;
#[cfg(feature = "usb")]
pub mod runner;
#[cfg(target_os = "linux")]
pub mod uhid;
#[cfg(feature = "usb")]
pub mod usb;

// Re-export commonly used types
pub use channel::ChannelManager;
pub use ctaphid::{Cmd, Message, Packet};
pub use error::{Error, Result};
pub use handler::{CommandHandler, CtapHidHandler};
#[cfg(feature = "usb")]
pub use runner::AuthenticatorRunner;
#[cfg(target_os = "linux")]
pub use uhid::UhidDevice;
#[cfg(feature = "usb")]
pub use usb::{UsbDeviceInfo, UsbTransport, enumerate_devices, init_usb};
