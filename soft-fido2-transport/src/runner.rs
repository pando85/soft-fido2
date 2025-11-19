//! Authenticator Runner
//!
//! High-level interface for running a CTAP authenticator with USB HID transport.
//!
//! This module provides a complete authenticator implementation that handles:
//! - USB device management
//! - HID packet I/O
//! - CTAP HID protocol (message assembly, built-in commands)
//! - Command dispatching to protocol layer
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "usb")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use soft_fido2_transport::{init_usb, enumerate_devices, AuthenticatorRunner, CommandHandler, Cmd};
//!
//! // Create a command handler (implement CommandHandler trait)
//! struct MyHandler;
//! impl CommandHandler for MyHandler {
//!     fn handle_command(&mut self, cmd: Cmd, data: &[u8]) -> Result<Vec<u8>, soft_fido2_transport::Error> {
//!         // Process CTAP command and return response
//!         Ok(vec![0x00]) // Success status
//!     }
//! }
//!
//! // Initialize USB and find devices
//! let api = init_usb()?;
//! let devices = enumerate_devices(&api)?;
//!
//! if let Some(device) = devices.first() {
//!     // Create and run authenticator
//!     let handler = MyHandler;
//!     let mut runner = AuthenticatorRunner::new(&api, &device.path, handler)?;
//!
//!     // Process packets in a loop
//!     loop {
//!         runner.process_one()?;
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "usb")]
use crate::handler::CtapHidHandler;
#[cfg(feature = "usb")]
use crate::usb::UsbTransport;
#[cfg(feature = "usb")]
use crate::{CommandHandler, Error, Result};

/// Authenticator runner with USB HID transport
///
/// Manages the complete authenticator stack from USB I/O to CTAP command processing.
#[cfg(feature = "usb")]
pub struct AuthenticatorRunner<H: CommandHandler> {
    /// USB transport for device I/O
    transport: UsbTransport,

    /// CTAP HID handler for protocol processing
    handler: CtapHidHandler<H>,

    /// Read timeout in milliseconds
    timeout_ms: i32,
}

#[cfg(feature = "usb")]
impl<H: CommandHandler> AuthenticatorRunner<H> {
    /// Create a new authenticator runner
    ///
    /// # Arguments
    ///
    /// * `api` - HID API instance
    /// * `path` - Device path to open
    /// * `command_handler` - Handler for CTAP commands
    pub fn new(api: &hidapi::HidApi, path: &str, command_handler: H) -> Result<Self> {
        let transport = UsbTransport::open(api, path)?;
        let handler = CtapHidHandler::new(command_handler);

        Ok(Self {
            transport,
            handler,
            timeout_ms: 100, // 100ms default timeout
        })
    }

    /// Create a new authenticator runner by vendor/product ID
    pub fn new_by_id(
        api: &hidapi::HidApi,
        vendor_id: u16,
        product_id: u16,
        command_handler: H,
    ) -> Result<Self> {
        let transport = UsbTransport::open_device(api, vendor_id, product_id)?;
        let handler = CtapHidHandler::new(command_handler);

        Ok(Self {
            transport,
            handler,
            timeout_ms: 100,
        })
    }

    /// Set read timeout in milliseconds
    pub fn set_timeout(&mut self, timeout_ms: i32) {
        self.timeout_ms = timeout_ms;
    }

    /// Process one packet
    ///
    /// Reads a packet from USB, processes it through the CTAP HID handler,
    /// and writes any response packets back to USB.
    ///
    /// Returns Ok(true) if a packet was processed, Ok(false) if timeout.
    pub fn process_one(&mut self) -> Result<bool> {
        // Read packet with timeout
        let packet = match self.transport.read_packet_timeout(self.timeout_ms)? {
            Some(p) => p,
            None => return Ok(false), // Timeout
        };

        // Process through CTAP HID handler
        let response_packets = self.handler.process_packet(packet)?;

        // Write response packets to USB
        for response_packet in response_packets {
            self.transport.write_packet(&response_packet)?;
        }

        Ok(true)
    }

    /// Run the authenticator in a loop
    ///
    /// Continuously processes packets until an error occurs or stopped is true.
    /// The `should_stop` callback is called periodically to check if the loop should exit.
    pub fn run<F>(&mut self, mut should_stop: F) -> Result<()>
    where
        F: FnMut() -> bool,
    {
        while !should_stop() {
            match self.process_one() {
                Ok(_) => {
                    // Continue processing
                }
                Err(Error::Timeout) => {
                    // Timeout is normal, continue
                    continue;
                }
                Err(e) => {
                    // Other errors are fatal
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Get a reference to the USB transport
    pub fn transport(&self) -> &UsbTransport {
        &self.transport
    }

    /// Get a reference to the CTAP HID handler
    pub fn handler(&self) -> &CtapHidHandler<H> {
        &self.handler
    }

    /// Get a mutable reference to the CTAP HID handler
    pub fn handler_mut(&mut self) -> &mut CtapHidHandler<H> {
        &mut self.handler
    }
}

#[cfg(all(test, feature = "usb"))]
mod tests {
    use super::*;
    use crate::Cmd;

    struct MockHandler;

    impl CommandHandler for MockHandler {
        fn handle_command(&mut self, _cmd: Cmd, data: &[u8]) -> Result<Vec<u8>> {
            Ok(data.to_vec())
        }
    }

    #[test]
    #[ignore] // Requires actual USB device
    fn test_authenticator_runner() {
        let api = crate::init_usb().unwrap();
        let devices = crate::enumerate_devices(&api).unwrap();

        if devices.is_empty() {
            println!("No devices found, skipping test");
            return;
        }

        let handler = MockHandler;
        let mut runner = AuthenticatorRunner::new(&api, &devices[0].path, handler).unwrap();

        // Process a few packets
        for _ in 0..10 {
            match runner.process_one() {
                Ok(true) => println!("Processed packet"),
                Ok(false) => println!("Timeout"),
                Err(e) => {
                    println!("Error: {:?}", e);
                    break;
                }
            }
        }
    }
}
