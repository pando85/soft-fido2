//! Linux UHID Virtual Device Support
//!
//! Provides UHID (Userspace HID) virtual device support for testing and development.

use crate::error::{Error, Result};

#[cfg(target_os = "linux")]
use soft_fido2_transport::UhidDevice;

/// UHID virtual device wrapper (matches zig-ffi API)
#[cfg(target_os = "linux")]
pub struct Uhid {
    device: UhidDevice,
}

#[cfg(target_os = "linux")]
impl Uhid {
    /// Open a UHID device
    ///
    /// Creates a virtual FIDO2 HID device via Linux UHID interface.
    pub fn open() -> Result<Self> {
        let device = UhidDevice::create_fido_device().map_err(|_| Error::Other)?;
        Ok(Self { device })
    }

    /// Read a 64-byte HID packet
    ///
    /// Returns the number of bytes read (0 if no data available).
    /// Non-blocking: returns immediately if no packet is available.
    pub fn read_packet(&self, out: &mut [u8; 64]) -> Result<usize> {
        match self.device.read_packet(out) {
            Ok(Some(len)) => Ok(len),
            Ok(None) => Ok(0), // No packet available
            Err(_) => Err(Error::Other),
        }
    }

    /// Write a 64-byte HID packet
    ///
    /// Returns the number of bytes written (always 64 on success).
    pub fn write_packet(&self, data: &[u8; 64]) -> Result<usize> {
        self.device.write_packet(data).map_err(|_| Error::Other)?;
        Ok(64) // Return number of bytes written
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires /dev/uhid permissions
    fn test_uhid_creation() {
        // This test requires proper permissions
        // Run with: cargo test -- --ignored
        let _uhid = Uhid::open();
    }
}
