//! Linux UHID Virtual HID Device Support
//!
//! Implements a virtual HID device using the Linux UHID (User-space HID) kernel module.
//! This allows creating virtual FIDO2 authenticators for testing without physical hardware.
//!
//! # Prerequisites
//!
//! - Linux kernel with UHID module loaded (`modprobe uhid`)
//! - Permissions to access `/dev/uhid` (usually requires fido group membership)
//!
//! # Example
//!
//! ```no_run
//! use soft_fido2_transport::uhid::UhidDevice;
//!
//! let device = UhidDevice::create_fido_device()?;
//!
//! // Read HID packets
//! let mut buffer = [0u8; 64];
//! if let Some(len) = device.read_packet(&mut buffer)? {
//!     println!("Received {} bytes", len);
//! }
//!
//! // Write HID packets
//! let packet = [0u8; 64];
//! device.write_packet(&packet)?;
//! # Ok::<(), soft_fido2_transport::Error>(())
//! ```

use crate::{Error, Result};

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

// UHID event types (from linux/uhid.h)
const UHID_CREATE2: u32 = 11;
const UHID_DESTROY: u32 = 1;
const UHID_INPUT2: u32 = 12;
const UHID_OUTPUT: u32 = 6;
const UHID_OPEN: u32 = 2; // Device opened by kernel
const UHID_START: u32 = 4;
#[allow(dead_code)]
const UHID_STOP: u32 = 5;

// Bus types
const BUS_USB: u16 = 0x03;

// FIDO HID constants (for documentation)
#[allow(dead_code)]
const FIDO_USAGE_PAGE: u16 = 0xF1D0;
#[allow(dead_code)]
const FIDO_USAGE: u16 = 0x01;

// HID Report Descriptor for FIDO device (64-byte reports)
const FIDO_HID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F Authenticator Device)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Var, Abs)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Var, Abs)
    0xC0, // End Collection
];

/// UHID CREATE2 event structure
#[repr(C, packed)]
struct UhidCreate2 {
    event_type: u32,
    name: [u8; 128],
    phys: [u8; 64],
    uniq: [u8; 64],
    rd_size: u16,
    bus: u16,
    vendor: u32,
    product: u32,
    version: u32,
    country: u32,
    rd_data: [u8; 4096],
}

impl Default for UhidCreate2 {
    fn default() -> Self {
        Self {
            event_type: UHID_CREATE2,
            name: [0; 128],
            phys: [0; 64],
            uniq: [0; 64],
            rd_size: 0,
            bus: 0,
            vendor: 0,
            product: 0,
            version: 0,
            country: 0,
            rd_data: [0; 4096],
        }
    }
}

/// UHID DESTROY event
#[repr(C, packed)]
struct UhidDestroy {
    event_type: u32,
}

/// UHID INPUT2 event (host -> device)
#[repr(C, packed)]
struct UhidInput2 {
    event_type: u32,
    size: u16,
    data: [u8; 4096],
}

// Note: The kernel uhid_input2_req structure has the size field first,
// then data. This matches our definition.

/// UHID OUTPUT event (device -> host)
/// Matches kernel structure: type (4) + data (4096) + size (2) + rtype (1) = 4103 bytes
#[repr(C, packed)]
struct UhidOutput {
    event_type: u32,
    data: [u8; 4096], // Data comes first in kernel uhid_output_req
    size: u16,
    rtype: u8,
}

/// UHID generic event header
#[repr(C)]
struct UhidEventHeader {
    event_type: u32,
}

/// Virtual UHID HID device
///
/// Creates and manages a virtual HID device through the Linux UHID interface.
pub struct UhidDevice {
    file: File,
    started: bool,
}

impl UhidDevice {
    /// Open the UHID device at `/dev/uhid`
    pub fn open() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/uhid")
            .map_err(|e| Error::Other(format!("Failed to open /dev/uhid: {}", e)))?;

        Ok(Self {
            file,
            started: false,
        })
    }

    /// Create a FIDO2 virtual HID device
    ///
    /// Creates a virtual HID device with FIDO2 usage page and 64-byte reports.
    pub fn create_fido_device() -> Result<Self> {
        let mut device = Self::open()?;
        device.create_device(
            "Virtual FIDO2 Authenticator",
            "virtual-fido",
            "virtual-fido-001",
            BUS_USB,
            0x15d9, // Match Zig implementation (NOT Yubico - browsers recognize Yubico and force U2F)
            0x0a37, // Match Zig implementation
            0x0001, // Version
            FIDO_HID_REPORT_DESCRIPTOR,
        )?;
        Ok(device)
    }

    /// Create a virtual HID device with custom parameters
    #[allow(clippy::too_many_arguments)]
    fn create_device(
        &mut self,
        name: &str,
        phys: &str,
        uniq: &str,
        bus: u16,
        vendor: u32,
        product: u32,
        version: u32,
        report_descriptor: &[u8],
    ) -> Result<()> {
        if report_descriptor.len() > 4096 {
            return Err(Error::Other(
                "Report descriptor too large (max 4096 bytes)".to_string(),
            ));
        }

        let mut event = UhidCreate2::default();

        // Copy name (null-terminated)
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(127);
        event.name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        // Copy phys (null-terminated)
        let phys_bytes = phys.as_bytes();
        let phys_len = phys_bytes.len().min(63);
        event.phys[..phys_len].copy_from_slice(&phys_bytes[..phys_len]);

        // Copy uniq (null-terminated)
        let uniq_bytes = uniq.as_bytes();
        let uniq_len = uniq_bytes.len().min(63);
        event.uniq[..uniq_len].copy_from_slice(&uniq_bytes[..uniq_len]);

        // Set device parameters
        event.bus = bus;
        event.vendor = vendor;
        event.product = product;
        event.version = version;
        event.country = 0;

        // Copy report descriptor
        event.rd_size = report_descriptor.len() as u16;
        event.rd_data[..report_descriptor.len()].copy_from_slice(report_descriptor);

        // Send CREATE2 event
        let event_bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<UhidCreate2>(),
            )
        };

        self.file
            .write_all(event_bytes)
            .map_err(|e| Error::Other(format!("Failed to create UHID device: {}", e)))?;

        // Wait for OPEN or START event indicating device is ready
        self.wait_for_start()?;

        Ok(())
    }

    /// Wait for UHID_START or UHID_OPEN event
    ///
    /// Different kernel versions send different events:
    /// - UHID_OPEN (2): Device opened by kernel (common on newer kernels)
    /// - UHID_START (4): Device started (common on older kernels)
    ///
    /// Both indicate the device is ready to use.
    fn wait_for_start(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; 4096];

        // Try to read events with a timeout (5 second timeout: 50 * 100ms)
        for _i in 0..50 {
            match self.read_event(&mut buffer) {
                Ok(Some(UHID_OPEN)) => {
                    self.started = true;
                    return Ok(());
                }
                Ok(Some(UHID_START)) => {
                    self.started = true;
                    return Ok(());
                }
                Ok(Some(_event_type)) => {
                    // Other event, continue waiting
                    continue;
                }
                Ok(None) => {
                    // No event available, try again
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Err(Error::Timeout)
    }

    /// Read a UHID event and return the event type
    fn read_event(&mut self, buffer: &mut [u8]) -> Result<Option<u32>> {
        // Set non-blocking mode for timeout support
        self.set_nonblocking(true)?;

        match self.file.read(buffer) {
            Ok(n) if n >= 4 => {
                let event_type = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                Ok(Some(event_type))
            }
            Ok(_n) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // This is normal for non-blocking reads
                Ok(None)
            }
            Err(e) => Err(Error::Other(format!("Failed to read UHID event: {}", e))),
        }
    }

    /// Set non-blocking mode on the file descriptor
    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let fd = self.file.as_raw_fd();
        let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL)
            .map_err(|e| Error::Other(format!("Failed to get file flags: {}", e)))?;

        let mut flags = nix::fcntl::OFlag::from_bits_truncate(flags);
        if nonblocking {
            flags.insert(nix::fcntl::OFlag::O_NONBLOCK);
        } else {
            flags.remove(nix::fcntl::OFlag::O_NONBLOCK);
        }

        nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(flags))
            .map_err(|e| Error::Other(format!("Failed to set file flags: {}", e)))?;
        Ok(())
    }

    /// Read a 64-byte HID packet from the device
    ///
    /// Returns `Ok(Some(len))` if a packet was received, `Ok(None)` if timeout.
    pub fn read_packet(&self, buffer: &mut [u8; 64]) -> Result<Option<usize>> {
        if !self.started {
            return Err(Error::Other("Device not started".to_string()));
        }

        // Need 4103 bytes for UhidOutput: event_type(4) + data(4096) + size(2) + rtype(1)
        let mut event_buffer = vec![0u8; 4200];

        // Set non-blocking mode
        self.set_nonblocking(true)?;

        // Try to read an event
        let mut file_ref = &self.file;
        match file_ref.read(&mut event_buffer) {
            Ok(n) if n >= std::mem::size_of::<UhidEventHeader>() => {
                let event_type = u32::from_ne_bytes([
                    event_buffer[0],
                    event_buffer[1],
                    event_buffer[2],
                    event_buffer[3],
                ]);

                match event_type {
                    UHID_OUTPUT => {
                        // Parse OUTPUT event
                        if n >= std::mem::size_of::<UhidOutput>() {
                            let output = unsafe { &*(event_buffer.as_ptr() as *const UhidOutput) };
                            let size = output.size as usize;

                            // UHID prepends a report ID byte (0x00) to HID packets
                            // We need to skip it and only return the 64-byte HID packet
                            if size == 65 && output.data[0] == 0x00 {
                                // Skip report ID, copy actual 64-byte packet
                                buffer[..64].copy_from_slice(&output.data[1..65]);
                                return Ok(Some(64));
                            } else if size <= 64 {
                                // No report ID, copy directly
                                buffer[..size].copy_from_slice(&output.data[..size]);
                                return Ok(Some(size));
                            }
                        }
                        Ok(None)
                    }
                    _ => {
                        // Other event types, skip
                        Ok(None)
                    }
                }
            }
            Ok(_) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(Error::Other(format!("Failed to read packet: {}", e))),
        }
    }

    /// Write a 64-byte HID packet to the device
    pub fn write_packet(&self, data: &[u8; 64]) -> Result<()> {
        if !self.started {
            return Err(Error::Other("Device not started".to_string()));
        }

        let mut event = UhidInput2 {
            event_type: UHID_INPUT2,
            size: 64, // Pure 64-byte HID packet (no report ID)
            data: [0; 4096],
        };

        // Copy 64-byte packet directly (kernel handles report ID internally)
        event.data[..64].copy_from_slice(data);

        let event_bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<UhidInput2>(),
            )
        };

        let mut file_ref = &self.file;
        file_ref
            .write_all(event_bytes)
            .map_err(|e| Error::Other(format!("Failed to write packet: {}", e)))?;

        Ok(())
    }

    /// Get the raw file descriptor
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Check if the device has been started by the kernel
    pub fn is_started(&self) -> bool {
        self.started
    }
}

impl Drop for UhidDevice {
    fn drop(&mut self) {
        // Send DESTROY event
        let event = UhidDestroy {
            event_type: UHID_DESTROY,
        };

        let event_bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<UhidDestroy>(),
            )
        };

        let _ = (&self.file).write_all(event_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires /dev/uhid access
    fn test_create_fido_device() {
        let device = UhidDevice::create_fido_device().unwrap();
        assert!(device.is_started());
    }

    #[test]
    #[ignore] // Requires /dev/uhid access
    fn test_packet_io() {
        let device = UhidDevice::create_fido_device().unwrap();

        // Try to read (should timeout quickly)
        let mut buffer = [0u8; 64];
        let result = device.read_packet(&mut buffer);
        assert!(result.is_ok());

        // Write a packet
        let packet = [0x42u8; 64];
        let result = device.write_packet(&packet);
        assert!(result.is_ok());
    }
}
