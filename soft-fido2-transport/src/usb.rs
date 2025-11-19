//! USB HID Transport
//!
//! Implements CTAP HID over USB using the hidapi library.
//!
//! This module provides device enumeration and communication with FIDO2
//! authenticators over USB HID.

#[cfg(feature = "usb")]
use crate::ctaphid::Packet;
#[cfg(feature = "usb")]
use crate::error::{Error, Result};

#[cfg(feature = "usb")]
use std::ffi::CString;

#[cfg(feature = "usb")]
use hidapi::{HidApi, HidDevice};

/// FIDO2 HID usage page
#[cfg(feature = "usb")]
const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// FIDO2 HID usage
#[cfg(feature = "usb")]
const FIDO_USAGE: u16 = 0x01;

/// USB HID device information
#[cfg(feature = "usb")]
#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    /// Vendor ID
    pub vendor_id: u16,

    /// Product ID
    pub product_id: u16,

    /// Device path (platform-specific)
    pub path: String,

    /// Manufacturer string
    pub manufacturer: Option<String>,

    /// Product string
    pub product: Option<String>,

    /// Serial number
    pub serial_number: Option<String>,
}

/// USB HID transport for CTAP
///
/// Provides communication with FIDO2 authenticators over USB HID.
#[cfg(feature = "usb")]
pub struct UsbTransport {
    /// HID device handle
    device: HidDevice,

    /// Device information
    info: UsbDeviceInfo,
}

#[cfg(feature = "usb")]
impl UsbTransport {
    /// Open a USB HID device by path
    pub fn open(api: &HidApi, path: &str) -> Result<Self> {
        // Convert path to CString for hidapi
        let c_path = CString::new(path)
            .map_err(|e| Error::IoError(format!("Invalid device path: {}", e)))?;

        let device = api
            .open_path(&c_path)
            .map_err(|e| Error::IoError(format!("Failed to open device: {}", e)))?;

        let info = UsbDeviceInfo {
            vendor_id: 0, // Would be populated from device info
            product_id: 0,
            path: path.to_string(),
            manufacturer: None,
            product: None,
            serial_number: None,
        };

        Ok(Self { device, info })
    }

    /// Open a USB HID device by vendor and product ID
    pub fn open_device(api: &HidApi, vendor_id: u16, product_id: u16) -> Result<Self> {
        let device = api
            .open(vendor_id, product_id)
            .map_err(|e| Error::IoError(format!("Failed to open device: {}", e)))?;

        let info = UsbDeviceInfo {
            vendor_id,
            product_id,
            path: String::new(),
            manufacturer: None,
            product: None,
            serial_number: None,
        };

        Ok(Self { device, info })
    }

    /// Write a HID packet to the device
    ///
    /// The packet must be exactly 64 bytes as per CTAP HID spec.
    pub fn write_packet(&self, packet: &Packet) -> Result<()> {
        let data = packet.as_bytes();
        let written = self
            .device
            .write(data)
            .map_err(|e| Error::IoError(format!("Failed to write packet: {}", e)))?;

        if written != data.len() {
            return Err(Error::IoError(format!(
                "Incomplete write: {} of {} bytes",
                written,
                data.len()
            )));
        }

        Ok(())
    }

    /// Read a HID packet from the device
    ///
    /// Blocks until a packet is received or timeout occurs.
    /// Returns a 64-byte packet as per CTAP HID spec.
    pub fn read_packet(&self) -> Result<Packet> {
        let mut buf = [0u8; 64];
        let read = self
            .device
            .read(&mut buf)
            .map_err(|e| Error::IoError(format!("Failed to read packet: {}", e)))?;

        if read != 64 {
            return Err(Error::IoError(format!(
                "Incomplete read: {} bytes (expected 64)",
                read
            )));
        }

        Packet::from_slice(&buf)
    }

    /// Read a HID packet with timeout
    ///
    /// Returns None if timeout expires, Some(Packet) if data received.
    pub fn read_packet_timeout(&self, timeout_ms: i32) -> Result<Option<Packet>> {
        let mut buf = [0u8; 64];
        let read = self
            .device
            .read_timeout(&mut buf, timeout_ms)
            .map_err(|e| Error::IoError(format!("Failed to read packet: {}", e)))?;

        if read == 0 {
            // Timeout
            return Ok(None);
        }

        if read != 64 {
            return Err(Error::IoError(format!(
                "Incomplete read: {} bytes (expected 64)",
                read
            )));
        }

        let packet = Packet::from_slice(&buf)?;
        Ok(Some(packet))
    }

    /// Get device information
    pub fn device_info(&self) -> &UsbDeviceInfo {
        &self.info
    }
}

/// Enumerate FIDO2 USB HID devices
///
/// Returns a list of all connected FIDO2 authenticators.
#[cfg(feature = "usb")]
pub fn enumerate_devices(api: &HidApi) -> Result<Vec<UsbDeviceInfo>> {
    let mut devices = Vec::new();

    for device_info in api.device_list() {
        // Check if this is a FIDO2 device
        if device_info.usage_page() == FIDO_USAGE_PAGE && device_info.usage() == FIDO_USAGE {
            devices.push(UsbDeviceInfo {
                vendor_id: device_info.vendor_id(),
                product_id: device_info.product_id(),
                path: device_info.path().to_string_lossy().to_string(),
                manufacturer: device_info.manufacturer_string().map(|s| s.to_string()),
                product: device_info.product_string().map(|s| s.to_string()),
                serial_number: device_info.serial_number().map(|s| s.to_string()),
            });
        }
    }

    Ok(devices)
}

/// Initialize the HID API
///
/// Must be called before using any USB transport functions.
#[cfg(feature = "usb")]
pub fn init_usb() -> Result<HidApi> {
    HidApi::new().map_err(|e| Error::IoError(format!("Failed to initialize HID API: {}", e)))
}

#[cfg(all(test, feature = "usb"))]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires actual USB device
    fn test_enumerate_devices() {
        let api = init_usb().unwrap();
        let devices = enumerate_devices(&api).unwrap();
        println!("Found {} FIDO2 devices", devices.len());
        for dev in devices {
            println!(
                "  {:04x}:{:04x} - {} {}",
                dev.vendor_id,
                dev.product_id,
                dev.manufacturer.as_deref().unwrap_or("Unknown"),
                dev.product.as_deref().unwrap_or("Unknown")
            );
        }
    }

    #[test]
    #[ignore] // Requires actual USB device
    fn test_packet_roundtrip() {
        use crate::ctaphid::{Cmd, Message};

        let api = init_usb().unwrap();
        let devices = enumerate_devices(&api).unwrap();

        if devices.is_empty() {
            println!("No FIDO2 devices found, skipping test");
            return;
        }

        // Open first device
        let transport = UsbTransport::open(&api, &devices[0].path).unwrap();

        // Send INIT command
        let nonce = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let message = Message::new(0xFFFFFFFF, Cmd::Init, nonce);
        let packets = message.to_packets().unwrap();

        // Write packet
        transport.write_packet(&packets[0]).unwrap();

        // Read response
        let response_packet = transport.read_packet_timeout(1000).unwrap();
        assert!(response_packet.is_some());
    }
}
