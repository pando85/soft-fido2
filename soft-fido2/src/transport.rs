//! CTAP Transport Layer
//!
//! Provides USB HID and Linux UHID transport implementations for CTAP communication.

use crate::error::{Error, Result};

#[cfg(target_os = "linux")]
use soft_fido2_transport::UhidDevice;
use soft_fido2_transport::{ChannelManager, Message, Packet};
#[cfg(feature = "usb")]
use soft_fido2_transport::{UsbTransport as RawUsbTransport, enumerate_devices, init_usb};

use std::sync::{Arc, Mutex};

use smallvec::SmallVec;

/// Safe Rust wrapper for Transport
///
/// Matches the API of the zig-ffi Transport type.
pub struct Transport {
    inner: Arc<Mutex<TransportInner>>,
}

#[allow(dead_code)]
enum TransportInner {
    #[cfg(feature = "usb")]
    Usb {
        transport: RawUsbTransport,
        #[allow(dead_code)]
        channel_manager: ChannelManager,
        channel_id: Option<u32>,
    },
    #[cfg(target_os = "linux")]
    Uhid {
        device: UhidDevice,
        #[allow(dead_code)]
        channel_manager: ChannelManager,
        #[allow(dead_code)]
        opened: bool,
        channel_id: Option<u32>,
    },
}

impl Transport {
    #[cfg(feature = "usb")]
    fn from_usb(transport: RawUsbTransport) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TransportInner::Usb {
                transport,
                channel_manager: ChannelManager::new(),
                channel_id: None,
            })),
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn from_uhid(device: UhidDevice) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TransportInner::Uhid {
                device,
                channel_manager: ChannelManager::new(),
                opened: false,
                channel_id: None,
            })),
        }
    }

    /// Open the transport for communication
    pub fn open(&mut self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        match &mut *inner {
            #[cfg(feature = "usb")]
            TransportInner::Usb { .. } => {
                // USB transports are opened on construction, nothing to do
                Ok(())
            }
            #[cfg(target_os = "linux")]
            TransportInner::Uhid { opened, .. } => {
                // UHID devices are always "open" after creation
                *opened = true;
                Ok(())
            }
            #[cfg(not(any(feature = "usb", target_os = "linux")))]
            _ => Err(Error::Other),
        }
    }

    /// Close the transport
    pub fn close(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        match &mut *inner {
            #[cfg(feature = "usb")]
            TransportInner::Usb { .. } => {
                // USB transports use Drop for cleanup, nothing to do
            }
            #[cfg(target_os = "linux")]
            TransportInner::Uhid { opened, .. } => {
                *opened = false;
            }
            #[cfg(not(any(feature = "usb", target_os = "linux")))]
            _ => {}
        }
    }

    /// Write data to the transport
    ///
    /// This sends raw packets. For CTAP commands, use send_ctap_command instead.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        match &*inner {
            #[cfg(feature = "usb")]
            TransportInner::Usb { transport, .. } => {
                // USB transport expects Packet, convert from raw bytes
                if data.len() != 64 {
                    return Err(Error::Other);
                }
                let mut buf = [0u8; 64];
                buf.copy_from_slice(data);
                let packet = Packet::from_slice(&buf).map_err(|e| Error::IoError(e.to_string()))?;
                transport
                    .write_packet(&packet)
                    .map_err(|e| Error::IoError(e.to_string()))?;
                Ok(())
            }
            #[cfg(target_os = "linux")]
            TransportInner::Uhid { device, .. } => {
                // UHID requires exactly 64 bytes
                if data.len() != 64 {
                    return Err(Error::Other);
                }
                let mut packet = [0u8; 64];
                packet.copy_from_slice(data);
                device
                    .write_packet(&packet)
                    .map_err(|e| Error::IoError(e.to_string()))?;
                Ok(())
            }
            #[cfg(not(any(feature = "usb", target_os = "linux")))]
            _ => Err(Error::Other),
        }
    }

    /// Read data from the transport with timeout
    pub fn read(
        &mut self,
        buffer: &mut [u8],
        #[allow(unused_variables)] timeout_ms: i32,
    ) -> Result<usize> {
        let inner = self.inner.lock().unwrap();
        match &*inner {
            #[cfg(feature = "usb")]
            TransportInner::Usb { transport, .. } => {
                // USB transport uses packet-based API with timeout
                match transport
                    .read_packet_timeout(timeout_ms)
                    .map_err(|e| Error::IoError(e.to_string()))?
                {
                    Some(packet) => {
                        let packet_bytes = packet.as_bytes();
                        let len = packet_bytes.len().min(buffer.len());
                        buffer[..len].copy_from_slice(&packet_bytes[..len]);
                        Ok(len)
                    }
                    None => {
                        // Timeout
                        Ok(0)
                    }
                }
            }
            #[cfg(target_os = "linux")]
            TransportInner::Uhid { device, .. } => {
                // UHID requires exactly 64 bytes buffer
                if buffer.len() < 64 {
                    return Err(Error::Other);
                }
                let mut packet = [0u8; 64];
                // UHID doesn't have timeout, use blocking read
                if let Some(len) = device
                    .read_packet(&mut packet)
                    .map_err(|e| Error::IoError(e.to_string()))?
                {
                    buffer[..len].copy_from_slice(&packet[..len]);
                    Ok(len)
                } else {
                    Ok(0)
                }
            }
            #[cfg(not(any(feature = "usb", target_os = "linux")))]
            _ => Err(Error::Other),
        }
    }

    /// Initialize CTAP HID channel
    ///
    /// Sends an INIT command to allocate a channel ID from the authenticator.
    /// This must be called before sending any CTAP commands.
    ///
    /// Returns the allocated channel ID.
    fn init_channel(&mut self) -> Result<u32> {
        use soft_fido2_transport::Cmd;

        // Generate 8-byte nonce for INIT
        let nonce: [u8; 8] = rand::random();

        // Build INIT message on broadcast channel
        let init_message = Message::new(0xffffffff, Cmd::Init, nonce.to_vec());

        // Fragment into packets
        let packets = init_message.to_packets().map_err(|_| Error::Other)?;

        // Send INIT packets
        for packet in &packets {
            self.write(packet.as_bytes())?;
        }

        // Read INIT response (use SmallVec for stack allocation)
        // INIT responses are small (17 bytes), so we can stack-allocate
        let mut response_packets: SmallVec<[Packet; 4]> = SmallVec::new();

        loop {
            let mut buffer = [0u8; 64];
            let bytes_read = self.read(&mut buffer, 5000)?;

            if bytes_read == 0 {
                return Err(Error::Timeout);
            }

            let packet = Packet::from_bytes(buffer);

            // INIT response should be on broadcast channel
            if packet.cid() != 0xffffffff {
                continue;
            }

            response_packets.push(packet);

            // Check if we have complete response
            if let Some(first) = response_packets.first()
                && let Some(total_len) = first.payload_len()
            {
                let mut received_len = first.payload().len();
                for pkt in &response_packets[1..] {
                    received_len += pkt.payload().len();
                }
                if received_len >= total_len as usize {
                    break;
                }
            }
        }

        // Parse INIT response
        let response_message =
            Message::from_packets(&response_packets).map_err(|_| Error::Other)?;

        // INIT response format:
        // - 8 bytes: nonce (echo)
        // - 4 bytes: channel ID (big-endian)
        // - 1 byte: protocol version
        // - 1 byte: major device version
        // - 1 byte: minor device version
        // - 1 byte: build device version
        // - 1 byte: capabilities

        if response_message.data.len() < 12 {
            return Err(Error::Other);
        }

        // Verify nonce matches
        if response_message.data[0..8] != nonce {
            return Err(Error::Other);
        }

        // Extract channel ID (bytes 8-11, big-endian)
        let channel_id = u32::from_be_bytes([
            response_message.data[8],
            response_message.data[9],
            response_message.data[10],
            response_message.data[11],
        ]);

        Ok(channel_id)
    }

    /// Send a CTAP command and receive response
    ///
    /// This handles CTAP HID framing automatically.
    ///
    /// # Arguments
    /// * `cmd` - CTAP authenticator command (0x01=makeCredential, 0x02=getAssertion, 0x04=getInfo, etc.)
    /// * `data` - CBOR-encoded command parameters
    pub fn send_ctap_command(&mut self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        // Use zero-allocation variant and convert to Vec
        let mut buffer = vec![0u8; 7609]; // Max CTAP response size
        let len = self.send_ctap_command_buf(cmd, data, &mut buffer)?;
        buffer.truncate(len);
        Ok(buffer)
    }

    /// Send a CTAP command and write response to provided buffer (zero-allocation variant)
    ///
    /// This is the zero-allocation version of `send_ctap_command`. The caller provides
    /// a buffer to write the response into, and this method returns the number of bytes written.
    ///
    /// # Arguments
    ///
    /// * `cmd` - CTAP command byte (e.g., 0x01 for makeCredential, 0x02 for getAssertion)
    /// * `data` - CBOR-encoded command parameters
    /// * `response` - Buffer to write the response into (should be at least 7609 bytes for max CTAP response)
    ///
    /// # Returns
    ///
    /// Number of bytes written to the response buffer
    ///
    /// # Errors
    ///
    /// Returns `Error::Other` if the buffer is too small for the response
    pub fn send_ctap_command_buf(
        &mut self,
        cmd: u8,
        data: &[u8],
        response: &mut [u8],
    ) -> Result<usize> {
        use soft_fido2_transport::Cmd;

        // CTAP authenticator commands are sent via CTAP HID Cbor (0x10) command
        // Payload format: [ctap_cmd, ...cbor_data]
        // Use SmallVec: most CTAP requests are <256 bytes (getInfo, PIN ops, etc.)
        let mut payload: SmallVec<[u8; 256]> = SmallVec::new();
        payload.push(cmd);
        payload.extend_from_slice(data);

        let cmd_enum = Cmd::Cbor;

        // Get or allocate channel
        let mut inner = self.inner.lock().unwrap();

        // Initialize channel if needed
        let needs_init = match &*inner {
            #[cfg(feature = "usb")]
            TransportInner::Usb { channel_id, .. } => channel_id.is_none(),
            #[cfg(target_os = "linux")]
            TransportInner::Uhid { channel_id, .. } => channel_id.is_none(),
            #[cfg(not(any(feature = "usb", target_os = "linux")))]
            _ => false,
        };

        if needs_init {
            drop(inner); // Release lock before calling init_channel
            let allocated_channel = self.init_channel()?;
            inner = self.inner.lock().unwrap();

            // Store the allocated channel
            match &mut *inner {
                #[cfg(feature = "usb")]
                TransportInner::Usb { channel_id, .. } => {
                    *channel_id = Some(allocated_channel);
                }
                #[cfg(target_os = "linux")]
                TransportInner::Uhid { channel_id, .. } => {
                    *channel_id = Some(allocated_channel);
                }
                #[cfg(not(any(feature = "usb", target_os = "linux")))]
                _ => {}
            }
        }

        // Get the channel ID to use (all CTAP2 commands use allocated channel)
        let channel_id = match &*inner {
            #[cfg(feature = "usb")]
            TransportInner::Usb { channel_id, .. } => channel_id.ok_or(Error::Other)?,
            #[cfg(target_os = "linux")]
            TransportInner::Uhid { channel_id, .. } => channel_id.ok_or(Error::Other)?,
            #[cfg(not(any(feature = "usb", target_os = "linux")))]
            _ => return Err(Error::Other),
        };

        // Build CTAP HID message (convert SmallVec to Vec for Message API)
        let message = Message::new(channel_id, cmd_enum, payload.to_vec());

        // Fragment into packets
        let packets = message.to_packets().map_err(|_| Error::Other)?;

        // Send packets
        for packet in &packets {
            let packet_bytes = packet.as_bytes();
            drop(inner); // Release lock before write
            self.write(packet_bytes)?;
            inner = self.inner.lock().unwrap();
        }

        // Read response packets (use SmallVec to avoid allocation for small responses)
        // Most CTAP responses are ≤200 bytes (~4 packets), so we can stack-allocate
        let mut response_packets: SmallVec<[Packet; 4]> = SmallVec::new();

        loop {
            drop(inner); // Release lock before read
            let mut buffer = [0u8; 64];
            let bytes_read = self.read(&mut buffer, 5000)?;
            inner = self.inner.lock().unwrap();

            if bytes_read == 0 {
                return Err(Error::Timeout);
            }

            // Parse packet
            let packet = Packet::from_bytes(buffer);

            // Check channel matches
            if packet.cid() != channel_id {
                continue; // Wrong channel, ignore
            }

            // Check for errors
            if let Some(cmd) = packet.cmd()
                && matches!(cmd, Cmd::Error)
            {
                return Err(Error::Other);
            }

            response_packets.push(packet);

            // Check if we have all packets
            if let Some(first) = response_packets.first()
                && let Some(total_len) = first.payload_len()
            {
                let mut received_len = first.payload().len();

                for pkt in &response_packets[1..] {
                    received_len += pkt.payload().len();
                }

                if received_len >= total_len as usize {
                    break;
                }
            }
        }

        // Reassemble message directly into response buffer
        let response_message =
            Message::from_packets(&response_packets).map_err(|_| Error::Other)?;

        let response_len = response_message.data.len();
        if response_len > response.len() {
            return Err(Error::Other); // Buffer too small
        }

        response[..response_len].copy_from_slice(&response_message.data);
        Ok(response_len)
    }

    /// Get a description of the transport
    pub fn get_description(&self) -> Result<String> {
        let inner = self.inner.lock().unwrap();
        match &*inner {
            #[cfg(feature = "usb")]
            TransportInner::Usb { .. } => Ok("USB HID Transport".to_string()),
            #[cfg(target_os = "linux")]
            TransportInner::Uhid { .. } => Ok("UHID Virtual Device".to_string()),
            #[cfg(not(any(feature = "usb", target_os = "linux")))]
            _ => Ok("Unknown Transport".to_string()),
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.close();
    }
}

/// Safe Rust wrapper for TransportList
///
/// Matches the API of the zig-ffi TransportList type.
pub struct TransportList {
    transports: Vec<Transport>,
}

impl TransportList {
    /// Enumerate all available transports
    pub fn enumerate() -> Result<Self> {
        #[allow(unused_mut)]
        let mut transports = Vec::new();

        #[cfg(feature = "usb")]
        {
            // Initialize USB library
            if let Ok(api) = init_usb() {
                // Enumerate USB FIDO devices
                if let Ok(devices) = enumerate_devices(&api) {
                    for device_info in devices {
                        // Open the device using its path
                        if let Ok(transport) = RawUsbTransport::open(&api, &device_info.path) {
                            transports.push(Transport::from_usb(transport));
                        }
                    }
                }
            }
        }

        Ok(TransportList { transports })
    }

    /// Get the number of transports
    pub fn len(&self) -> usize {
        self.transports.len()
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }

    /// Get a transport at the given index
    pub fn get(&self, index: usize) -> Option<Transport> {
        self.transports.get(index).map(|t| Transport {
            inner: Arc::clone(&t.inner),
        })
    }

    /// Iterate over all transports
    pub fn iter(&self) -> impl Iterator<Item = Transport> + '_ {
        self.transports.iter().map(|t| Transport {
            inner: Arc::clone(&t.inner),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_list_enumerate() {
        // Should not panic even if no devices available
        let list = TransportList::enumerate();
        assert!(list.is_ok());
    }
}
