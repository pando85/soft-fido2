//! CTAP HID Protocol Implementation
//!
//! Implements CTAP over USB HID with message fragmentation and reassembly.
//!
//! Packet Format:
//! - Initialization packet: CID(4) + CMD(1) + BCNT(2) + DATA(57)
//! - Continuation packet: CID(4) + SEQ(1) + DATA(59)
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#usb-hid-framing>

use crate::error::{Error, Result};

/// HID packet size (fixed at 64 bytes for USB HID)
pub const PACKET_SIZE: usize = 64;

/// Maximum CTAP message size (7609 bytes)
pub const MAX_MESSAGE_SIZE: usize = 7609;

/// Broadcast channel ID (used for INIT command)
pub const BROADCAST_CID: u32 = 0xFFFFFFFF;

/// Initial packet payload size (64 - 4 CID - 1 CMD - 2 BCNT = 57 bytes)
const INIT_PACKET_DATA_SIZE: usize = 57;

/// Continuation packet payload size (64 - 4 CID - 1 SEQ = 59 bytes)
const CONT_PACKET_DATA_SIZE: usize = 59;

/// CTAP HID commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    /// Transaction that echoes the data back
    Ping = 0x01,

    /// Encapsulated CTAP1/U2F message
    Msg = 0x03,

    /// Place an exclusive lock for one channel
    Lock = 0x04,

    /// Allocate a new CID or synchronize channel
    Init = 0x06,

    /// Request authenticator to provide visual/audible identification
    Wink = 0x08,

    /// Encapsulated CTAP CBOR encoded message
    Cbor = 0x10,

    /// Cancel any outstanding requests on the given CID
    Cancel = 0x11,

    /// The request is still being processed
    Keepalive = 0x3B,

    /// Error response message
    Error = 0x3F,
}

impl Cmd {
    /// Convert from u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x7F {
            // Mask off the TYPE bit
            0x01 => Some(Cmd::Ping),
            0x03 => Some(Cmd::Msg),
            0x04 => Some(Cmd::Lock),
            0x06 => Some(Cmd::Init),
            0x08 => Some(Cmd::Wink),
            0x10 => Some(Cmd::Cbor),
            0x11 => Some(Cmd::Cancel),
            0x3B => Some(Cmd::Keepalive),
            0x3F => Some(Cmd::Error),
            _ => None,
        }
    }

    /// Convert to u8 value with TYPE bit set (0x80 for initialization packet)
    pub fn to_u8_init(self) -> u8 {
        (self as u8) | 0x80
    }

    /// Convert to u8 value
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// CTAP HID error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// Invalid command
    InvalidCmd = 0x01,

    /// Invalid parameter
    InvalidPar = 0x02,

    /// Invalid message length
    InvalidLen = 0x03,

    /// Invalid message sequencing
    InvalidSeq = 0x04,

    /// Message has timed out
    MsgTimeout = 0x05,

    /// Channel busy
    ChannelBusy = 0x06,

    /// Command requires channel lock
    LockRequired = 0x0A,

    /// CID invalid
    InvalidChannel = 0x0B,

    /// Other unspecified error
    Other = 0x7F,
}

impl ErrorCode {
    /// Convert to u8 value
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A single 64-byte HID packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    data: [u8; PACKET_SIZE],
}

impl Packet {
    /// Create a new packet from raw data
    pub fn from_bytes(data: [u8; PACKET_SIZE]) -> Self {
        Self { data }
    }

    /// Create a new packet from a slice (must be exactly 64 bytes)
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        if data.len() != PACKET_SIZE {
            return Err(Error::InvalidPacket);
        }
        let mut packet_data = [0u8; PACKET_SIZE];
        packet_data.copy_from_slice(data);
        Ok(Self { data: packet_data })
    }

    /// Get raw packet data
    pub fn as_bytes(&self) -> &[u8; PACKET_SIZE] {
        &self.data
    }

    /// Get channel ID
    pub fn cid(&self) -> u32 {
        u32::from_be_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    /// Check if this is an initialization packet
    pub fn is_init(&self) -> bool {
        (self.data[4] & 0x80) != 0
    }

    /// Get command (only valid for initialization packets)
    pub fn cmd(&self) -> Option<Cmd> {
        if !self.is_init() {
            return None;
        }
        Cmd::from_u8(self.data[4])
    }

    /// Get payload length (only valid for initialization packets)
    pub fn payload_len(&self) -> Option<u16> {
        if !self.is_init() {
            return None;
        }
        Some(u16::from_be_bytes([self.data[5], self.data[6]]))
    }

    /// Get sequence number (only valid for continuation packets)
    pub fn seq(&self) -> Option<u8> {
        if self.is_init() {
            return None;
        }
        Some(self.data[4])
    }

    /// Get payload data
    pub fn payload(&self) -> &[u8] {
        if self.is_init() {
            &self.data[7..]
        } else {
            &self.data[5..]
        }
    }

    /// Create an initialization packet
    pub fn new_init(cid: u32, cmd: Cmd, data: &[u8]) -> Result<Vec<Self>> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge);
        }

        let mut packets = Vec::new();
        let total_len = data.len() as u16;

        // Create initialization packet
        let mut init_packet = [0u8; PACKET_SIZE];
        init_packet[0..4].copy_from_slice(&cid.to_be_bytes());
        init_packet[4] = cmd.to_u8_init();
        init_packet[5..7].copy_from_slice(&total_len.to_be_bytes());

        let init_data_len = std::cmp::min(data.len(), INIT_PACKET_DATA_SIZE);
        init_packet[7..7 + init_data_len].copy_from_slice(&data[..init_data_len]);

        packets.push(Packet::from_bytes(init_packet));

        // Create continuation packets if needed
        let mut remaining = &data[init_data_len..];
        let mut seq = 0u8;

        while !remaining.is_empty() {
            let mut cont_packet = [0u8; PACKET_SIZE];
            cont_packet[0..4].copy_from_slice(&cid.to_be_bytes());
            cont_packet[4] = seq;

            let cont_data_len = std::cmp::min(remaining.len(), CONT_PACKET_DATA_SIZE);
            cont_packet[5..5 + cont_data_len].copy_from_slice(&remaining[..cont_data_len]);

            packets.push(Packet::from_bytes(cont_packet));

            remaining = &remaining[cont_data_len..];
            seq += 1;

            if seq > 127 {
                // Prevent overflow (max 128 continuation packets)
                return Err(Error::MessageTooLarge);
            }
        }

        Ok(packets)
    }

    /// Create an error packet
    pub fn new_error(cid: u32, error_code: ErrorCode) -> Self {
        let mut packet = [0u8; PACKET_SIZE];
        packet[0..4].copy_from_slice(&cid.to_be_bytes());
        packet[4] = Cmd::Error.to_u8_init();
        packet[5..7].copy_from_slice(&1u16.to_be_bytes()); // Length = 1
        packet[7] = error_code.to_u8();

        Packet::from_bytes(packet)
    }
}

/// A complete CTAP message (reassembled from packets)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Channel ID
    pub cid: u32,

    /// Command
    pub cmd: Cmd,

    /// Payload data
    pub data: Vec<u8>,
}

impl Message {
    /// Create a new message
    pub fn new(cid: u32, cmd: Cmd, data: Vec<u8>) -> Self {
        Self { cid, cmd, data }
    }

    /// Fragment this message into HID packets
    pub fn to_packets(&self) -> Result<Vec<Packet>> {
        Packet::new_init(self.cid, self.cmd, &self.data)
    }

    /// Reassemble a message from HID packets
    pub fn from_packets(packets: &[Packet]) -> Result<Self> {
        if packets.is_empty() {
            return Err(Error::InvalidPacket);
        }

        let init_packet = &packets[0];
        if !init_packet.is_init() {
            return Err(Error::InvalidPacket);
        }

        let cid = init_packet.cid();
        let cmd = init_packet.cmd().ok_or(Error::InvalidCommand)?;
        let total_len = init_packet.payload_len().ok_or(Error::InvalidPacket)? as usize;

        if total_len > MAX_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge);
        }

        // Reassemble data
        let mut data = Vec::with_capacity(total_len);

        // Add initial packet data
        let init_data_len = std::cmp::min(total_len, INIT_PACKET_DATA_SIZE);
        data.extend_from_slice(&init_packet.payload()[..init_data_len]);

        // Add continuation packet data
        let mut remaining = total_len - init_data_len;

        for (expected_seq, packet) in packets[1..].iter().enumerate() {
            if packet.is_init() {
                return Err(Error::InvalidSequence);
            }

            if packet.cid() != cid {
                return Err(Error::InvalidChannel);
            }

            let seq = packet.seq().ok_or(Error::InvalidSequence)?;
            if seq != expected_seq as u8 {
                return Err(Error::InvalidSequence);
            }

            let cont_data_len = std::cmp::min(remaining, CONT_PACKET_DATA_SIZE);
            data.extend_from_slice(&packet.payload()[..cont_data_len]);

            remaining -= cont_data_len;

            if remaining == 0 {
                break;
            }
        }

        if remaining != 0 {
            return Err(Error::FragmentationError);
        }

        Ok(Message { cid, cmd, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_conversion() {
        assert_eq!(Cmd::from_u8(0x01), Some(Cmd::Ping));
        assert_eq!(Cmd::from_u8(0x10), Some(Cmd::Cbor));
        assert_eq!(Cmd::from_u8(0x81), Some(Cmd::Ping)); // With TYPE bit
        assert_eq!(Cmd::from_u8(0xFF), None);

        assert_eq!(Cmd::Ping.to_u8_init(), 0x81);
        assert_eq!(Cmd::Cbor.to_u8(), 0x10);
    }

    #[test]
    fn test_single_packet_message() {
        let data = vec![1, 2, 3, 4, 5];
        let packets = Packet::new_init(0x12345678, Cmd::Ping, &data).unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].cid(), 0x12345678);
        assert_eq!(packets[0].cmd(), Some(Cmd::Ping));
        assert_eq!(packets[0].payload_len(), Some(5));
        assert_eq!(&packets[0].payload()[..5], &data[..]);
    }

    #[test]
    fn test_multi_packet_message() {
        // Create a message that requires continuation packets
        let data = vec![0x42; 100]; // 100 bytes > 57 (init packet size)
        let packets = Packet::new_init(0xABCDEF01, Cmd::Cbor, &data).unwrap();

        // Should need 2 packets: init (57 bytes) + cont (43 bytes)
        assert_eq!(packets.len(), 2);

        // Check init packet
        assert_eq!(packets[0].cid(), 0xABCDEF01);
        assert_eq!(packets[0].cmd(), Some(Cmd::Cbor));
        assert_eq!(packets[0].payload_len(), Some(100));
        assert!(packets[0].is_init());

        // Check continuation packet
        assert_eq!(packets[1].cid(), 0xABCDEF01);
        assert!(!packets[1].is_init());
        assert_eq!(packets[1].seq(), Some(0));
    }

    #[test]
    fn test_message_reassembly() {
        let data = vec![0x55; 150];
        let packets = Packet::new_init(0x11111111, Cmd::Cbor, &data).unwrap();

        let message = Message::from_packets(&packets).unwrap();
        assert_eq!(message.cid, 0x11111111);
        assert_eq!(message.cmd, Cmd::Cbor);
        assert_eq!(message.data, data);
    }

    #[test]
    fn test_message_round_trip() {
        let original = Message::new(0x99999999, Cmd::Ping, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        let packets = original.to_packets().unwrap();
        let reassembled = Message::from_packets(&packets).unwrap();

        assert_eq!(original, reassembled);
    }

    #[test]
    fn test_error_packet() {
        let packet = Packet::new_error(0xDEADBEEF, ErrorCode::InvalidCmd);

        assert_eq!(packet.cid(), 0xDEADBEEF);
        assert_eq!(packet.cmd(), Some(Cmd::Error));
        assert_eq!(packet.payload_len(), Some(1));
        assert_eq!(packet.payload()[0], ErrorCode::InvalidCmd.to_u8());
    }

    #[test]
    fn test_invalid_sequence() {
        let data = vec![0x33; 100];
        let mut packets = Packet::new_init(0x22222222, Cmd::Cbor, &data).unwrap();

        // Corrupt the sequence number
        if packets.len() > 1 {
            let mut corrupted = packets[1].clone();
            corrupted.data[4] = 99; // Invalid sequence
            packets[1] = corrupted;

            let result = Message::from_packets(&packets);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_message_too_large() {
        let data = vec![0x00; MAX_MESSAGE_SIZE + 1];
        let result = Packet::new_init(0x12345678, Cmd::Cbor, &data);
        assert!(result.is_err());
    }

    #[test]
    fn test_broadcast_cid() {
        assert_eq!(BROADCAST_CID, 0xFFFFFFFF);
    }
}
