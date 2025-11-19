//! CTAP HID Channel Management
//!
//! Manages channel IDs (CIDs), message assembly state, and timeouts.
//!
//! Each channel represents an independent communication stream between
//! a client and the authenticator. The broadcast channel (0xFFFFFFFF)
//! is used for INIT commands to allocate new channels.

use crate::ctaphid::{BROADCAST_CID, Message, Packet};
use crate::error::{Error, Result};

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Transaction timeout (500ms per CTAP spec)
const TRANSACTION_TIMEOUT: Duration = Duration::from_millis(500);

/// Channel state for message assembly
#[derive(Debug)]
struct ChannelState {
    /// Partially assembled message
    packets: Vec<Packet>,

    /// Expected total message length
    expected_len: usize,

    /// Bytes received so far
    received_len: usize,

    /// Next expected sequence number
    next_seq: u8,

    /// Transaction start time
    started_at: Instant,
}

impl ChannelState {
    /// Create new channel state from an initialization packet
    fn new(init_packet: Packet) -> Result<Self> {
        let expected_len = init_packet.payload_len().ok_or(Error::InvalidPacket)? as usize;

        let initial_data_len = std::cmp::min(expected_len, 57); // Init packet holds up to 57 bytes

        Ok(Self {
            packets: vec![init_packet],
            expected_len,
            received_len: initial_data_len,
            next_seq: 0,
            started_at: Instant::now(),
        })
    }

    /// Add a continuation packet
    fn add_packet(&mut self, packet: Packet) -> Result<()> {
        // Check timeout
        if self.started_at.elapsed() > TRANSACTION_TIMEOUT {
            return Err(Error::Timeout);
        }

        // Verify sequence number
        let seq = packet.seq().ok_or(Error::InvalidSequence)?;
        if seq != self.next_seq {
            return Err(Error::InvalidSequence);
        }

        // Calculate data length in this packet
        let remaining = self.expected_len - self.received_len;
        let cont_data_len = std::cmp::min(remaining, 59); // Cont packet holds up to 59 bytes

        self.packets.push(packet);
        self.received_len += cont_data_len;
        self.next_seq += 1;

        Ok(())
    }

    /// Check if message is complete
    fn is_complete(&self) -> bool {
        self.received_len >= self.expected_len
    }

    /// Check if transaction has timed out
    fn is_timeout(&self) -> bool {
        self.started_at.elapsed() > TRANSACTION_TIMEOUT
    }

    /// Assemble the complete message
    fn assemble(self) -> Result<Message> {
        Message::from_packets(&self.packets)
    }
}

/// Channel manager for CTAP HID
///
/// Manages multiple concurrent channels, each with independent message assembly.
pub struct ChannelManager {
    /// Active channel states
    channels: HashMap<u32, ChannelState>,

    /// Next CID to allocate (starts at 1, broadcast is 0xFFFFFFFF)
    next_cid: u32,
}

impl ChannelManager {
    /// Create a new channel manager
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            next_cid: 1, // Start from 1, avoid 0 and broadcast
        }
    }

    /// Allocate a new channel ID
    pub fn allocate_cid(&mut self) -> u32 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        // Skip broadcast CID and zero
        if self.next_cid == 0 || self.next_cid == BROADCAST_CID {
            self.next_cid = 1;
        }

        cid
    }

    /// Process an incoming packet
    ///
    /// Returns Some(Message) if a complete message has been assembled,
    /// None if more packets are needed, or Error if the packet is invalid.
    pub fn process_packet(&mut self, packet: Packet) -> Result<Option<Message>> {
        let cid = packet.cid();

        // Clean up timed out channels
        self.cleanup_timeouts();

        if packet.is_init() {
            // Initialization packet starts a new transaction
            // If there's an existing transaction on this CID, it gets aborted
            if self.channels.contains_key(&cid) {
                self.channels.remove(&cid);
            }

            let payload_len = packet.payload_len().ok_or(Error::InvalidPacket)?;

            // Check if this is a single-packet message
            if payload_len as usize <= 57 {
                // Complete message in one packet
                return Ok(Some(Message::from_packets(&[packet])?));
            }

            // Start multi-packet transaction
            let state = ChannelState::new(packet)?;
            self.channels.insert(cid, state);
            Ok(None)
        } else {
            // Continuation packet
            let state = self.channels.get_mut(&cid).ok_or(Error::InvalidChannel)?;

            state.add_packet(packet)?;

            if state.is_complete() {
                // Message is complete
                let state = self.channels.remove(&cid).unwrap();
                Ok(Some(state.assemble()?))
            } else {
                // More packets needed
                Ok(None)
            }
        }
    }

    /// Clean up channels that have timed out
    fn cleanup_timeouts(&mut self) {
        self.channels.retain(|_, state| !state.is_timeout());
    }

    /// Cancel a transaction on a specific channel
    pub fn cancel_channel(&mut self, cid: u32) {
        self.channels.remove(&cid);
    }

    /// Get number of active channels
    pub fn active_channels(&self) -> usize {
        self.channels.len()
    }

    /// Clear all channels
    pub fn clear(&mut self) {
        self.channels.clear();
    }
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctaphid::Cmd;

    #[test]
    fn test_allocate_cid() {
        let mut manager = ChannelManager::new();

        let cid1 = manager.allocate_cid();
        let cid2 = manager.allocate_cid();
        let cid3 = manager.allocate_cid();

        assert_eq!(cid1, 1);
        assert_eq!(cid2, 2);
        assert_eq!(cid3, 3);
        assert_ne!(cid1, cid2);
        assert_ne!(cid2, cid3);
    }

    #[test]
    fn test_single_packet_message() {
        let mut manager = ChannelManager::new();

        let data = vec![1, 2, 3, 4, 5];
        let packets = Packet::new_init(0x12345678, Cmd::Ping, &data).unwrap();

        let result = manager.process_packet(packets[0].clone()).unwrap();
        assert!(result.is_some());

        let message = result.unwrap();
        assert_eq!(message.cid, 0x12345678);
        assert_eq!(message.cmd, Cmd::Ping);
        assert_eq!(message.data, data);
    }

    #[test]
    fn test_multi_packet_message() {
        let mut manager = ChannelManager::new();

        let data = vec![0x42; 100];
        let packets = Packet::new_init(0xABCDEF01, Cmd::Cbor, &data).unwrap();

        // Process init packet
        let result1 = manager.process_packet(packets[0].clone()).unwrap();
        assert!(result1.is_none()); // Not complete yet

        // Process continuation packet
        let result2 = manager.process_packet(packets[1].clone()).unwrap();
        assert!(result2.is_some()); // Complete

        let message = result2.unwrap();
        assert_eq!(message.cid, 0xABCDEF01);
        assert_eq!(message.cmd, Cmd::Cbor);
        assert_eq!(message.data, data);
    }

    #[test]
    fn test_multiple_channels() {
        let mut manager = ChannelManager::new();

        let data1 = vec![0x11; 100];
        let data2 = vec![0x22; 100];

        let packets1 = Packet::new_init(0x11111111, Cmd::Cbor, &data1).unwrap();
        let packets2 = Packet::new_init(0x22222222, Cmd::Cbor, &data2).unwrap();

        // Start both transactions
        let r1 = manager.process_packet(packets1[0].clone()).unwrap();
        assert!(r1.is_none());

        let r2 = manager.process_packet(packets2[0].clone()).unwrap();
        assert!(r2.is_none());

        assert_eq!(manager.active_channels(), 2);

        // Complete first transaction
        let r3 = manager.process_packet(packets1[1].clone()).unwrap();
        assert!(r3.is_some());
        assert_eq!(manager.active_channels(), 1);

        // Complete second transaction
        let r4 = manager.process_packet(packets2[1].clone()).unwrap();
        assert!(r4.is_some());
        assert_eq!(manager.active_channels(), 0);
    }

    #[test]
    fn test_invalid_sequence() {
        let mut manager = ChannelManager::new();

        let data = vec![0x33; 100];
        let packets = Packet::new_init(0x33333333, crate::ctaphid::Cmd::Cbor, &data).unwrap();

        // Process init packet
        let _ = manager.process_packet(packets[0].clone()).unwrap();

        // Create a packet with wrong sequence number by manually constructing it
        let mut wrong_data = [0u8; 64];
        wrong_data[0..4].copy_from_slice(&0x33333333u32.to_be_bytes());
        wrong_data[4] = 5; // Wrong sequence (should be 0)
        // Fill with some dummy data
        wrong_data[5..64].fill(0xFF);
        let wrong_packet = Packet::from_bytes(wrong_data);

        let result = manager.process_packet(wrong_packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_cancel_channel() {
        let mut manager = ChannelManager::new();

        let data = vec![0x44; 100];
        let packets = Packet::new_init(0x44444444, Cmd::Cbor, &data).unwrap();

        // Start transaction
        let _ = manager.process_packet(packets[0].clone()).unwrap();
        assert_eq!(manager.active_channels(), 1);

        // Cancel it
        manager.cancel_channel(0x44444444);
        assert_eq!(manager.active_channels(), 0);

        // Trying to continue should fail
        let result = manager.process_packet(packets[1].clone());
        assert!(result.is_err());
    }

    #[test]
    fn test_abort_by_new_init() {
        let mut manager = ChannelManager::new();

        let data1 = vec![0x55; 100];
        let data2 = vec![0x66; 10];

        let packets1 = Packet::new_init(0x55555555, Cmd::Cbor, &data1).unwrap();
        let packets2 = Packet::new_init(0x55555555, Cmd::Ping, &data2).unwrap();

        // Start first transaction
        let _ = manager.process_packet(packets1[0].clone()).unwrap();
        assert_eq!(manager.active_channels(), 1);

        // Start second transaction on same CID (aborts first)
        let result = manager.process_packet(packets2[0].clone()).unwrap();
        assert!(result.is_some()); // Second message completes immediately

        let message = result.unwrap();
        assert_eq!(message.data, data2); // Got second message, not first
    }

    #[test]
    fn test_cid_wraparound() {
        let mut manager = ChannelManager::new();
        manager.next_cid = 0xFFFFFFFE; // Near wraparound

        let cid1 = manager.allocate_cid();
        let cid2 = manager.allocate_cid(); // This wraps around
        let cid3 = manager.allocate_cid();

        assert_eq!(cid1, 0xFFFFFFFE);
        assert_eq!(cid2, 1); // Skips 0xFFFFFFFF and 0
        assert_eq!(cid3, 2);
    }
}
