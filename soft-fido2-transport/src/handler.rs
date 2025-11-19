//! CTAP HID Message Handler
//!
//! Provides abstractions for processing CTAP HID messages and managing
//! the authenticator state machine.

use crate::channel::ChannelManager;
use crate::ctaphid::{Cmd, ErrorCode, Message, Packet};
use crate::error::Result;

/// Trait for handling CTAP commands
///
/// Implement this trait to process CTAP messages and generate responses.
/// The handler receives the command and data, and returns response data.
pub trait CommandHandler {
    /// Process a CTAP command
    ///
    /// Returns the response data, or an error if the command fails.
    fn handle_command(&mut self, cmd: Cmd, data: &[u8]) -> Result<Vec<u8>>;
}

/// CTAP HID Authenticator Handler
///
/// Manages the complete CTAP HID protocol including:
/// - Message assembly from packets
/// - Command dispatching
/// - Response generation
/// - Channel management
pub struct CtapHidHandler<H: CommandHandler> {
    /// Channel manager for message assembly
    channel_manager: ChannelManager,

    /// Command handler for processing CTAP commands
    command_handler: H,
}

impl<H: CommandHandler> CtapHidHandler<H> {
    /// Create a new CTAP HID handler
    pub fn new(command_handler: H) -> Self {
        Self {
            channel_manager: ChannelManager::new(),
            command_handler,
        }
    }

    /// Process a single HID packet
    ///
    /// Returns response packets if a complete message was assembled and processed.
    pub fn process_packet(&mut self, packet: Packet) -> Result<Vec<Packet>> {
        // Try to assemble a complete message
        match self.channel_manager.process_packet(packet.clone()) {
            Ok(Some(message)) => {
                // Got a complete message, process it
                self.process_message(message)
            }
            Ok(None) => {
                // Need more packets
                Ok(vec![])
            }
            Err(e) => {
                // Error during assembly, send error response
                let error_code = match e {
                    crate::error::Error::InvalidSequence => ErrorCode::InvalidSeq,
                    crate::error::Error::InvalidChannel => ErrorCode::InvalidChannel,
                    crate::error::Error::MessageTooLarge => ErrorCode::InvalidLen,
                    crate::error::Error::Timeout => ErrorCode::MsgTimeout,
                    _ => ErrorCode::Other,
                };

                Ok(vec![Packet::new_error(packet.cid(), error_code)])
            }
        }
    }

    /// Process a complete CTAP message
    fn process_message(&mut self, message: Message) -> Result<Vec<Packet>> {
        match message.cmd {
            Cmd::Ping => {
                // Echo the data back
                let response = Message::new(message.cid, Cmd::Ping, message.data);
                response.to_packets()
            }
            Cmd::Init => {
                // Allocate a new CID
                let new_cid = self.channel_manager.allocate_cid();

                // INIT response format:
                // - nonce (8 bytes) - echo from request
                // - new CID (4 bytes)
                // - protocol version (1 byte)
                // - major device version (1 byte)
                // - minor device version (1 byte)
                // - build device version (1 byte)
                // - capabilities (1 byte)

                let mut response_data = Vec::new();

                // Echo nonce (first 8 bytes of request)
                if message.data.len() >= 8 {
                    response_data.extend_from_slice(&message.data[..8]);
                } else {
                    // If nonce is too short, pad with zeros
                    response_data.extend_from_slice(&message.data);
                    response_data.resize(8, 0);
                }

                // New CID
                response_data.extend_from_slice(&new_cid.to_be_bytes());

                // Protocol version (CTAP HID version 2)
                response_data.push(2);

                // Device version (major.minor.build = 1.0.0)
                response_data.push(1); // Major
                response_data.push(0); // Minor
                response_data.push(0); // Build

                // Capabilities: CBOR (0x04) + WINK (0x01) = 0x05
                response_data.push(0x05);

                let response = Message::new(message.cid, Cmd::Init, response_data);
                response.to_packets()
            }
            Cmd::Wink => {
                // Simple wink acknowledgment (no data)
                let response = Message::new(message.cid, Cmd::Wink, vec![]);
                response.to_packets()
            }
            Cmd::Cancel => {
                // Cancel transaction on this channel
                self.channel_manager.cancel_channel(message.cid);
                // No response for cancel
                Ok(vec![])
            }
            Cmd::Cbor | Cmd::Msg => {
                // Dispatch to command handler
                match self
                    .command_handler
                    .handle_command(message.cmd, &message.data)
                {
                    Ok(response_data) => {
                        let response = Message::new(message.cid, message.cmd, response_data);
                        response.to_packets()
                    }
                    Err(_e) => {
                        // Command handler error
                        Ok(vec![Packet::new_error(message.cid, ErrorCode::Other)])
                    }
                }
            }
            Cmd::Lock | Cmd::Keepalive | Cmd::Error => {
                // These are handled internally or are responses
                Ok(vec![Packet::new_error(message.cid, ErrorCode::InvalidCmd)])
            }
        }
    }

    /// Get a reference to the channel manager
    pub fn channel_manager(&self) -> &ChannelManager {
        &self.channel_manager
    }

    /// Get a mutable reference to the channel manager
    pub fn channel_manager_mut(&mut self) -> &mut ChannelManager {
        &mut self.channel_manager
    }

    /// Get a reference to the command handler
    pub fn command_handler(&self) -> &H {
        &self.command_handler
    }

    /// Get a mutable reference to the command handler
    pub fn command_handler_mut(&mut self) -> &mut H {
        &mut self.command_handler
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock command handler for testing
    struct MockHandler;

    impl CommandHandler for MockHandler {
        fn handle_command(&mut self, _cmd: Cmd, data: &[u8]) -> Result<Vec<u8>> {
            // Echo the data back
            Ok(data.to_vec())
        }
    }

    #[test]
    fn test_ping_command() {
        let handler = MockHandler;
        let mut ctap_handler = CtapHidHandler::new(handler);

        let data = vec![1, 2, 3, 4, 5];
        let message = Message::new(0x12345678, Cmd::Ping, data.clone());
        let packets = message.to_packets().unwrap();

        // Process the packet
        let response_packets = ctap_handler.process_packet(packets[0].clone()).unwrap();

        assert!(!response_packets.is_empty());

        // Reassemble response
        let response = Message::from_packets(&response_packets).unwrap();
        assert_eq!(response.cmd, Cmd::Ping);
        assert_eq!(response.data, data);
    }

    #[test]
    fn test_init_command() {
        let handler = MockHandler;
        let mut ctap_handler = CtapHidHandler::new(handler);

        // INIT with 8-byte nonce
        let nonce = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let message = Message::new(0xFFFFFFFF, Cmd::Init, nonce.clone());
        let packets = message.to_packets().unwrap();

        // Process the packet
        let response_packets = ctap_handler.process_packet(packets[0].clone()).unwrap();

        assert!(!response_packets.is_empty());

        // Reassemble response
        let response = Message::from_packets(&response_packets).unwrap();
        assert_eq!(response.cmd, Cmd::Init);

        // Check response format
        assert_eq!(&response.data[..8], &nonce[..]); // Nonce echoed
        assert_eq!(response.data.len(), 17); // nonce(8) + cid(4) + version(1) + device(3) + caps(1)
    }

    #[test]
    fn test_cbor_command() {
        let handler = MockHandler;
        let mut ctap_handler = CtapHidHandler::new(handler);

        let data = vec![0xA1, 0x01, 0x02]; // Some CBOR data
        let message = Message::new(0x99999999, Cmd::Cbor, data.clone());
        let packets = message.to_packets().unwrap();

        // Process the packet
        let response_packets = ctap_handler.process_packet(packets[0].clone()).unwrap();

        assert!(!response_packets.is_empty());

        // Reassemble response
        let response = Message::from_packets(&response_packets).unwrap();
        assert_eq!(response.cmd, Cmd::Cbor);
        assert_eq!(response.data, data); // MockHandler echoes data
    }

    #[test]
    fn test_multi_packet_message() {
        let handler = MockHandler;
        let mut ctap_handler = CtapHidHandler::new(handler);

        // Large message requiring multiple packets
        let data = vec![0x42; 100];
        let message = Message::new(0xABCDEF01, Cmd::Cbor, data.clone());
        let packets = message.to_packets().unwrap();

        assert!(packets.len() > 1); // Should be fragmented

        // Process first packet - should return empty (need more packets)
        let response1 = ctap_handler.process_packet(packets[0].clone()).unwrap();
        assert!(response1.is_empty());

        // Process second packet - should return response
        let response2 = ctap_handler.process_packet(packets[1].clone()).unwrap();
        assert!(!response2.is_empty());

        // Reassemble response
        let response = Message::from_packets(&response2).unwrap();
        assert_eq!(response.data, data);
    }

    #[test]
    fn test_wink_command() {
        let handler = MockHandler;
        let mut ctap_handler = CtapHidHandler::new(handler);

        let message = Message::new(0x77777777, Cmd::Wink, vec![]);
        let packets = message.to_packets().unwrap();

        // Process the packet
        let response_packets = ctap_handler.process_packet(packets[0].clone()).unwrap();

        assert!(!response_packets.is_empty());

        // Reassemble response
        let response = Message::from_packets(&response_packets).unwrap();
        assert_eq!(response.cmd, Cmd::Wink);
        assert!(response.data.is_empty());
    }

    #[test]
    fn test_cancel_command() {
        let handler = MockHandler;
        let mut ctap_handler = CtapHidHandler::new(handler);

        // Start a multi-packet transaction
        let data = vec![0x55; 100];
        let message = Message::new(0x88888888, Cmd::Cbor, data);
        let packets = message.to_packets().unwrap();

        // Process first packet
        let _ = ctap_handler.process_packet(packets[0].clone()).unwrap();

        // Send cancel
        let cancel = Message::new(0x88888888, Cmd::Cancel, vec![]);
        let cancel_packets = cancel.to_packets().unwrap();
        let response = ctap_handler
            .process_packet(cancel_packets[0].clone())
            .unwrap();

        // Cancel has no response
        assert!(response.is_empty());

        // Trying to continue the original transaction should fail
        let response2 = ctap_handler.process_packet(packets[1].clone());
        assert!(response2.is_err() || response2.unwrap()[0].cmd() == Some(Cmd::Error));
    }
}
