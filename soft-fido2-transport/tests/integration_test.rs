//! Integration Tests for CTAP Transport Layer
//!
//! Tests the complete stack integration between crypto, protocol, and transport layers.

use soft_fido2_transport::{ChannelManager, Cmd, CtapHidHandler, Message, Packet};

/// Mock command handler for testing
struct MockCommandHandler;

impl soft_fido2_transport::CommandHandler for MockCommandHandler {
    fn handle_command(&mut self, cmd: Cmd, data: &[u8]) -> soft_fido2_transport::Result<Vec<u8>> {
        match cmd {
            Cmd::Cbor => {
                // Echo the data back (simple test)
                Ok(data.to_vec())
            }
            Cmd::Msg => Err(soft_fido2_transport::Error::Other(
                "MSG not supported".to_string(),
            )),
            _ => Err(soft_fido2_transport::Error::InvalidCommand),
        }
    }
}

#[test]
fn test_channel_manager_basic() {
    let mut manager = ChannelManager::new();

    // Allocate a CID
    let cid = manager.allocate_cid();
    assert!(cid >= 1); // Should not be broadcast CID (0)

    // Create a single-packet message
    let cmd = Cmd::Ping;
    let data = b"test";
    let packets = Packet::new_init(cid, cmd, data).expect("Failed to create packet");

    assert_eq!(packets.len(), 1, "Should be single packet for 4 bytes");

    // Process the packet
    let message = manager
        .process_packet(packets[0].clone())
        .expect("Failed to process packet");

    assert!(message.is_some(), "Should complete in one packet");
    let message = message.unwrap();

    assert_eq!(message.cid, cid);
    assert_eq!(message.cmd, cmd);
    assert_eq!(message.data, data);
}

#[test]
fn test_channel_manager_multi_packet() {
    let mut manager = ChannelManager::new();
    let cid = manager.allocate_cid();

    // Create a multi-packet message (larger than 57 bytes)
    let cmd = Cmd::Cbor;
    let data = vec![0x42; 100]; // 100 bytes
    let packets = Packet::new_init(cid, cmd, &data).expect("Failed to create packets");

    assert!(
        packets.len() > 1,
        "Should be multiple packets for 100 bytes"
    );

    // Process first packet
    let message = manager
        .process_packet(packets[0].clone())
        .expect("Failed to process first packet");
    assert!(message.is_none(), "Should not complete after first packet");

    // Process remaining packets
    for (i, packet) in packets[1..].iter().enumerate() {
        let message = manager
            .process_packet(packet.clone())
            .expect("Failed to process continuation packet");

        if i < packets.len() - 2 {
            assert!(message.is_none(), "Should not complete until last packet");
        } else {
            assert!(message.is_some(), "Should complete on last packet");
            let message = message.unwrap();
            assert_eq!(message.cid, cid);
            assert_eq!(message.cmd, cmd);
            assert_eq!(message.data, data);
        }
    }
}

#[test]
fn test_handler_ping_command() {
    let handler = MockCommandHandler;
    let mut ctaphid_handler = CtapHidHandler::new(handler);

    let cid = 1; // Use CID 1 for testing
    let data = b"ping test";

    // Create PING request
    let packets = Packet::new_init(cid, Cmd::Ping, data).expect("Failed to create packet");

    // Process packet
    let response_packets = ctaphid_handler
        .process_packet(packets[0].clone())
        .expect("Failed to process packet");

    assert!(!response_packets.is_empty(), "Should have response");

    // Reassemble response
    let response_message = Message::from_packets(&response_packets).expect("Failed to reassemble");

    assert_eq!(response_message.cid, cid);
    assert_eq!(response_message.cmd, Cmd::Ping);
    assert_eq!(response_message.data, data);
}

#[test]
fn test_handler_init_command() {
    let handler = MockCommandHandler;
    let mut ctaphid_handler = CtapHidHandler::new(handler);

    // INIT uses broadcast CID
    let broadcast_cid = 0xFFFFFFFF;
    let nonce = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

    // Create INIT request
    let packets =
        Packet::new_init(broadcast_cid, Cmd::Init, &nonce).expect("Failed to create packet");

    // Process packet
    let response_packets = ctaphid_handler
        .process_packet(packets[0].clone())
        .expect("Failed to process packet");

    assert!(!response_packets.is_empty(), "Should have response");

    // Reassemble response
    let response_message = Message::from_packets(&response_packets).expect("Failed to reassemble");

    assert_eq!(response_message.cid, broadcast_cid);
    assert_eq!(response_message.cmd, Cmd::Init);
    assert_eq!(response_message.data.len(), 17); // 8 (nonce) + 4 (CID) + 1 (protocol) + 1 (major) + 1 (minor) + 1 (build) + 1 (capabilities)

    // Verify nonce echoed back
    assert_eq!(&response_message.data[0..8], &nonce);

    // Extract allocated CID (bytes 8-11)
    let allocated_cid = u32::from_be_bytes([
        response_message.data[8],
        response_message.data[9],
        response_message.data[10],
        response_message.data[11],
    ]);

    assert_ne!(allocated_cid, 0, "CID should not be 0");
    assert_ne!(allocated_cid, 0xFFFFFFFF, "CID should not be broadcast");
}

#[test]
fn test_handler_cbor_command() {
    let handler = MockCommandHandler;
    let mut ctaphid_handler = CtapHidHandler::new(handler);

    let cid = 1;
    let data = vec![0x04]; // GetInfo command

    // Create CBOR request
    let packets = Packet::new_init(cid, Cmd::Cbor, &data).expect("Failed to create packet");

    // Process packet
    let response_packets = ctaphid_handler
        .process_packet(packets[0].clone())
        .expect("Failed to process packet");

    assert!(!response_packets.is_empty(), "Should have response");

    // Reassemble response
    let response_message = Message::from_packets(&response_packets).expect("Failed to reassemble");

    assert_eq!(response_message.cid, cid);
    assert_eq!(response_message.cmd, Cmd::Cbor);
    // Mock handler echoes data back
    assert_eq!(response_message.data, data);
}

#[test]
fn test_full_stack_message_round_trip() {
    let handler = MockCommandHandler;
    let mut ctaphid_handler = CtapHidHandler::new(handler);

    // Step 1: Initialize with INIT command
    let broadcast_cid = 0xFFFFFFFF;
    let nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let init_packets =
        Packet::new_init(broadcast_cid, Cmd::Init, &nonce).expect("Failed to create INIT");
    let init_response = ctaphid_handler
        .process_packet(init_packets[0].clone())
        .expect("Failed to process INIT");

    let init_message = Message::from_packets(&init_response).expect("Failed to parse INIT");
    let allocated_cid = u32::from_be_bytes([
        init_message.data[8],
        init_message.data[9],
        init_message.data[10],
        init_message.data[11],
    ]);

    // Step 2: Send PING with allocated CID
    let ping_data = b"Hello, CTAP!";
    let ping_packets =
        Packet::new_init(allocated_cid, Cmd::Ping, ping_data).expect("Failed to create PING");
    let ping_response = ctaphid_handler
        .process_packet(ping_packets[0].clone())
        .expect("Failed to process PING");

    let ping_message = Message::from_packets(&ping_response).expect("Failed to parse PING");
    assert_eq!(ping_message.cid, allocated_cid);
    assert_eq!(ping_message.cmd, Cmd::Ping);
    assert_eq!(ping_message.data, ping_data);

    // Step 3: Send CBOR command
    let cbor_data = vec![0x04]; // GetInfo
    let cbor_packets =
        Packet::new_init(allocated_cid, Cmd::Cbor, &cbor_data).expect("Failed to create CBOR");
    let cbor_response = ctaphid_handler
        .process_packet(cbor_packets[0].clone())
        .expect("Failed to process CBOR");

    let cbor_message = Message::from_packets(&cbor_response).expect("Failed to parse CBOR");
    assert_eq!(cbor_message.cid, allocated_cid);
    assert_eq!(cbor_message.cmd, Cmd::Cbor);
    assert_eq!(cbor_message.data, cbor_data);
}

#[test]
fn test_multiple_channels() {
    let handler = MockCommandHandler;
    let mut ctaphid_handler = CtapHidHandler::new(handler);

    // Allocate two channels
    let nonce1 = [0x11; 8];
    let nonce2 = [0x22; 8];

    // Initialize channel 1
    let init1 = Packet::new_init(0xFFFFFFFF, Cmd::Init, &nonce1).expect("Failed to create INIT 1");
    let response1 = ctaphid_handler
        .process_packet(init1[0].clone())
        .expect("Failed to process INIT 1");
    let msg1 = Message::from_packets(&response1).expect("Failed to parse INIT 1");
    let cid1 = u32::from_be_bytes([msg1.data[8], msg1.data[9], msg1.data[10], msg1.data[11]]);

    // Initialize channel 2
    let init2 = Packet::new_init(0xFFFFFFFF, Cmd::Init, &nonce2).expect("Failed to create INIT 2");
    let response2 = ctaphid_handler
        .process_packet(init2[0].clone())
        .expect("Failed to process INIT 2");
    let msg2 = Message::from_packets(&response2).expect("Failed to parse INIT 2");
    let cid2 = u32::from_be_bytes([msg2.data[8], msg2.data[9], msg2.data[10], msg2.data[11]]);

    // CIDs should be different
    assert_ne!(cid1, cid2);

    // Send messages on both channels
    let data1 = b"Channel 1";
    let data2 = b"Channel 2";

    let ping1 = Packet::new_init(cid1, Cmd::Ping, data1).expect("Failed to create PING 1");
    let ping2 = Packet::new_init(cid2, Cmd::Ping, data2).expect("Failed to create PING 2");

    let resp1 = ctaphid_handler
        .process_packet(ping1[0].clone())
        .expect("Failed to process PING 1");
    let resp2 = ctaphid_handler
        .process_packet(ping2[0].clone())
        .expect("Failed to process PING 2");

    let msg1 = Message::from_packets(&resp1).expect("Failed to parse response 1");
    let msg2 = Message::from_packets(&resp2).expect("Failed to parse response 2");

    assert_eq!(msg1.cid, cid1);
    assert_eq!(msg1.data, data1);
    assert_eq!(msg2.cid, cid2);
    assert_eq!(msg2.data, data2);
}
