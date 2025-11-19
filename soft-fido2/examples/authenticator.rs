//! Virtual FIDO2 Authenticator Example
//!
//! This example creates a virtual FIDO2 authenticator using UHID (Userspace HID).
//! It demonstrates how to:
//! - Set up an authenticator with callbacks
//! - Handle CTAP HID protocol
//! - Process CTAP commands
//! - Store credentials in memory
//!
//! # Prerequisites
//!
//! - Linux with UHID kernel module loaded (`sudo modprobe uhid`)
//! - Proper permissions to access /dev/uhid (user in `fido` group)
//! - Udev rules configured (see DEVELOPMENT.md)
//!
//! # Usage
//! ```bash
//! cargo run --example authenticator
//! ```
//!
//! The authenticator will run until you press Ctrl+C.

use soft_fido2::AuthenticatorOptions;
use soft_fido2::authenticator::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, UpResult, UvResult,
};
use soft_fido2::uhid::Uhid;
use soft_fido2::{Credential, CredentialRef, Result};

use soft_fido2_transport::{Cmd, Message, Packet};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};

const UHID_ERROR_MESSAGE: &str = "Make sure you have the uhid kernel module loaded and proper permissions.\n\
Run the following commands as root:\n\
  modprobe uhid\n\
  groupadd fido 2>/dev/null || true\n\
  usermod -a -G fido $USER\n\
  echo 'KERNEL==\"uhid\", GROUP=\"fido\", MODE=\"0660\"' > /etc/udev/rules.d/90-uinput.rules\n\
  udevadm control --reload-rules && udevadm trigger";

/// Decode CTAP command code to human-readable name
fn ctap_cmd_name(cmd: u8) -> &'static str {
    match cmd {
        0x01 => "authenticatorMakeCredential",
        0x02 => "authenticatorGetAssertion",
        0x04 => "authenticatorGetInfo",
        0x06 => "authenticatorClientPIN",
        0x07 => "authenticatorReset",
        0x08 => "authenticatorGetNextAssertion",
        0x09 => "authenticatorBioEnrollment",
        0x0a => "authenticatorCredentialManagement",
        0x0b => "authenticatorSelection",
        0x0c => "authenticatorLargeBlobs",
        0x0d => "authenticatorConfig",
        _ => "unknown",
    }
}

// PIN configuration - "123456" hashed with SHA-256
fn get_pin_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"123456");
    hasher.finalize().into()
}

/// Simple authenticator callbacks for testing
struct SimpleCallbacks {
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
}

impl SimpleCallbacks {
    fn new() -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl AuthenticatorCallbacks for SimpleCallbacks {
    fn request_up(&self, _info: &str, _user: Option<&str>, _rp: &str) -> Result<UpResult> {
        Ok(UpResult::Accepted)
    }

    fn request_uv(&self, _info: &str, _user: Option<&str>, _rp: &str) -> Result<UvResult> {
        Ok(UvResult::Accepted)
    }

    fn write_credential(&self, cred_id: &[u8], rp_id: &str, cred: &CredentialRef) -> Result<()> {
        eprintln!("[CALLBACK] write_credential: cred_id={:02x?}..., rp_id={}", &cred_id[..cred_id.len().min(8)], rp_id);
        let mut store = self.credentials.lock().unwrap();
        store.insert(cred_id.to_vec(), cred.to_owned());
        eprintln!("[CALLBACK] Credential stored. Total credentials: {}", store.len());
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8], rp_id: &str) -> Result<Option<Credential>> {
        eprintln!("[CALLBACK] read_credential: cred_id={:02x?}..., rp_id={}", &cred_id[..cred_id.len().min(8)], rp_id);
        let store = self.credentials.lock().unwrap();
        let result = store.get(cred_id).cloned();
        eprintln!("[CALLBACK] read_credential result: {}", if result.is_some() { "FOUND" } else { "NOT FOUND" });
        Ok(result)
    }

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        eprintln!("[CALLBACK] delete_credential: cred_id={:02x?}...", &cred_id[..cred_id.len().min(8)]);
        let mut store = self.credentials.lock().unwrap();
        store.remove(cred_id);
        Ok(())
    }

    fn list_credentials(&self, rp_id: &str, user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        eprintln!("[CALLBACK] list_credentials: rp_id={}, user_id={:?}", rp_id, user_id.map(|u| format!("{:02x?}", &u[..u.len().min(8)])));
        let store = self.credentials.lock().unwrap();
        let filtered: Vec<Credential> = store
            .values()
            .filter(|c| {
                c.rp.id == rp_id && (user_id.is_none() || user_id == Some(c.user.id.as_slice()))
            })
            .cloned()
            .collect();
        eprintln!("[CALLBACK] list_credentials returning {} credentials", filtered.len());
        Ok(filtered)
    }
}

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════╗");
    println!("║     Virtual FIDO2 Authenticator                ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Setup PIN
    Authenticator::<SimpleCallbacks>::set_pin_hash(&get_pin_hash());
    println!("[Setup] PIN configured: 123456");

    // Create callbacks
    let callbacks = SimpleCallbacks::new();

    // Configure authenticator
    let aaguid = [
        0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29, 0x7c,
        0x88,
    ];
    let options = AuthenticatorOptions::new()
        .with_user_verification(Some(true))
        .with_credential_management(Some(true));
    let extensions = vec!["credProtect".to_string(), "federationId".to_string()];
    let max_creds = 100;

    let config = AuthenticatorConfig::builder()
        .aaguid(aaguid)
        .max_credentials(max_creds)
        .extensions(extensions.clone())
        .options(options.clone())
        .build();

    println!("[Setup] Creating authenticator...");
    let mut auth = Authenticator::with_config(callbacks, config)?;
    println!("[Setup] ✓ Authenticator created");

    // Open UHID device
    println!("[Setup] Opening UHID device...");
    let uhid = match Uhid::open() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("❌ Failed to open UHID device: {:?}", e);
            eprintln!();
            eprintln!("{}", UHID_ERROR_MESSAGE);
            return Err(e);
        }
    };
    println!("[Setup] ✓ UHID device opened");

    println!();
    println!("╔════════════════════════════════════════════════╗");
    println!("║  Authenticator Ready - Waiting for requests   ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();
    println!("The virtual authenticator is now running.");
    println!("You can connect to it using USB HID transport.");
    println!("Press Ctrl+C to stop.");
    println!();
    eprintln!("[DEBUG] Debug logging enabled - all messages will appear in stderr");
    eprintln!("[DEBUG] Authenticator capabilities:");
    eprintln!("[DEBUG]   - AAGUID: {:02x?}", aaguid);
    eprintln!("[DEBUG]   - PIN configured: yes (123456)");
    eprintln!("[DEBUG]   - User Verification: {:?}", options.uv);
    eprintln!("[DEBUG]   - Credential Management: {:?}", options.cred_mgmt);
    eprintln!("[DEBUG]   - Client PIN: {:?}", options.client_pin);
    eprintln!("[DEBUG]   - Resident Keys: {}", options.rk);
    eprintln!("[DEBUG]   - User Presence: {}", options.up);
    eprintln!("[DEBUG]   - Extensions: {:?}", extensions);
    eprintln!("[DEBUG]   - Max credentials: {}", max_creds);
    eprintln!();

    // CTAP HID state
    let mut current_channel: u32 = 0xffffffff; // Broadcast channel
    let mut next_channel_id: u32 = 1; // Channel ID allocator (starts at 1)
    let mut pending_packets: Vec<Packet> = Vec::new();
    let mut response_buffer = Vec::new();
    let mut buffer = [0u8; 64];

    // Main loop
    loop {
        match uhid.read_packet(&mut buffer) {
            Ok(len) if len > 0 => {
                let packet = Packet::from_bytes(buffer);
                eprintln!(
                    "[DEBUG] Received packet: CID=0x{:08x}, len={}",
                    packet.cid(),
                    len
                );
                eprintln!("[DEBUG] Raw packet data: {:02x?}", &buffer[..len.min(64)]);

                // Handle initialization packets
                if packet.is_init() {
                    current_channel = packet.cid();
                    eprintln!(
                        "[DEBUG] Init packet on channel 0x{:08x}, cmd={:02x}",
                        current_channel, buffer[4]
                    );
                    pending_packets.clear();
                    pending_packets.push(packet);

                    // Check if this is a complete message
                    if let Some(payload_len) = pending_packets[0].payload_len() {
                        let init_data_len = pending_packets[0].payload().len();
                        eprintln!(
                            "[DEBUG] Init packet payload: {} bytes (expected: {})",
                            init_data_len, payload_len
                        );
                        if init_data_len >= payload_len as usize {
                            eprintln!("[DEBUG] Complete message in single packet, processing...");
                            let _ = process_message(
                                &mut auth,
                                &uhid,
                                &pending_packets,
                                &mut response_buffer,
                                &mut next_channel_id,
                            );
                            pending_packets.clear();
                        } else {
                            eprintln!(
                                "[DEBUG] Waiting for {} more bytes in continuation packets",
                                payload_len as usize - init_data_len
                            );
                        }
                    }
                } else {
                    // Continuation packet
                    eprintln!("[DEBUG] Continuation packet: seq={}", buffer[4] & 0x7f);
                    if packet.cid() == current_channel {
                        pending_packets.push(packet);

                        // Check if we have the complete message
                        if let Some(first) = pending_packets.first()
                            && let Some(total_len) = first.payload_len()
                        {
                            let mut received_len = first.payload().len();
                            for pkt in &pending_packets[1..] {
                                received_len += pkt.payload().len();
                            }

                            eprintln!(
                                "[DEBUG] Assembled {} bytes (need {}), packets: {}",
                                received_len,
                                total_len,
                                pending_packets.len()
                            );

                            if received_len >= total_len as usize {
                                eprintln!("[DEBUG] Complete message assembled, processing...");
                                let _ = process_message(
                                    &mut auth,
                                    &uhid,
                                    &pending_packets,
                                    &mut response_buffer,
                                    &mut next_channel_id,
                                );
                                pending_packets.clear();
                            }
                        }
                    } else {
                        eprintln!(
                            "[DEBUG] Continuation packet CID mismatch: got 0x{:08x}, expected 0x{:08x}",
                            packet.cid(),
                            current_channel
                        );
                    }
                }
            }
            Ok(_) => {
                // No data, sleep briefly
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("[ERROR] UHID read error: {:?}", e);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Process a complete CTAP HID message
fn process_message<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    uhid: &Uhid,
    packets: &[Packet],
    response_buffer: &mut Vec<u8>,
    next_channel_id: &mut u32,
) -> Result<()> {
    let message = Message::from_packets(packets).map_err(|_e| {
        eprintln!("[ERROR] Failed to assemble message from packets");
        soft_fido2::Error::Other
    })?;

    let cid = message.cid;
    let cmd = message.cmd;

    eprintln!(
        "[DEBUG] Processing message: CID=0x{:08x}, cmd={:?}, data_len={}",
        cid,
        cmd,
        message.data.len()
    );

    match cmd {
        Cmd::Cbor => {
            // CTAP CBOR command
            eprintln!(
                "[DEBUG] CTAP CBOR command received, data: {} bytes",
                message.data.len()
            );
            if !message.data.is_empty() {
                let cmd_code = message.data[0];
                eprintln!(
                    "[DEBUG] CTAP command: 0x{:02x} ({})",
                    cmd_code,
                    ctap_cmd_name(cmd_code)
                );
                if message.data.len() > 1 {
                    eprintln!(
                        "[DEBUG] CTAP request payload: {:02x?}",
                        &message.data[1..message.data.len().min(33)]
                    );
                }
            }

            response_buffer.clear();
            match auth.handle(&message.data, response_buffer) {
                Ok(len) => {
                    eprintln!("[DEBUG] CTAP command succeeded, response: {} bytes", len);
                    if !response_buffer.is_empty() {
                        eprintln!("[DEBUG] Response status: 0x{:02x}", response_buffer[0]);
                        // Show full response for makeCredential to debug issues
                        if !message.data.is_empty() && message.data[0] == 0x01 {
                            eprintln!("[DEBUG] makeCredential response (full): {:02x?}", &response_buffer[..response_buffer.len().min(128)]);
                        }
                    }
                    let response_msg = Message::new(cid, Cmd::Cbor, response_buffer.clone());
                    send_message(uhid, &response_msg)?;
                }
                Err(e) => {
                    eprintln!("[ERROR] CTAP command failed: {:?}", e);
                    let response_msg = Message::new(cid, Cmd::Cbor, vec![0x01]); // CTAP2_ERR_INVALID_COMMAND
                    send_message(uhid, &response_msg)?;
                }
            }
        }
        Cmd::Init => {
            eprintln!("[DEBUG] CTAP HID INIT command received");
            // CTAP HID INIT - allocate a new channel ID
            if message.data.len() >= 8 {
                // Allocate new channel ID
                let allocated_cid = *next_channel_id;
                *next_channel_id += 1;
                eprintln!("[DEBUG] Allocated new channel ID: 0x{:08x}", allocated_cid);

                let mut response_data = message.data[..8].to_vec(); // Echo nonce
                response_data.extend_from_slice(&allocated_cid.to_be_bytes()); // NEW channel ID
                response_data.push(2); // CTAP protocol version
                response_data.push(0); // Major device version
                response_data.push(0); // Minor device version
                response_data.push(0); // Build device version

                // Advertise CBOR support without NMSG flag
                let capabilities = 0x04; // CBOR only
                response_data.push(capabilities);

                eprintln!(
                    "[DEBUG] Sending INIT response with CID=0x{:08x}, capabilities=0x{:02x}",
                    allocated_cid, capabilities
                );
                // Respond on broadcast channel with new CID in payload
                let response_msg = Message::new(0xffffffff, Cmd::Init, response_data);
                send_message(uhid, &response_msg)?;
            } else {
                eprintln!(
                    "[ERROR] INIT command too short: {} bytes (need 8)",
                    message.data.len()
                );
            }
        }
        Cmd::Ping => {
            eprintln!(
                "[DEBUG] PING command received, echoing {} bytes",
                message.data.len()
            );
            // Echo ping data
            let response_msg = Message::new(cid, Cmd::Ping, message.data);
            send_message(uhid, &response_msg)?;
        }
        Cmd::Msg => {
            eprintln!("[DEBUG] U2F/CTAP1 MSG command not supported");
            // U2F/CTAP1 not supported - return error
            let error_data = vec![0x01]; // ERR_INVALID_CMD
            let response_msg = Message::new(cid, Cmd::Error, error_data);
            send_message(uhid, &response_msg)?;
        }
        _ => {
            eprintln!("[DEBUG] Unknown command: {:?}", cmd);
            // Unknown command - return error
            let error_data = vec![0x01]; // ERR_INVALID_CMD
            let response_msg = Message::new(cid, Cmd::Error, error_data);
            send_message(uhid, &response_msg)?;
        }
    }

    Ok(())
}

/// Send a CTAP HID message via UHID
fn send_message(uhid: &Uhid, message: &Message) -> Result<()> {
    let packets = message.to_packets().map_err(|_e| {
        eprintln!("[ERROR] Failed to convert message to packets");
        soft_fido2::Error::Other
    })?;

    eprintln!(
        "[DEBUG] Sending response: {} packets, total {} bytes",
        packets.len(),
        message.data.len()
    );

    for (i, packet) in packets.iter().enumerate() {
        match uhid.write_packet(packet.as_bytes()) {
            Ok(_) => {
                eprintln!("[DEBUG] Sent packet {}/{}", i + 1, packets.len());
            }
            Err(e) => {
                eprintln!(
                    "[ERROR] Failed to send packet {}/{}: {:?}",
                    i + 1,
                    packets.len(),
                    e
                );
                return Err(e);
            }
        }
    }

    eprintln!("[DEBUG] Response sent successfully");
    Ok(())
}
