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

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Credential,
    CredentialRef, Result, Uhid, UpResult, UvResult,
};

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

    fn write_credential(&self, cred_id: &[u8], _rp_id: &str, cred: &CredentialRef) -> Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.insert(cred_id.to_vec(), cred.to_owned());
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8], _rp_id: &str) -> Result<Option<Credential>> {
        let store = self.credentials.lock().unwrap();
        let result = store.get(cred_id).cloned();
        Ok(result)
    }

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        let mut store = self.credentials.lock().unwrap();
        store.remove(cred_id);
        Ok(())
    }

    fn list_credentials(&self, rp_id: &str, user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        let store = self.credentials.lock().unwrap();
        let filtered: Vec<Credential> = store
            .values()
            .filter(|c| {
                c.rp.id == rp_id && (user_id.is_none() || user_id == Some(c.user.id.as_slice()))
            })
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
        let store = self.credentials.lock().unwrap();
        let mut rp_map: HashMap<String, (Option<String>, usize)> = HashMap::new();

        for cred in store.values() {
            let entry = rp_map
                .entry(cred.rp.id.clone())
                .or_insert((cred.rp.name.clone(), 0));
            entry.1 += 1;
        }

        let result: Vec<(String, Option<String>, usize)> = rp_map
            .into_iter()
            .map(|(rp_id, (rp_name, count))| (rp_id, rp_name, count))
            .collect();

        Ok(result)
    }
    fn credential_count(&self) -> Result<usize> {
        let store = self.credentials.lock().unwrap();
        Ok(store.len())
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
        .with_user_verification(Some(false))
        .with_client_pin(Some(true))
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
                // Handle initialization packets
                if packet.is_init() {
                    current_channel = packet.cid();
                    pending_packets.clear();
                    pending_packets.push(packet);

                    // Check if this is a complete message
                    if let Some(payload_len) = pending_packets[0].payload_len() {
                        let init_data_len = pending_packets[0].payload().len();

                        if init_data_len >= payload_len as usize {
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
                    // Continuation packet
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

                            if received_len >= total_len as usize {
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
    let message = Message::from_packets(packets, None).map_err(|_e| {
        eprintln!("[ERROR] Failed to assemble message from packets");
        soft_fido2::Error::Other
    })?;

    let cid = message.cid;
    let cmd = message.cmd;

    match cmd {
        Cmd::Cbor => {
            // CTAP CBOR command
            response_buffer.clear();
            match auth.handle(&message.data, response_buffer) {
                Ok(_len) => {
                    if !response_buffer.is_empty() {
                        // Show full response for makeCredential to debug issues
                        if !message.data.is_empty() && message.data[0] == 0x01 {}
                    }
                    let response_msg = Message::new(cid, Cmd::Cbor, response_buffer.clone(), None);
                    send_message(uhid, &response_msg)?;
                }
                Err(e) => {
                    eprintln!("[ERROR] CTAP command failed: {:?}", e);
                    let response_msg = Message::new(cid, Cmd::Cbor, vec![0x01], None); // CTAP2_ERR_INVALID_COMMAND
                    send_message(uhid, &response_msg)?;
                }
            }
        }
        Cmd::Init => {
            // CTAP HID INIT - allocate a new channel ID
            if message.data.len() >= 8 {
                // Allocate new channel ID
                let allocated_cid = *next_channel_id;
                *next_channel_id += 1;

                let mut response_data = message.data[..8].to_vec(); // Echo nonce
                response_data.extend_from_slice(&allocated_cid.to_be_bytes()); // NEW channel ID
                response_data.push(2); // CTAP protocol version
                response_data.push(0); // Major device version
                response_data.push(0); // Minor device version
                response_data.push(0); // Build device version

                // Advertise CBOR support without NMSG flag
                let capabilities = 0x04; // CBOR only
                response_data.push(capabilities);

                // Respond on broadcast channel with new CID in payload
                let response_msg = Message::new(0xffffffff, Cmd::Init, response_data, None);
                send_message(uhid, &response_msg)?;
            }
        }
        Cmd::Ping => {
            // Echo ping data
            let response_msg = Message::new(cid, Cmd::Ping, message.data, None);
            send_message(uhid, &response_msg)?;
        }
        Cmd::Msg => {
            // U2F/CTAP1 not supported - return error
            let error_data = vec![0x01]; // ERR_INVALID_CMD
            let response_msg = Message::new(cid, Cmd::Error, error_data, None);
            send_message(uhid, &response_msg)?;
        }
        _ => {
            // Unknown command - return error
            let error_data = vec![0x01]; // ERR_INVALID_CMD
            let response_msg = Message::new(cid, Cmd::Error, error_data, None);
            send_message(uhid, &response_msg)?;
        }
    }

    Ok(())
}

/// Send a CTAP HID message via UHID
fn send_message(uhid: &Uhid, message: &Message) -> Result<()> {
    let packets = message
        .to_packets()
        .map_err(|_e| soft_fido2::Error::Other)?;

    for packet in packets.iter() {
        uhid.write_packet(packet.as_bytes())?;
    }

    Ok(())
}
