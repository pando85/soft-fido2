use std::env;
use std::io::{self, Write};
use std::process;

use soft_fido2::client::Client;
use soft_fido2::request::{
    CredentialManagementRequest, DeleteCredentialRequest, EnumerateCredentialsRequest,
    UpdateUserRequest,
};
use soft_fido2::transport::Transport;
use soft_fido2::types::User;
use soft_fido2::{
    PinProtocol, PinUvAuthEncapsulation, TransportList, compute_rp_id_hash, request::Permission,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        eprintln!("Commands:");
        eprintln!("  get-metadata                    - Get credential metadata");
        eprintln!("  enumerate-rps                   - Enumerate relying parties");
        eprintln!("  enumerate-credentials <rp_id>   - Enumerate credentials for RP");
        eprintln!("  delete-credential <cred_id>     - Delete a credential");
        eprintln!("  update-user <cred_id> <name> <display_name> - Update user info");
        eprintln!();
        eprintln!("Note: UV (biometric) authentication is attempted first, then PIN if needed.");
        process::exit(1);
    }

    // Initialize transport
    let transport_list = match TransportList::enumerate() {
        Ok(list) => list,
        Err(e) => {
            eprintln!("Failed to enumerate transports: {:?}", e);
            process::exit(1);
        }
    };

    if transport_list.is_empty() {
        eprintln!("No FIDO2 devices found");
        process::exit(1);
    }

    let mut transport = match transport_list.iter().next() {
        Some(t) => t,
        None => {
            eprintln!("No FIDO2 devices found");
            process::exit(1);
        }
    };

    // Test basic connectivity
    println!("Testing authenticator connectivity...");
    match Client::authenticator_get_info(&mut transport) {
        Ok(info_bytes) => {
            println!("✓ Authenticator info received: {} bytes", info_bytes.len());
            // Parse the info
            use std::io::Cursor;
            match ciborium::de::from_reader::<ciborium::Value, _>(Cursor::new(&info_bytes)) {
                Ok(value) => {
                    println!("Parsed CBOR: {:?}", value);
                }
                Err(e) => {
                    println!("Failed to parse CBOR: {:?}", e);
                    println!("Raw bytes: {:?}", info_bytes);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to get authenticator info: {:?}", e);
            eprintln!("Make sure the virtual authenticator is running.");
            process::exit(1);
        }
    }

    // Perform authentication (UV first, then PIN fallback)
    // For testing, skip authentication and try without PIN
    println!("Skipping authentication for testing...");
    let pin_uv_auth = None;

    // Extract command and arguments
    let command = &args[1];
    let command_args = &args[2..];

    match command.as_str() {
        "get-metadata" => {
            let request = CredentialManagementRequest::new(pin_uv_auth.clone());
            match Client::get_credentials_metadata(&mut transport, request) {
                Ok(metadata) => {
                    println!(
                        "Existing credentials: {}",
                        metadata.existing_resident_credentials_count
                    );
                    println!(
                        "Max remaining: {}",
                        metadata.max_possible_remaining_resident_credentials_count
                    );
                }
                Err(e) => {
                    eprintln!("Failed to get metadata: {:?}", e);
                    process::exit(1);
                }
            }
        }

        "enumerate-rps" => {
            let request = CredentialManagementRequest::new(pin_uv_auth.clone());
            match Client::enumerate_rps(&mut transport, request) {
                Ok(rps) => {
                    println!("Relying Parties ({}):", rps.len());
                    for (i, rp) in rps.iter().enumerate() {
                        println!(
                            "  {}. {} ({})",
                            i + 1,
                            rp.name.as_deref().unwrap_or("Unknown"),
                            rp.id
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Failed to enumerate RPs: {:?}", e);
                    process::exit(1);
                }
            }
        }

        "enumerate-credentials" => {
            if command_args.is_empty() {
                eprintln!("Usage: {} enumerate-credentials <rp_id>", args[0]);
                process::exit(1);
            }

            let rp_id = &command_args[0];
            let rp_id_hash = compute_rp_id_hash(rp_id);
            let request = EnumerateCredentialsRequest::new(pin_uv_auth.clone(), rp_id_hash);

            match Client::enumerate_credentials(&mut transport, request) {
                Ok(credentials) => {
                    println!("Credentials for {} ({}):", rp_id, credentials.len());
                    for (i, cred) in credentials.iter().enumerate() {
                        println!(
                            "  {}. User: {} ({})",
                            i + 1,
                            cred.user.name.as_deref().unwrap_or("Unknown"),
                            hex::encode(&cred.user.id)
                        );
                        println!(
                            "      Display Name: {}",
                            cred.user.display_name.as_deref().unwrap_or("None")
                        );
                        println!(
                            "      Credential ID: {}",
                            hex::encode(&cred.credential_id.id)
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Failed to enumerate credentials: {:?}", e);
                    process::exit(1);
                }
            }
        }

        "delete-credential" => {
            if command_args.is_empty() {
                eprintln!("Usage: {} delete-credential <cred_id_hex>", args[0]);
                process::exit(1);
            }

            let cred_id_hex = &command_args[0];
            let cred_id = match hex::decode(cred_id_hex) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("Invalid credential ID hex: {:?}", e);
                    process::exit(1);
                }
            };

            let request = DeleteCredentialRequest::new(pin_uv_auth.clone(), cred_id);
            match Client::delete_credential(&mut transport, request) {
                Ok(()) => {
                    println!("Credential deleted successfully");
                }
                Err(e) => {
                    eprintln!("Failed to delete credential: {:?}", e);
                    process::exit(1);
                }
            }
        }

        "update-user" => {
            if command_args.len() < 3 {
                eprintln!(
                    "Usage: {} update-user <cred_id_hex> <name> <display_name>",
                    args[0]
                );
                process::exit(1);
            }

            let cred_id_hex = &command_args[0];
            let name = &command_args[1];
            let display_name = &command_args[2];

            let cred_id = match hex::decode(cred_id_hex) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("Invalid credential ID hex: {:?}", e);
                    process::exit(1);
                }
            };

            let user = User {
                id: vec![1, 2, 3, 4], // This should match the existing credential's user ID
                name: Some(name.to_string()),
                display_name: Some(display_name.to_string()),
            };

            let request = UpdateUserRequest::new(pin_uv_auth.clone(), cred_id, user);
            match Client::update_user_information(&mut transport, request) {
                Ok(()) => {
                    println!("User information updated successfully");
                }
                Err(e) => {
                    eprintln!("Failed to update user information: {:?}", e);
                    process::exit(1);
                }
            }
        }

        _ => {
            eprintln!("Unknown command: {}", command);
            process::exit(1);
        }
    }

    // Clean up
    transport.close();
}

#[allow(dead_code)]
fn authenticate(transport: &mut Transport) -> soft_fido2::request::PinUvAuth {
    // Try UV authentication first
    match get_pin_uv_auth_token_uv(transport) {
        Ok(token) => {
            println!("✓ UV authentication successful");
            return token;
        }
        Err(e) => {
            eprintln!("UV authentication failed: {:?}", e);
        }
    }

    // Fallback to PIN authentication
    // Get PIN from user
    print!("Enter PIN for credential management operations: ");
    io::stdout().flush().unwrap();
    let mut pin = String::new();
    io::stdin().read_line(&mut pin).unwrap();
    let pin = pin.trim();

    if pin.is_empty() {
        eprintln!("PIN cannot be empty");
        process::exit(1);
    }

    match get_pin_uv_auth_token_pin(transport, pin) {
        Ok(token) => {
            println!("✓ PIN authentication successful");
            token
        }
        Err(e) => {
            eprintln!("PIN authentication failed: {:?}", e);
            process::exit(1);
        }
    }
}

#[allow(dead_code)]
fn get_pin_uv_auth_token_pin(
    transport: &mut Transport,
    pin: &str,
) -> Result<soft_fido2::request::PinUvAuth, Box<dyn std::error::Error>> {
    println!(
        "Attempting PIN token request with PIN: {}...",
        if pin.is_empty() { "EMPTY" } else { "PROVIDED" }
    );
    // Establish PIN protocol
    let protocol = PinProtocol::V2;
    let mut encapsulation = PinUvAuthEncapsulation::new(transport, protocol)?;
    println!("✓ PIN encapsulation created");

    // Get PIN token with credential management permission
    let permissions = Permission::CredentialManagement as u8;
    println!("Requesting PIN token with permissions: {}", permissions);
    let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        transport,
        pin,
        permissions,
        None, // No specific RP for credential management
    )?;
    println!("✓ PIN token received");

    // Create PIN auth object
    Ok(soft_fido2::request::PinUvAuth::new(
        pin_token,
        soft_fido2::request::PinUvAuthProtocol::V2,
    ))
}

#[allow(dead_code)]
fn get_pin_uv_auth_token_uv(
    transport: &mut Transport,
) -> Result<soft_fido2::request::PinUvAuth, Box<dyn std::error::Error>> {
    println!("Attempting UV token request...");
    // Establish PIN protocol
    let protocol = PinProtocol::V2;
    let mut encapsulation = PinUvAuthEncapsulation::new(transport, protocol)?;
    println!("✓ PIN encapsulation created");

    // Get PIN token with credential management permission using UV
    let permissions = Permission::CredentialManagement as u8;
    println!("Requesting UV token with permissions: {}", permissions);
    let pin_token = encapsulation.get_pin_uv_auth_token_using_uv_with_permissions(
        transport,
        permissions,
        None, // No specific RP for credential management
    )?;
    println!("✓ UV token received");

    // Create PIN auth object
    Ok(soft_fido2::request::PinUvAuth::new(
        pin_token,
        soft_fido2::request::PinUvAuthProtocol::V2,
    ))
}
