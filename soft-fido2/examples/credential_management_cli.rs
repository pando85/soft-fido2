use std::env;
use std::io::{self, Write};
use std::process;

use soft_fido2::request::{
    CredentialManagementRequest, DeleteCredentialRequest, EnumerateCredentialsRequest,
    UpdateUserRequest,
};
use soft_fido2::transport::Transport;
use soft_fido2::{Client, PinProtocol, TransportList, compute_rp_id_hash};
use soft_fido2_ctap::types::User;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Check for --no-pin flag
    let no_pin = args.contains(&"--no-pin".to_string());
    let args: Vec<String> = args.into_iter().filter(|a| a != "--no-pin").collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }

    // Connect to authenticator
    let mut transport = match connect_to_authenticator() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("❌ Failed to connect: {}", e);
            process::exit(1);
        }
    };

    println!("✓ Connected to authenticator\n");

    // Get authentication token if needed
    let pin_uv_auth = if no_pin {
        println!("ℹ️  Skipping authentication (--no-pin flag)\n");
        None
    } else {
        println!("🔐 Credential management requires authentication");
        println!();
        match authenticate_for_credential_management(&mut transport) {
            Ok(token) => Some(token),
            Err(e) => {
                eprintln!("❌ Authentication failed: {}", e);
                eprintln!();
                eprintln!("💡 Tips:");
                eprintln!("   - Make sure you entered the correct PIN");
                eprintln!("   - Check that PIN is set on the authenticator");
                eprintln!("   - For test authenticators, try --no-pin flag");
                process::exit(1);
            }
        }
    };

    // Execute command
    let command = &args[1];
    let command_args = &args[2..];

    let result = match command.as_str() {
        "get-metadata" | "metadata" => cmd_get_metadata(&mut transport, pin_uv_auth),
        "enumerate-rps" | "list-rps" | "rps" => cmd_enumerate_rps(&mut transport, pin_uv_auth),
        "enumerate-credentials" | "list-credentials" | "credentials" => {
            cmd_enumerate_credentials(&mut transport, pin_uv_auth, command_args, &args[0])
        }
        "delete-credential" | "delete" => {
            cmd_delete_credential(&mut transport, pin_uv_auth, command_args, &args[0])
        }
        "update-user" | "update" => {
            cmd_update_user(&mut transport, pin_uv_auth, command_args, &args[0])
        }
        _ => {
            eprintln!("❌ Unknown command: {}", command);
            print_usage(&args[0]);
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("\n❌ Command failed: {}", e);
        process::exit(1);
    }

    transport.close();
}

fn print_usage(program: &str) {
    eprintln!("🔑 Credential Management CLI");
    eprintln!();
    eprintln!("Usage: {} [--no-pin] <command> [args...]", program);
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --no-pin    Skip PIN authentication (for test authenticators)");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  get-metadata                              - Show credential storage info");
    eprintln!("  enumerate-rps                             - List all relying parties");
    eprintln!("  enumerate-credentials <rp_id>             - List credentials for RP");
    eprintln!("  delete-credential <cred_id_hex>           - Delete a credential");
    eprintln!("  update-user <cred_id_hex> <user_id_hex> <name> <display_name>");
    eprintln!("                                            - Update user information");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} get-metadata", program);
    eprintln!("  {} enumerate-rps", program);
    eprintln!("  {} enumerate-credentials example.com", program);
    eprintln!(
        "  {} --no-pin get-metadata   # For test authenticators",
        program
    );
}

fn connect_to_authenticator() -> Result<Transport, String> {
    let transport_list = TransportList::enumerate()
        .map_err(|e| format!("Failed to enumerate transports: {:?}", e))?;

    if transport_list.is_empty() {
        return Err("No FIDO2 devices found".to_string());
    }

    if transport_list.len() > 1 {
        println!(
            "Found {} FIDO2 devices, using the first one",
            transport_list.len()
        );
    }

    let mut transport = transport_list.get(0).ok_or("Failed to get transport")?;

    transport
        .open()
        .map_err(|e| format!("Failed to open transport: {:?}", e))?;

    Ok(transport)
}

fn authenticate_for_credential_management(
    transport: &mut Transport,
) -> Result<soft_fido2::request::PinUvAuth, String> {
    // Try UV (biometric/platform) authentication first
    println!("Attempting built-in user verification (biometric/platform)...");
    match Client::get_uv_token_for_credential_management(transport, PinProtocol::V2) {
        Ok(token) => {
            println!("✓ User verification successful\n");
            return Ok(token);
        }
        Err(e) => {
            println!("  UV not available: {:?}", e);
            println!("  Falling back to PIN authentication...\n");
        }
    }

    // Fall back to PIN authentication
    print!("Enter PIN: ");
    io::stdout().flush().unwrap();
    let mut pin = String::new();
    io::stdin()
        .read_line(&mut pin)
        .map_err(|e| format!("Failed to read PIN: {:?}", e))?;
    let pin = pin.trim();

    if pin.is_empty() {
        return Err("PIN cannot be empty".to_string());
    }

    // Try PIN protocol V2 first, then V1
    for protocol in [PinProtocol::V2, PinProtocol::V1] {
        match Client::get_pin_token_for_credential_management(transport, pin, protocol) {
            Ok(token) => {
                println!("✓ PIN authentication successful\n");
                return Ok(token);
            }
            Err(e) => {
                if protocol == PinProtocol::V2 {
                    println!("  PIN protocol V2 failed, trying V1...");
                } else {
                    return Err(format!("PIN authentication failed: {:?}", e));
                }
            }
        }
    }

    Err("All authentication methods failed".to_string())
}

fn cmd_get_metadata(
    transport: &mut Transport,
    pin_uv_auth: Option<soft_fido2::request::PinUvAuth>,
) -> Result<(), String> {
    println!("📊 Credential Storage Metadata");
    println!("================================");

    let request = CredentialManagementRequest::new(pin_uv_auth);
    let metadata = Client::get_credentials_metadata(transport, request)
        .map_err(|e| format!("Failed to get metadata: {:?}", e))?;

    println!(
        "Existing discoverable credentials: {}",
        metadata.existing_resident_credentials_count
    );
    println!(
        "Max remaining credentials:         {}",
        metadata.max_possible_remaining_resident_credentials_count
    );

    Ok(())
}

fn cmd_enumerate_rps(
    transport: &mut Transport,
    pin_uv_auth: Option<soft_fido2::request::PinUvAuth>,
) -> Result<(), String> {
    println!("🌐 Relying Parties");
    println!("==================");

    let request = CredentialManagementRequest::new(pin_uv_auth);
    let rps = Client::enumerate_rps(transport, request)
        .map_err(|e| format!("Failed to enumerate RPs: {:?}", e))?;

    if rps.is_empty() {
        println!("No relying parties found");
        return Ok(());
    }

    println!(
        "Found {} relying part{}\n",
        rps.len(),
        if rps.len() == 1 { "y" } else { "ies" }
    );

    for (i, rp) in rps.iter().enumerate() {
        println!("{}. {}", i + 1, rp.id);
        if let Some(name) = &rp.name {
            println!("   Name:       {}", name);
        }
        println!("   RP ID Hash: {}", hex::encode(rp.rp_id_hash));
    }

    Ok(())
}

fn cmd_enumerate_credentials(
    transport: &mut Transport,
    pin_uv_auth: Option<soft_fido2::request::PinUvAuth>,
    args: &[String],
    program: &str,
) -> Result<(), String> {
    if args.is_empty() {
        eprintln!("Usage: {} enumerate-credentials <rp_id>", program);
        return Err("Missing RP ID argument".to_string());
    }

    let rp_id = &args[0];
    let rp_id_hash = compute_rp_id_hash(rp_id);

    println!("🔑 Credentials for {}", rp_id);
    println!("================================");

    let request = EnumerateCredentialsRequest::new(pin_uv_auth, rp_id_hash);
    let credentials = Client::enumerate_credentials(transport, request)
        .map_err(|e| format!("Failed to enumerate credentials: {:?}", e))?;

    if credentials.is_empty() {
        println!("No credentials found for this RP");
        return Ok(());
    }

    println!(
        "Found {} credential{}\n",
        credentials.len(),
        if credentials.len() == 1 { "" } else { "s" }
    );

    for (i, cred) in credentials.iter().enumerate() {
        println!("{}. Credential", i + 1);
        println!("   User ID:        {}", hex::encode(&cred.user.id));
        if let Some(name) = &cred.user.name {
            println!("   User Name:      {}", name);
        }
        if let Some(display_name) = &cred.user.display_name {
            println!("   Display Name:   {}", display_name);
        }
        println!("   Credential ID:  {}", hex::encode(&cred.credential_id.id));

        if let Some(cred_protect) = cred.cred_protect {
            let protection_level = match cred_protect {
                1 => "UV Optional",
                2 => "UV Optional with Credential ID List",
                3 => "UV Required",
                _ => "Unknown",
            };
            println!("   Protection:     {} ({})", protection_level, cred_protect);
        }

        if cred.public_key.is_some() {
            println!("   Public Key:     Present");
        }

        if cred.large_blob_key.is_some() {
            println!("   Large Blob Key: Present");
        }

        println!();
    }

    Ok(())
}

fn cmd_delete_credential(
    transport: &mut Transport,
    pin_uv_auth: Option<soft_fido2::request::PinUvAuth>,
    args: &[String],
    program: &str,
) -> Result<(), String> {
    if args.is_empty() {
        eprintln!("Usage: {} delete-credential <cred_id_hex>", program);
        return Err("Missing credential ID argument".to_string());
    }

    let cred_id_hex = &args[0];
    let cred_id =
        hex::decode(cred_id_hex).map_err(|e| format!("Invalid credential ID hex: {:?}", e))?;

    println!("🗑️  Deleting credential...");

    let request = DeleteCredentialRequest::new(pin_uv_auth, cred_id);
    Client::delete_credential(transport, request)
        .map_err(|e| format!("Failed to delete credential: {:?}", e))?;

    println!("✓ Credential deleted successfully");

    Ok(())
}

fn cmd_update_user(
    transport: &mut Transport,
    pin_uv_auth: Option<soft_fido2::request::PinUvAuth>,
    args: &[String],
    program: &str,
) -> Result<(), String> {
    if args.len() < 4 {
        eprintln!(
            "Usage: {} update-user <cred_id_hex> <user_id_hex> <name> <display_name>",
            program
        );
        return Err("Missing arguments".to_string());
    }

    let cred_id_hex = &args[0];
    let user_id_hex = &args[1];
    let name = &args[2];
    let display_name = &args[3];

    let cred_id =
        hex::decode(cred_id_hex).map_err(|e| format!("Invalid credential ID hex: {:?}", e))?;

    let user_id = hex::decode(user_id_hex).map_err(|e| format!("Invalid user ID hex: {:?}", e))?;

    println!("✏️  Updating user information...");

    let user = User {
        id: user_id,
        name: Some(name.to_string()),
        display_name: Some(display_name.to_string()),
    };

    let request = UpdateUserRequest::new(pin_uv_auth, cred_id, user);
    Client::update_user_information(transport, request)
        .map_err(|e| format!("Failed to update user information: {:?}", e))?;

    println!("✓ User information updated successfully");

    Ok(())
}
