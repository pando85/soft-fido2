use soft_fido2::{Client, PinProtocol, TransportList};

fn main() {
    let transport_list = TransportList::enumerate().expect("Failed to enumerate transports");
    let mut transport = transport_list.get(0).expect("No transport found");
    transport.open().expect("Failed to open transport");

    println!("Trying UV authentication for credential management...");
    match Client::get_uv_token_for_credential_management(&mut transport, PinProtocol::V2) {
        Ok(token) => {
            println!("✓ UV token obtained successfully!");
            println!("  Protocol: {:?}", token.protocol());
        }
        Err(e) => {
            println!("✗ UV authentication failed: {:?}", e);
        }
    }

    transport.close();
}
