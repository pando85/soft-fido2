# soft-fido2

[![Crates.io](https://img.shields.io/crates/v/soft-fido2.svg)](https://crates.io/crates/soft-fido2)
[![Documentation](https://docs.rs/soft-fido2/badge.svg)](https://docs.rs/soft-fido2)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Build Status](https://github.com/pando85/soft-fido2/workflows/CI/badge.svg)](https://github.com/pando85/soft-fido2/actions)

A pure Rust implementation of FIDO2/WebAuthn CTAP 2.0/2.1 protocol for virtual authenticators.

**soft-fido2** provides virtual FIDO2 authenticator capabilities for testing and development, enabling developers to implement WebAuthn authentication flows without physical security keys.

## Features

- 🔐 **Full CTAP 2.0/2.1 Protocol** - Complete implementation of FIDO2 Client-to-Authenticator Protocol
- 🦀 **Pure Rust** - Zero dependencies on C libraries, fully memory-safe implementation
- 🚫 **no_std Support** - Core protocol and cryptography work in embedded environments
- 🔌 **Multiple Transports** - USB HID and Linux UHID virtual device support
- 🧪 **Testing-First** - Designed for WebAuthn integration testing and development
- 🎯 **Callback-Based** - Flexible user interaction model with customizable callbacks
- 📦 **Modular Architecture** - Separate crates for crypto, protocol, and transport layers
- 🔒 **Well-Audited Crypto** - Uses industry-standard cryptographic libraries (p256, sha2, aes)

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
soft-fido2 = "0.2"
```

### Basic Example

```rust
use soft_fido2::{Authenticator, CallbacksBuilder, TransportList, Client};

// Create an in-memory authenticator with default callbacks
let callbacks = CallbacksBuilder::new()
    .up(|_, _, _| Ok(soft_fido2::UpResult::Accepted))  // User presence
    .uv(|_, _, _| Ok(soft_fido2::UvResult::Accepted))  // User verification
    .build();

let mut auth = Authenticator::new(callbacks)?;

// Enumerate available transports (USB HID or UHID)
let mut transport_list = TransportList::enumerate()?;
let mut transport = transport_list.get(0)?;
transport.open()?;

// Get authenticator info
let info = Client::authenticator_get_info(&mut transport)?;
println!("Authenticator: {:?}", info);
```

## Architecture

soft-fido2 is organized into four main crates:

```
soft-fido2/
├── soft-fido2           # High-level API and examples
├── soft-fido2-crypto    # Cryptographic primitives (ECDSA, ECDH, PIN protocols)
├── soft-fido2-ctap      # CTAP 2.0/2.1 protocol implementation
└── soft-fido2-transport # Transport layers (USB HID, UHID)
```

### Crate Overview

| Crate | Description | no_std |
|-------|-------------|---------|
| [`soft-fido2`](soft-fido2) | High-level API combining all components | ⚠️ Core only |
| [`soft-fido2-crypto`](soft-fido2-crypto) | P-256 ECDSA/ECDH, PIN protocols V1/V2 | ✅ Yes |
| [`soft-fido2-ctap`](soft-fido2-ctap) | CTAP command handlers and authenticator logic | ✅ Yes |
| [`soft-fido2-transport`](soft-fido2-transport) | USB HID and UHID transport implementations | ❌ Requires std |

## Usage

### Creating a Virtual Authenticator

```rust
use soft_fido2::{
    Authenticator, AuthenticatorConfig, CallbacksBuilder,
    UpResult, UvResult, Credential
};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// Setup credential storage
let credentials = Arc::new(Mutex::new(HashMap::<Vec<u8>, Credential>::new()));

// Build callbacks for user interaction
let creds_write = credentials.clone();
let creds_read = credentials.clone();

let callbacks = CallbacksBuilder::new()
    .up(Arc::new(|_info, _user, _rp| {
        println!("User presence check - tap to continue");
        Ok(UpResult::Accepted)
    }))
    .uv(Arc::new(|_info, _user, _rp| {
        println!("User verification - provide PIN or biometric");
        Ok(UvResult::Accepted)
    }))
    .write(Arc::new(move |_id, _rp, cred| {
        let mut store = creds_write.lock().unwrap();
        store.insert(cred.id.to_vec(), cred.to_owned());
        Ok(())
    }))
    .read_credentials(Arc::new(move |rp_id, user_id| {
        let store = creds_read.lock().unwrap();
        let filtered: Vec<Credential> = store
            .values()
            .filter(|c| c.rp.id == rp_id &&
                       (user_id.is_none() || user_id == Some(c.user.id.as_slice())))
            .cloned()
            .collect();
        Ok(filtered)
    }))
    .build();

// Create authenticator with custom configuration
let config = AuthenticatorConfig::builder()
    .aaguid([0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d,
             0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29, 0x7c, 0x88])
    .max_credentials(100)
    .extensions(vec!["credProtect".to_string(), "hmac-secret".to_string()])
    .build();

let auth = Authenticator::with_config(callbacks, config)?;
```

### WebAuthn Registration Flow

```rust
use soft_fido2::{
    Client, MakeCredentialRequest, ClientDataHash,
    RelyingParty, User, PinUvAuthProtocol
};
use sha2::{Sha256, Digest};

// 1. Create client data hash (normally from browser)
let client_data_json = r#"{"type":"webauthn.create","challenge":"...","origin":"https://example.com"}"#;
let mut hasher = Sha256::new();
hasher.update(client_data_json.as_bytes());
let client_data_hash = ClientDataHash::from(hasher.finalize().as_slice());

// 2. Setup relying party and user
let rp = RelyingParty {
    id: "example.com".to_string(),
    name: Some("Example Corp".to_string()),
};

let user = User {
    id: b"user123".to_vec(),
    name: Some("alice@example.com".to_string()),
    display_name: Some("Alice Smith".to_string()),
};

// 3. Create credential
let request = MakeCredentialRequest::builder()
    .client_data_hash(client_data_hash)
    .rp(rp)
    .user(user)
    .resident_key(false)
    .user_verification(true)
    .build();

let response = Client::make_credential(&mut transport, request)?;
println!("Credential created! Credential ID: {:?}", response);
```

### WebAuthn Authentication Flow

```rust
use soft_fido2::{Client, GetAssertionRequest, CredentialDescriptor, CredentialType};

// 1. Get assertion (authentication)
let request = GetAssertionRequest::builder()
    .rp_id("example.com")
    .client_data_hash(client_data_hash)
    .allow_list(vec![
        CredentialDescriptor {
            credential_type: CredentialType::PublicKey,
            id: credential_id.clone(),
            transports: None,
        }
    ])
    .user_verification(true)
    .build();

let response = Client::get_assertion(&mut transport, request)?;
println!("Authentication successful! Signature: {:?}", response);
```

### PIN Protocol

```rust
use soft_fido2::{PinUvAuthEncapsulation, PinProtocol, PinUvAuthProtocol};

// Establish PIN protocol
let mut pin_encapsulation = PinUvAuthEncapsulation::new(&mut transport, PinProtocol::V2)?;

// Get PIN token for operations
let pin_token = pin_encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
    &mut transport,
    "123456",  // User's PIN
    0x01 | 0x02,  // Permissions: makeCredential | getAssertion
    Some("example.com"),
)?;

// Use PIN token for authenticated operations
let pin_auth = PinUvAuthProtocol::from_pin_token(&pin_token, client_data_hash.as_slice());
```

## no_std Support

The core protocol and cryptographic components support `no_std` environments:

```toml
[dependencies]
soft-fido2 = { version = "0.2", default-features = false }
```

**Available in no_std:**
- ✅ CTAP protocol logic
- ✅ Cryptographic operations (ECDSA, ECDH)
- ✅ PIN protocols V1 and V2
- ✅ Authenticator state management
- ✅ CBOR encoding/decoding

**Requires std:**
- ❌ Transport layers (USB HID, UHID)
- ❌ Client API
- ❌ Time-based PIN token expiration (uses timestamp = 0 in no_std)

## Examples

The [`soft-fido2/examples`](soft-fido2/examples) directory contains several complete examples:

- **[authenticator.rs](soft-fido2/examples/authenticator.rs)** - Virtual authenticator with UHID
- **[client.rs](soft-fido2/examples/client.rs)** - CTAP client communicating with authenticators
- **[webauthn_flow.rs](soft-fido2/examples/webauthn_flow.rs)** - Complete WebAuthn registration and authentication
- **[pin_protocol.rs](soft-fido2/examples/pin_protocol.rs)** - PIN protocol demonstration
- **[credential_management.rs](soft-fido2/examples/credential_management.rs)** - Managing stored credentials

Run examples:

```bash
# List available FIDO2 devices
cargo run --example client

# Run virtual authenticator (requires UHID permissions)
cargo run --example authenticator

# Complete WebAuthn flow
cargo run --example webauthn_flow
```

## Building

### Standard Build

```bash
cargo build --release
```

### Build without USB Support

Useful on systems without `libudev`:

```bash
cargo build --no-default-features --release
```

### Build for no_std

```bash
cargo build --no-default-features --target thumbv7em-none-eabihf --release
```

## Testing

```bash
# Run all tests
cargo test --all

# Run integration tests only
cargo test --test webauthn_inmemory_test

# Run with all features
cargo test --all-features
```

## Supported CTAP Commands

soft-fido2 implements the following CTAP 2.0/2.1 commands:

| Command | Support | Description |
|---------|---------|-------------|
| `authenticatorMakeCredential` | ✅ | Create new credential (registration) |
| `authenticatorGetAssertion` | ✅ | Get authentication assertion (login) |
| `authenticatorGetInfo` | ✅ | Get authenticator metadata |
| `authenticatorClientPIN` | ✅ | PIN protocol operations (V1, V2) |
| `authenticatorReset` | ✅ | Factory reset |
| `authenticatorGetNextAssertion` | ✅ | Get next assertion in batch |
| `authenticatorCredentialManagement` | ✅ | Manage stored credentials |
| `authenticatorSelection` | ✅ | User verification and selection |

## Security

⚠️ **Important:** This library is designed for **testing and development** purposes. While it implements the FIDO2 specification correctly and uses well-audited cryptographic libraries, it is **not intended for production use** as a real security key.

### Cryptographic Dependencies

All cryptographic operations use well-maintained, audited libraries:

- **p256** (v0.13) - NIST P-256 elliptic curve operations
- **sha2** (v0.10) - SHA-256 hashing
- **aes** (v0.8) - AES-256 encryption
- **hmac** (v0.12) - HMAC authentication
- **rand** (v0.8) - Cryptographically secure RNG

### Credential Storage

Credentials are stored in memory by default. For persistent storage, implement custom callback functions that write to secure storage (encrypted filesystem, TPM, etc.).

## Platform Support

| Platform | USB HID | UHID Virtual Device |
|----------|---------|---------------------|
| Linux    | ✅ Yes  | ✅ Yes              |
| macOS    | ✅ Yes  | ❌ No               |
| Windows  | ✅ Yes  | ❌ No               |
| Embedded | ❌ No   | ❌ No               |

**UHID Requirements** (Linux only):
- UHID kernel module loaded: `sudo modprobe uhid`
- User permissions: Add user to `fido` group or configure udev rules

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Clone repository
git clone https://github.com/pando85/soft-fido2
cd soft-fido2

# Install pre-commit hooks
make pre-commit-install

# Run tests
make test

# Run formatting and linting
make lint
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## References

- [FIDO2 CTAP Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [COSE (CBOR Object Signing and Encryption)](https://tools.ietf.org/html/rfc8152)

## Acknowledgments

Built with ❤️ using Rust

---

**Note:** This is a community project and is not affiliated with the FIDO Alliance.
