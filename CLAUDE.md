# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`soft-fido2` is a pure Rust FIDO2/WebAuthn CTAP2 implementation providing virtual authenticator capabilities for testing and development.

**Workspace Structure:**
- **soft-fido2-crypto**: Cryptographic primitives (ECDSA, ECDH, PIN protocols)
- **soft-fido2-ctap**: CTAP2 protocol implementation (authenticator, commands, callbacks)
- **soft-fido2-transport**: Transport layer (USB HID via hidapi, Linux UHID virtual devices)
- **keylib**: High-level API combining all components

## Common Commands

### Building
```bash
# Standard build (requires libudev-dev on Linux for USB support)
cargo build

# Build without USB support (no libudev required)
cargo build --no-default-features
```

### Testing
```bash
# Run basic tests with linting
make test

# Run integration tests (in-memory WebAuthn, no hardware required)
make test-integration

# Run E2E WebAuthn tests (requires UHID permissions and hardware/virtual device)
make test-e2e

# Run all tests
make test-all
```

### Linting
```bash
# Format and lint
make lint

# Format and lint with auto-fixes
make lint-fix

# Individual checks
cargo fmt                                              # Format code
cargo clippy --all-targets --all-features -- -D warnings  # Lint
```

### Examples
```bash
# Run examples (located in keylib/examples/)
cargo run --example authenticator      # Virtual authenticator demo
cargo run --example client              # CTAP client demo
cargo run --example credential_management  # Credential management demo
cargo run --example pin_protocol        # PIN protocol demo
cargo run --example webauthn_flow       # Complete WebAuthn flow demo
```

### Pre-commit
```bash
make pre-commit-install  # Install pre-commit hooks
make pre-commit          # Run pre-commit on all files
```

## Architecture

### Multi-Layer Design

**Layer 1: Cryptography (soft-fido2-crypto/)**
- ECDSA signing/verification using P-256 curve
- ECDH key agreement for PIN protocols
- PIN protocol V1 (AES-256-CBC) and V2 (HMAC-based)
- Uses well-audited crates: p256, sha2, aes, hmac, hkdf

**Layer 2: CTAP Protocol (soft-fido2-ctap/)**
- CTAP2 command handlers (getInfo, makeCredential, getAssertion, clientPIN, etc.)
- Authenticator state management with thread-safe callbacks
- CBOR serialization/deserialization
- Extension support (credProtect, hmac-secret, etc.)

**Layer 3: Transport (soft-fido2-transport/)**
- USB HID transport via hidapi (optional `usb` feature)
- Linux UHID virtual device support for testing
- CTAP HID protocol implementation
- Channel management and packet fragmentation

**Layer 4: High-Level API (keylib/)**
- Combines all components into ergonomic API
- Builder patterns for complex configuration
- Examples and integration tests

### Core Components

**Authenticator (soft-fido2-ctap/src/authenticator.rs)**
- Virtual FIDO2 authenticator with callback-based user interaction
- Configurable via `AuthenticatorConfig` and `AuthenticatorOptions`
- Stores credentials in memory (HashMap)
- Thread-safe state management using Arc and Mutex

**CTAP Commands (soft-fido2-ctap/src/commands/)**
- `get_info.rs`: Authenticator metadata and capabilities
- `make_credential.rs`: Create new credentials (WebAuthn registration)
- `get_assertion.rs`: Authenticate with existing credentials (WebAuthn login)
- `client_pin.rs`: PIN protocol operations (set PIN, get PIN token, change PIN)
- `credential_management.rs`: Manage stored credentials
- `selection.rs`: User verification and credential selection

**Callbacks (soft-fido2-ctap/src/callbacks.rs)**
- Six callback types: UP (user presence), UV (user verification), Select, Read, Write, Delete
- Thread-safe via `Arc<dyn Fn + Send + Sync>`
- Global state synchronized with `Mutex`
- Zero-copy design with borrowed data

**Transport Layer (soft-fido2-transport/src/)**
- `usb.rs`: USB HID transport via hidapi (optional, requires `usb` feature)
- `uhid.rs`: Linux UHID virtual device support for testing
- `ctaphid.rs`: CTAP HID protocol (initialization, fragmentation, keepalive)
- `channel.rs`: Channel ID management
- `runner.rs`: Command execution loop

**Client API (keylib/src/rust_impl/client.rs)**
- High-level CTAP client for communicating with authenticators
- Issues commands: getInfo, makeCredential, getAssertion, clientPIN
- Transport enumeration and lifecycle management

## Code Style & Safety

### Rust Settings
- **Edition**: 2024
- **MSRV**: 1.91
- **Linting**: All clippy warnings are errors (`-D warnings`)

### Safety Rules
1. **Document safety requirements** - Use `# Safety` sections for all `unsafe` functions
2. **RAII pattern** - Implement `Drop` for resource cleanup; no manual cleanup exposed
3. **Zero-copy design** - Pass borrowed data when possible, provide `to_owned()` methods for lifetime extension
4. **Global state synchronization** - Use `Mutex` for shared mutable state, especially in callbacks
5. **Thread safety** - Use `Arc<dyn Fn + Send + Sync>` for callbacks shared across threads

### Error Handling
- Return `Result<T>` for all fallible operations
- Custom error types per crate (e.g., `soft-fido2_transport::Error`, `soft-fido2_crypto::Error`)
- Use `?` operator, avoid `unwrap()`/`expect()` in library code
- Provide descriptive error messages with context

### Naming Conventions
- **Modules**: snake_case
- **Types**: PascalCase
- **Functions**: snake_case
- **Constants**: SCREAMING_SNAKE_CASE

### Production Standards

**Import Ordering:**
All imports must follow this order (separated by blank lines):
1. `super` imports
2. `crate` imports
3. Same workspace crates (soft-fido2-crypto, soft-fido2-ctap, soft-fido2-transport)
4. `std` imports
5. External crates (third-party dependencies)

Example:
```rust
use super::SomeType;

use crate::error::Error;

use keylib_crypto::ecdsa;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ciborium::cbor;
use serde::Serialize;
```

**Workspace Dependencies:**
- All common dependencies MUST be defined in workspace `Cargo.toml` with versions
- Individual crate `Cargo.toml` files use `dependency.workspace = true`
- This ensures consistent versions across the workspace and prevents duplication
- Common dependencies: ciborium, serde, p256, sha2, rand, hex, thiserror, subtle, etc.

**Debug Output:**
- ❌ NEVER use `println!`, `eprintln!`, or `dbg!` in production code
- ✅ Debug output is ONLY allowed in test code (within `#[cfg(test)]` modules)
- ✅ Use proper error types and `Result<T>` for error handling
- Production code must be silent unless returning errors

**Pre-commit Workflow:**
The repository uses Python `pre-commit` tool (NOT shell scripts) with the following hooks:
- **cargo fmt**: Format all Rust code
- **cargo clippy**: Lint with `-D warnings` (all warnings are errors)
- **cargo test --test webauthn_inmemory_test**: Run in-memory integration test

Install hooks with: `make pre-commit-install`
Run manually with: `make pre-commit`

## Testing Architecture

### Test Organization

**Unit tests**: In `#[cfg(test)] mod tests` within source files

**Integration tests** (keylib/tests/):
- `webauthn_inmemory_test.rs` - In-memory WebAuthn flow (no hardware required, runs in CI)
- `integration.rs` - Basic integration tests
- `credential_storage_test.rs` - Credential storage tests
- `e2e_webauthn_test.rs` - Full end-to-end WebAuthn flow with UHID virtual device

**Examples as documentation**: All examples in `soft-fido2/examples/` serve as usage documentation

### Hardware-Dependent Tests

Integration and E2E tests gracefully skip when hardware/permissions are unavailable. They should check for device availability before proceeding:

```rust
let list = match TransportList::enumerate() {
    Ok(list) => list,
    Err(e) => {
        eprintln!("No devices available: {:?}", e);
        return; // Skip test
    }
};
```

### E2E WebAuthn Testing

The `e2e_webauthn_test.rs` test provides comprehensive testing:

**Architecture:**
- **Authenticator Thread**: Virtual authenticator via UHID, runs CTAP HID protocol
- **Test Thread (Client)**: Enumerates devices, sends commands via USB HID transport
- **Communication**: Both threads use Linux UHID kernel module (`/dev/uhid`)

**Requirements:**
- UHID kernel module loaded (`sudo modprobe uhid`)
- User in `fido` group
- Udev rules for UHID access (see DEVELOPMENT.md)

## Important Patterns

### Builder Pattern
Used for complex types with many optional fields:
```rust
let config = AuthenticatorConfig::builder()
    .aaguid([...])
    .commands(vec![...])
    .options(options)
    .max_credentials(100)
    .extensions(vec![...])
    .build();
```

### Callback Design
- Type aliases with `Arc<dyn Fn + Send + Sync>` for thread safety
- Zero-copy: pass borrowed data when possible
- Provide `to_owned()` methods for lifetime extension

### Resource Lifetime
- Rust types own their resources
- `Drop` implementation automatically performs cleanup
- Users never manually manage resource lifecycle

## What NOT to Do

- ❌ Use `println!`, `eprintln!`, or `dbg!` in production code (only in tests)
- ❌ Use `unwrap()` or `expect()` in library code
- ❌ Declare dependencies in multiple crates (use workspace dependencies)
- ❌ Forget `Send + Sync` bounds for callbacks
- ❌ Mix import ordering (follow the standard: super → crate → workspace → std → external)
- ❌ Implement manual memory management (always use RAII)
- ❌ Create summary documentation files (IMPLEMENTATION.md, TESTING.md, etc.)
- ❌ Skip pre-commit hooks (always run before committing)

## Additional Resources

- **CTAP Specification**: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
- **WebAuthn Specification**: https://www.w3.org/TR/webauthn-2/
- **Repository**: https://github.com/pando85/soft-fido2
- **Pre-commit**: https://pre-commit.com/
