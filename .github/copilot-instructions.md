# GitHub Copilot Instructions for soft-fido2

## Project Overview

`soft-fido2` is a pure Rust FIDO2/WebAuthn CTAP2 implementation providing virtual authenticator capabilities for testing and development.

### Architecture

- **soft-fido2-crypto**: Cryptographic primitives (ECDSA, ECDH, PIN protocols)
- **soft-fido2-ctap**: CTAP2 protocol implementation (authenticator, commands, callbacks)
- **soft-fido2-transport**: Transport layer (USB HID via hidapi, Linux UHID virtual devices)
- **keylib**: High-level API combining all components

### Core Components

1. **Authenticator**: Virtual FIDO2 authenticator with trait-based callbacks
2. **Client**: CTAP client for communicating with authenticators via transports
3. **Transport**: USB HID and Linux UHID support
4. **CBOR**: Zero-allocation CBOR encoding using cbor4ii
5. **Callbacks**: Trait-based API for user interaction

## Code Style & Conventions

### Rust Edition & Toolchain

- **Edition**: 2024
- **MSRV**: 1.91
- **Linting**: All clippy warnings treated as errors (`-D warnings`)

### Naming Conventions

- **Modules**: `snake_case`
- **Types**: `PascalCase` (e.g., `Authenticator`, `MapBuilder`)
- **Functions**: `snake_case` (e.g., `make_credential`, `get_assertion`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_PIN_RETRIES`, `MAX_CTAP_MESSAGE_SIZE`)

### Import Ordering

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

use soft_fido2_crypto::ecdsa;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cbor4ii::serde;
use serde::Serialize;
```

### Safety & Memory Management

#### Critical Safety Rules

1. **Document safety requirements** with `# Safety` sections for all `unsafe` functions
2. **RAII pattern** - Implement `Drop` for resource cleanup; no manual cleanup exposed
3. **Zero-copy design** - Pass borrowed data when possible, provide `to_owned()` methods for lifetime extension
4. **Global state synchronization** - Use `Mutex` for shared mutable state, especially in callbacks
5. **Thread safety** - Use `Arc<dyn Fn + Send + Sync>` for callbacks shared across threads

### Error Handling

- Return `Result<T>` for all fallible operations
- Custom error types per crate (e.g., `soft_fido2_ctap::StatusCode`)
- Use `?` operator, avoid `unwrap()`/`expect()` in library code
- Provide descriptive error messages with context

### Debug Output

- ❌ NEVER use `println!`, `eprintln!`, or `dbg!` in production code
- ✅ Debug output is ONLY allowed in test code (within `#[cfg(test)]` modules)
- ✅ Use proper error types and `Result<T>` for error handling
- Production code must be silent unless returning errors

### Workspace Dependencies

- All common dependencies MUST be defined in workspace `Cargo.toml` with versions
- Individual crate `Cargo.toml` files use `dependency.workspace = true`
- This ensures consistent versions across the workspace

## Common Patterns

### CBOR Encoding (Zero Allocation)

The project uses cbor4ii with stack-allocated buffers for zero-allocation encoding:

```rust
use crate::cbor::{MapBuilder, encode};

// Build CBOR map
let response = MapBuilder::new()
    .insert(0x01, "value")?
    .insert_bytes(0x02, &data)?
    .build()?;

// Encode with stack buffer (no heap allocation during encode)
let encoded = encode(&response)?;
```

### Trait-Based Callbacks

```rust
pub trait AuthenticatorCallbacks: Send + Sync {
    fn request_up(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UpResult>;
    fn request_uv(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UvResult>;
    fn write_credential(&self, cred: Credential, cred_id: &[u8], rp_id: &str) -> Result<()>;
    fn read_credential(&self, cred_id: &[u8], rp_id: &str) -> Result<Option<Credential>>;
    fn delete_credential(&self, cred_id: &[u8]) -> Result<()>;
    fn select_credential(&self, creds: &[Credential]) -> Result<usize>;
}
```

### Command Handler Pattern

```rust
pub fn handle(auth: &mut Authenticator, request: &[u8]) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(request)?;

    // Extract parameters
    let param1 = parser.get(0x01)?;
    let param2_bytes = parser.get_bytes(0x02)?;

    // Process command
    let result = process_command(auth, param1, param2_bytes)?;

    // Build response
    MapBuilder::new()
        .insert(0x01, result)?
        .build()
}
```

## Testing

### Test Organization

- **Unit tests**: In `#[cfg(test)] mod tests` within source files
- **Integration tests**: In `tests/` directory
- **Examples**: In `examples/` directory serve as documentation

### Running Tests

```bash
# Basic tests
make test

# Integration tests (in-memory WebAuthn)
make test-integration

# All tests
make test-all
```

### Hardware-Dependent Tests

Integration tests gracefully skip when hardware is unavailable:

```rust
let list = match TransportList::enumerate() {
    Ok(list) => list,
    Err(e) => {
        eprintln!("No devices available: {:?}", e);
        return; // Skip test
    }
};
```

## Dependencies

- **cbor4ii**: Zero-allocation CBOR encoding/decoding
- **p256**: ECDSA P-256 curve operations
- **sha2**: SHA-256 hashing
- **aes**: AES-256-CBC encryption for PIN protocol V1
- **hmac**: HMAC for PIN protocol V2
- **hidapi**: USB HID transport (optional, requires libudev)
- **serde**: Serialization framework

## Build System

```bash
# Standard build (requires libudev-dev on Linux)
cargo build

# Build without USB support
cargo build --no-default-features

# Format and lint
make lint

# Run pre-commit hooks
make pre-commit
```

## Documentation Standards

- Document all public APIs with rustdoc comments
- Explain complex algorithms inline
- Reference CTAP spec sections where applicable
- Provide examples in doc comments

Example:
```rust
/// Create a new credential (CTAP 2.0 makeCredential)
///
/// # Arguments
///
/// * `rp` - Relying party information
/// * `user` - User information
/// * `options` - Credential creation options
///
/// # Errors
///
/// Returns `StatusCode::PinRequired` if PIN is not set
/// Returns `StatusCode::KeyStoreFull` if max credentials reached
///
/// # Example
///
/// ```rust
/// let cred = make_credential(&rp, &user, &options)?;
/// ```
pub fn make_credential(
    rp: &RelyingParty,
    user: &User,
    options: &Options,
) -> Result<Credential> {
    // Implementation
}
```

## What NOT to Do

- ❌ Use `println!`, `eprintln!`, or `dbg!` in production code (only in tests)
- ❌ Use `unwrap()` or `expect()` in library code
- ❌ Declare dependencies in multiple crates (use workspace dependencies)
- ❌ Forget `Send + Sync` bounds for callbacks
- ❌ Mix import ordering (follow the standard: super → crate → workspace → std → external)
- ❌ Implement manual memory management (always use RAII)
- ❌ Create summary documentation files (IMPLEMENTATION.md, TESTING.md, etc.)
- ❌ Skip pre-commit hooks (always run before committing)

## References

- **CTAP Specification**: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
- **WebAuthn Specification**: https://www.w3.org/TR/webauthn-2/
- **Repository**: https://github.com/pando85/soft-fido2
- **CLAUDE.md**: Project-specific instructions for Claude Code
