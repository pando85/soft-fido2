<h1 style="font-size: 64px; margin: 0"><span style="color: #de6e1c; font-size: 88px; line-height: 0.9;">🦀</span> <span style="color: inherit; font-size: 48px; vertical-align: middle;">soft-fido2</span></h1>

![Build status](https://img.shields.io/github/actions/workflow/status/pando85/soft-fido2/rust.yml?branch=master)
[![Crates.io](https://img.shields.io/crates/v/soft-fido2.svg)](https://crates.io/crates/soft-fido2)
[![Documentation](https://docs.rs/soft-fido2/badge.svg)](https://docs.rs/soft-fido2)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

A pure Rust implementation of FIDO2/WebAuthn CTAP 2.0/2.1/2.2 protocol.

**soft-fido2** provides both **authenticator** and **client** FIDO2 capabilities for complete
WebAuthn authentication flows.

## Features

- 🔐 **Full CTAP 2.0/2.1/2.2 Protocol** - Complete implementation of FIDO2 Authenticator Protocol
- 🚫 **no_std Support** - Core protocol and cryptography work in embedded environments
- 🔌 **Multiple Transports** - USB HID and Linux UHID virtual device support
- 🧪 **Testing-First** - Designed for WebAuthn integration testing and development
- 🔒 **Well-Audited Crypto** - Uses industry-standard cryptographic libraries (p256, sha2, aes)

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

| Crate                                          | Description                                   | no_std          |
| ---------------------------------------------- | --------------------------------------------- | --------------- |
| [`soft-fido2`](soft-fido2)                     | High-level API combining all components       | ⚠️ Core only    |
| [`soft-fido2-crypto`](soft-fido2-crypto)       | P-256 ECDSA/ECDH, PIN protocols V1/V2         | ✅ Yes          |
| [`soft-fido2-ctap`](soft-fido2-ctap)           | CTAP command handlers and authenticator logic | ✅ Yes          |
| [`soft-fido2-transport`](soft-fido2-transport) | USB HID and UHID transport implementations    | ❌ Requires std |

## Documentation

Comprehensive documentation is available on
[docs.rs/soft-fido2](https://docs.rs/crate/soft-fido2/latest).

## Examples

The [`soft-fido2/examples`](soft-fido2/examples) directory contains several complete examples. Check
them out to see how to use the library!

Run examples:

```bash
# Run virtual authenticator (requires UHID permissions)
cargo run --example virtual_authenticator

# Complete WebAuthn flow
cargo run --example webauthn_flow
```

### UHID Requirements (Linux only)

Make sure you have the uhid kernel module loaded and proper permissions.

Run the following commands as root:

```bash
modprobe uhid
echo uhid > /etc/modules-load.d/fido.conf
groupadd fido 2>/dev/null || true
usermod -a -G fido $YOUR_USERNAME
echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' > /etc/udev/rules.d/90-uinput.rules
udevadm control --reload-rules && udevadm trigger
```

## Projects Using soft-fido2

- **[passless](https://github.com/pando85/passless)** - Virtual FIDO2 device and client FIDO 2
  utility, it runs as a virtual UHID device on Linux.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open
an issue first to discuss what you would like to change.

### Development Setup

```bash
# Clone repository
git clone https://github.com/pando85/soft-fido2
cd soft-fido2

# Install pre-commit hooks
make pre-commit-install

# Run formatting and linting
make lint

# Run tests
make test

# Run end-to-end tests (requires UHID permissions)
make test-e2e
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file
for details.

## References

- [FIDO2 CTAP Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [COSE (CBOR Object Signing and Encryption)](https://tools.ietf.org/html/rfc8152)

**Note:** This is a community project and is not affiliated with the FIDO Alliance.
