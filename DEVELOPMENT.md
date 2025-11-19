# Development Guide

## Building the Project

### Standard Build (USB Support)

For USB HID transport support, you'll need libudev:

1. **Install dependencies:**

   ```bash
   # Ubuntu/Debian
   sudo apt-get install libudev-dev
   ```

2. **Build:**

   ```bash
   cargo build
   ```

### Build Without USB Support

If you don't need USB HID transport (e.g., testing only):

```bash
cargo build --no-default-features
```

### Testing

```bash
# Run basic tests
make test

# Run integration tests (in-memory WebAuthn)
make test-integration

# Run E2E tests (requires UHID permissions)
make test-e2e

# Run all tests
make test-all
```

### Linting and Formatting

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Run both
make lint
```

## End-to-End WebAuthn Testing

The `e2e_webauthn_test.rs` test file provides comprehensive end-to-end testing of the complete
WebAuthn/FIDO2 flow, including:

1. **Virtual Authenticator**: A software authenticator running in a background thread
2. **PIN Protocol**: Full PIN/UV authentication with protocol V2
3. **Registration Flow**: Complete makeCredential operation
4. **Authentication Flow**: Complete getAssertion operation
5. **UHID Transport**: Virtual USB HID device for testing without physical hardware

## Architecture

```ascii
┌──────────────────────────────────────────────────────────────┐
│                      Test Process                            │
│                                                               │
│  ┌────────────────────┐         ┌────────────────────┐      │
│  │  Test Thread       │         │  Authenticator     │      │
│  │  (Client)          │         │  Thread            │      │
│  │                    │         │                    │      │
│  │  ┌──────────────┐  │         │  ┌──────────────┐ │      │
│  │  │   Client     │  │         │  │ Authenticator│ │      │
│  │  │   Builder    │  │         │  │  + Callbacks │ │      │
│  │  │   API        │  │         │  └──────┬───────┘ │      │
│  │  └──────┬───────┘  │         │         │         │      │
│  │         │          │         │  ┌──────▼───────┐ │      │
│  │  ┌──────▼───────┐  │         │  │   CTAP HID   │ │      │
│  │  │  Transport   │  │         │  └──────┬───────┘ │      │
│  │  │  (USB HID)   │  │         │         │         │      │
│  │  └──────┬───────┘  │         │  ┌──────▼───────┐ │      │
│  │         │          │         │  │     UHID     │ │      │
│  └─────────┼──────────┘         │  │   (write)    │ │      │
│            │                    │  └──────────────┘ │      │
│            │                    └────────────────────┘      │
│            │                             ▲                  │
│            └─────────────────────────────┘                  │
│                    /dev/uhid                                │
└──────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Authenticator Thread**:

   - Creates a virtual UHID device (`/dev/uhid`)
   - Runs CTAP HID protocol handler
   - Processes CTAP2 commands via software authenticator
   - Stores credentials in memory (HashMap)

2. **Test Thread (Client)**:

   - Enumerates USB HID devices (finds the virtual authenticator)
   - Opens transport connection
   - Sends CTAP2 commands using the Client builder API
   - Receives responses through the transport

3. **Communication**:
   - Both threads communicate through the Linux UHID kernel module
   - UHID provides a `/dev/uhid` device that appears as a real USB HID device
   - The OS handles the transport layer, making it indistinguishable from hardware

## Prerequisites

### Linux Kernel Requirements

The tests require the UHID kernel module and proper permissions:

```bash
# Load the UHID kernel module
sudo modprobe uhid

# Create fido group
sudo groupadd fido 2>/dev/null || true

# Add your user to the fido group
sudo usermod -a -G fido $USER

# Create udev rules for UHID access
echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' | \
    sudo tee /etc/udev/rules.d/90-uhid.rules

# Reload udev rules
sudo udevadm control --reload-rules && sudo udevadm trigger

# You'll need to log out and log back in for group membership to take effect
```

### Verify Setup

```bash
# Check if UHID module is loaded
lsmod | grep uhid

# Check if /dev/uhid exists and has correct permissions
ls -l /dev/uhid

# Should show: crw-rw---- 1 root fido ... /dev/uhid
```

## Running the Tests

### Compile the Tests

```bash
make test-e2e
```
