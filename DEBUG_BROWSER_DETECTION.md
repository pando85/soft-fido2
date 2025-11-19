# Debugging Browser Detection of Virtual FIDO2 Device

## Problem
The virtual authenticator runs without errors, but WebAuthn websites don't detect it when the "Register" button is pressed.

## Root Cause
Browsers access FIDO2 devices through `/dev/hidraw*` devices, which require specific permissions and udev rules. The virtual device created via UHID needs proper udev configuration for browser access.

## Diagnostic Steps

### 1. Verify Virtual Device Creation

While the authenticator example is running, check if the HID device appears:

```bash
# List all hidraw devices
ls -la /dev/hidraw*

# Check for FIDO devices
lsusb | grep -i fido
udevadm info /dev/hidraw* | grep -i fido

# Monitor udev events while starting the authenticator
sudo udevadm monitor --environment --udev &
# Then start the authenticator example
```

You should see a new `/dev/hidraw*` device appear when the authenticator starts.

### 2. Check Device Permissions

```bash
# Check which user/group owns the hidraw devices
ls -la /dev/hidraw*

# Should show something like:
# crw-rw---- 1 root plugdev 243, 0 Nov 18 10:00 /dev/hidraw0
```

The device needs to be accessible by your user (either through group membership or MODE="0666").

### 3. Required udev Rules

Create `/etc/udev/rules.d/70-fido-u2f.rules`:

```udev
# FIDO/U2F HID devices (for all users)
# This allows browsers to access FIDO2 devices including virtual ones

# Generic FIDO devices (Usage Page 0xF1D0)
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{usage}=="F1D00001", MODE="0666", TAG+="uaccess"

# Fallback: All hidraw devices for FIDO (more permissive - use if above doesn't work)
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0666", TAG+="uaccess"

# Virtual FIDO devices via UHID
SUBSYSTEM=="uhid", MODE="0666", GROUP="plugdev"
```

After creating the rules:

```bash
# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Re-login to apply group changes if needed
```

### 4. Check Browser FIDO Support

```bash
# Check if your browser can see FIDO devices at all
# In Chrome/Chromium: chrome://device-log
# You should see USB/HID device detection logs

# For Firefox: about:config
# Search for: security.webauthn.enable
# Should be: true
```

### 5. Test with Command Line Tool

Before testing with a browser, verify the device works with `fido2-token`:

```bash
# Install fido2 tools
sudo apt-get install fido2-tools

# List FIDO devices (should show your virtual device)
fido2-token -L

# Get device info
fido2-token -I /dev/hidraw0  # Replace with your device
```

### 6. Browser-Specific Issues

**Chrome/Chromium:**
- Requires `chrome://flags/#enable-experimental-web-platform-features` (usually not needed)
- Check `chrome://device-log` for HID errors
- May need to restart browser after device appears

**Firefox:**
- Supports WebAuthn by default
- May need `security.webauthn.u2f` = true in about:config
- Check Browser Console (F12) for WebAuthn errors

### 7. SELinux/AppArmor Issues

If using SELinux or AppArmor:

```bash
# Check for denials
sudo ausearch -m avc -ts recent | grep hidraw

# Temporarily disable to test
sudo setenforce 0  # SELinux
sudo systemctl stop apparmor  # AppArmor

# If this fixes it, you need to add proper policies
```

## Quick Fix (Permissive Mode)

For testing only, make all hidraw devices world-accessible:

```bash
# Temporary (until reboot)
sudo chmod 666 /dev/hidraw*

# Permanent via udev (creates security risk!)
echo 'KERNEL=="hidraw*", MODE="0666"' | sudo tee /etc/udev/rules.d/99-hidraw.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

## Recommended Solution

1. **Create proper udev rules** (see step 3 above)
2. **Add your user to the plugdev group**:
   ```bash
   sudo usermod -a -G plugdev $USER
   # Log out and back in
   ```
3. **Verify group membership**:
   ```bash
   groups | grep plugdev
   ```
4. **Restart browser** after device is ready

## Testing Sequence

1. Set up udev rules and permissions
2. Log out and back in (for group changes)
3. Start the authenticator: `cargo run --example authenticator --features pure-rust`
4. Verify device appears: `ls -la /dev/hidraw*`
5. Test with fido2-token: `fido2-token -L`
6. **Restart your browser** (important!)
7. Test with WebAuthn website

## Debug Output to Check

When you run the authenticator with the new debug logging, you should see:

```
[Setup] ✓ UHID device opened
...
[UHID] Received 64 bytes        # <-- When browser probes device
[UHID] Packet: CID=0xffffffff, Type=INIT, Payload=8 bytes
[CTAP] INIT command processed
```

If you see NO output when pressing "Register" in the browser, the browser isn't seeing the device at all (permission issue).

If you see output but the browser shows an error, the CTAP protocol exchange has an issue (check the CBOR logs).

## Common Issues

1. **No /dev/hidraw* appears**: UHID module not loaded or permissions wrong
2. **Device appears but browser can't access**: udev rules or permissions wrong
3. **Browser caching old device list**: Restart browser after device creation
4. **SELinux/AppArmor blocking**: Check audit logs

## Contact

If none of this works, provide:
- Output of `ls -la /dev/hidraw*`
- Output of `udevadm info /dev/hidraw0` (use your device number)
- Output of `groups` (your user groups)
- Browser and version
- Any errors in browser console (F12)
