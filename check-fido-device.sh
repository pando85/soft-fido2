#!/bin/bash
# Quick diagnostic script for FIDO2 virtual device detection

echo "═══════════════════════════════════════════════════"
echo "    FIDO2 Virtual Device Detection Diagnostic"
echo "═══════════════════════════════════════════════════"
echo

echo "[1] Checking UHID module..."
if lsmod | grep -q uhid; then
    echo "    ✓ UHID module is loaded"
else
    echo "    ✗ UHID module NOT loaded"
    echo "    Run: sudo modprobe uhid"
fi
echo

echo "[2] Checking /dev/uhid permissions..."
if [ -c /dev/uhid ]; then
    ls -la /dev/uhid
    if [ -r /dev/uhid ] && [ -w /dev/uhid ]; then
        echo "    ✓ You have read/write access to /dev/uhid"
    else
        echo "    ✗ No read/write access to /dev/uhid"
        echo "    Run: sudo chmod 666 /dev/uhid  (temporary)"
        echo "    Or set up proper udev rules (see DEVELOPMENT.md)"
    fi
else
    echo "    ✗ /dev/uhid does not exist"
fi
echo

echo "[3] Checking your groups..."
echo "    Your groups: $(groups)"
if groups | grep -qE "plugdev|fido"; then
    echo "    ✓ You're in plugdev or fido group"
else
    echo "    ⚠ Not in plugdev or fido group"
    echo "    Run: sudo usermod -a -G plugdev $USER"
    echo "    Then log out and back in"
fi
echo

echo "[4] Checking hidraw devices..."
if ls /dev/hidraw* 2>/dev/null; then
    echo
    for dev in /dev/hidraw*; do
        echo "    Device: $dev"
        ls -la "$dev"
        # Try to get device info
        if command -v udevadm &> /dev/null; then
            udevadm info "$dev" 2>/dev/null | grep -E "ID_VENDOR|ID_MODEL|DEVNAME" | sed 's/^/      /'
        fi
        echo
    done
else
    echo "    ⚠ No /dev/hidraw* devices found"
    echo "    Start the authenticator example first"
fi
echo

echo "[5] Checking udev rules for FIDO..."
if [ -f /etc/udev/rules.d/70-fido-u2f.rules ] || [ -f /etc/udev/rules.d/70-u2f.rules ]; then
    echo "    ✓ FIDO udev rules found"
    grep -h "hidraw" /etc/udev/rules.d/*fido*.rules /etc/udev/rules.d/*u2f*.rules 2>/dev/null | head -3 | sed 's/^/      /'
else
    echo "    ✗ No FIDO udev rules found"
    echo "    Create /etc/udev/rules.d/70-fido-u2f.rules"
    echo "    See DEBUG_BROWSER_DETECTION.md for details"
fi
echo

echo "[6] Checking for fido2-tools..."
if command -v fido2-token &> /dev/null; then
    echo "    ✓ fido2-token is installed"
    echo
    echo "    Available FIDO devices:"
    fido2-token -L 2>&1 | sed 's/^/      /'
else
    echo "    ⚠ fido2-token not installed (optional)"
    echo "    Install: sudo apt-get install fido2-tools"
fi
echo

echo "═══════════════════════════════════════════════════"
echo "Next steps:"
echo "  1. Fix any issues marked with ✗"
echo "  2. Start authenticator: cargo run --example authenticator --features pure-rust"
echo "  3. Re-run this script to verify /dev/hidraw* appears"
echo "  4. Test with: fido2-token -L"
echo "  5. Restart your browser"
echo "  6. Try WebAuthn website again"
echo
echo "For detailed help, see: DEBUG_BROWSER_DETECTION.md"
echo "═══════════════════════════════════════════════════"
