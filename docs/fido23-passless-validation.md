# Passless compatibility validation for the FIDO 2.3 batch

The `FIDO 2.3 batch compatibility` workflow validates Passless against the exact composed
soft-fido2 source tree rather than against the latest crates.io release.

## Hosted CI coverage

The workflow patches these Passless dependencies to local paths:

- `soft-fido2`
- `soft-fido2-ctap`
- `soft-fido2-transport`

It then checks `passless-core`, `passless-uhid`, and `passless-rs`. This validates Rust API,
feature, type, and transport integration without requiring a privileged kernel device.

## Privileged UHID validation

Run the following on a Linux host with `/dev/uhid` access after composing or merging the batch:

```bash
sudo modprobe uhid
sudo test -r /dev/uhid -a -w /dev/uhid

# In Passless, patch the three soft-fido2 crates to the local checkout as done by CI.
cargo build -p passless-rs -p passless-uhid
cargo test -p passless-core -p passless-uhid

# Start the virtual authenticator using the normal Passless configuration and verify:
# 1. libfido2/browser discovery;
# 2. authenticatorGetInfo;
# 3. PIN-backed registration and authentication;
# 4. discoverable and wrapped credential workflows;
# 5. exact CTAP error propagation through UHID.
```

Hosted runners intentionally do not claim this kernel-level validation. A self-hosted runner
with a `uhid` label can execute the same procedure when one is available.
