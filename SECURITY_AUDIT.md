# Security Audit: FIDO2 Implementation Review

**Date:** 2026-02-26
**Auditor:** Security Audit (Issue #67)
**Repository:** soft-fido2

## Executive Summary

This security audit reviewed the soft-fido2 FIDO2/WebAuthn CTAP2 implementation for compliance with FIDO2 security expectations and secure-by-default practices. The implementation demonstrates strong cryptographic foundations with proper use of well-audited crates (p256, sha2, aes, hmac, hkdf).

### Overall Assessment: **Good with Minor Improvements Needed**

The implementation follows FIDO2 specifications well and has appropriate security controls in place. Several medium and low severity issues were identified that should be addressed to strengthen security posture.

---

## Findings Summary

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| SEC-001 | Medium | Debug output in production code | Fixed |
| SEC-002 | Medium | Missing size limits on input data | Fixed |
| SEC-003 | Low | PIN minimum length default | Documented |
| SEC-004 | Low | force_resident_keys defaults to true | Documented |
| SEC-005 | Medium | No challenge uniqueness enforcement | By Design |
| SEC-006 | Low | Credential ID size not validated | Fixed |
| SEC-007 | Info | no_std token expiration warning | Documented |

---

## Detailed Findings

### SEC-001: Debug Output in Production Code (Medium)

**Location:** `soft-fido2-ctap/src/commands/get_assertion.rs:564-635`, `soft-fido2-ctap/src/extensions.rs:447-617`

**Description:** 
Multiple `eprintln!` debug statements are present in the hmac-secret extension code and getAssertion command. While these are behind `#[cfg(feature = "std")]`, they still appear in standard builds.

**Risk:**
- Information leakage through logs
- Timing side-channels if debug output affects execution time
- Violates CLAUDE.md requirement: "NEVER use `println!`, `eprintln!`, or `dbg!` in production code"

**Remediation:**
Remove all `eprintln!` statements from production code paths. Debug output should only be in `#[cfg(test)]` blocks.

**Status:** Fixed

---

### SEC-002: Missing Size Limits on Input Data (Medium)

**Location:** `soft-fido2-ctap/src/commands/make_credential.rs`, `soft-fido2-ctap/src/commands/get_assertion.rs`

**Description:**
Several input fields lack explicit size validation:
- RP ID length not bounded
- User ID length not bounded  
- User name/display name length not bounded
- Extension data size not bounded

While the CBOR parser has a maximum message size (7609 bytes), individual fields should have explicit limits to prevent DoS and ensure compliance.

**Risk:**
- Potential DoS through oversized fields
- Memory exhaustion attacks
- Non-compliant with FIDO2 recommendations

**Remediation:**
Add explicit size validation for:
- RP ID: max 256 bytes (typical domain limit)
- User ID: max 64 bytes (per FIDO2 spec)
- User name/display name: max 256 bytes each
- Credential ID: max 1023 bytes (per CTAP spec)

**Status:** Fixed

---

### SEC-003: PIN Minimum Length Default (Low)

**Location:** `soft-fido2-ctap/src/types.rs:436`, `soft-fido2-ctap/src/authenticator.rs:135`

**Description:**
Default minimum PIN length is 4 characters, which is the CTAP minimum but considered weak by modern standards.

**Risk:**
- 4-digit PINs are susceptible to brute-force if rate limiting fails
- Modern guidance suggests minimum 6 characters

**Remediation:**
Document that integrators should increase `min_pin_length` for production use. Consider adding a compile-time warning or configuration option.

**Status:** Documented in code comments

---

### SEC-004: force_resident_keys Defaults to True (Low)

**Location:** `soft-fido2-ctap/src/authenticator.rs:137`

**Description:**
`force_resident_keys` defaults to `true`, which means all credentials are stored as resident keys regardless of the RP's request.

**Risk:**
- Credential storage exhaustion
- Privacy implications (all credentials discoverable)
- Not matching typical hardware authenticator behavior

**Remediation:**
Document that this default is for testing convenience. Production deployments should set `force_resident_keys: false` to match hardware authenticator behavior.

**Status:** Documented in code comments

---

### SEC-005: No Challenge Uniqueness Enforcement (Medium - By Design)

**Location:** `soft-fido2-ctap/src/commands/make_credential.rs`, `soft-fido2-ctap/src/commands/get_assertion.rs`

**Description:**
The authenticator does not validate or track challenge (clientDataHash) uniqueness. The same challenge can be used multiple times.

**Risk:**
- Potential for replay attacks if client doesn't enforce uniqueness
- However, this is the correct behavior per FIDO2 spec - the client/RP is responsible for challenge uniqueness

**Remediation:**
This is correct by design. The FIDO2 spec places challenge management responsibility on the Relying Party, not the authenticator. No change needed.

**Status:** By Design - No Action Required

---

### SEC-006: Credential ID Size Not Validated (Low)

**Location:** `soft-fido2-ctap/src/commands/get_assertion.rs:418-458`

**Description:**
When processing the allow list in getAssertion, credential IDs from the request are not validated for maximum size before lookup operations.

**Risk:**
- Large credential IDs could cause memory issues
- Non-compliant with CTAP spec (max credential ID length is 1023 bytes)

**Remediation:**
Add validation that credential IDs in allow lists do not exceed 1023 bytes per CTAP specification.

**Status:** Fixed

---

### SEC-007: no_std Token Expiration Warning (Info)

**Location:** `soft-fido2-ctap/src/pin_token.rs:12-25`

**Description:**
In no_std builds without a real-time clock, PIN tokens never expire. This is clearly documented with security implications.

**Risk:**
- Token replay attacks possible in no_std environments
- Captured tokens can be used indefinitely

**Remediation:**
The code already documents this thoroughly. No additional action needed, but integrators should be aware.

**Status:** Documented - No Action Required

---

## Positive Security Observations

### Cryptographic Implementation
- **Strong**: Uses well-audited cryptographic crates (p256, sha2, aes, hmac, hkdf)
- **Strong**: Proper constant-time comparison via `subtle` crate
- **Strong**: Memory protection with `zeroize` for sensitive data
- **Strong**: Correct ECDH implementation for PIN protocol

### PIN Protocol
- **Strong**: Proper key derivation using HKDF-SHA256 (V2)
- **Strong**: Constant-time PIN hash verification
- **Strong**: PIN retry counter with exponential backoff consideration
- **Strong**: PIN blocked after 8 failed attempts

### Token Management
- **Strong**: 19-second usage window for PIN tokens
- **Strong**: 10-minute maximum token lifetime
- **Strong**: RP-scoped permissions for mc/ga operations
- **Strong**: Permission clearing after operations complete

### Input Validation
- **Strong**: CBOR parsing with proper error handling
- **Strong**: Client data hash validation (must be 32 bytes)
- **Strong**: Protocol version validation (1 or 2 only)
- **Strong**: Algorithm validation against supported list

### User Verification
- **Strong**: Proper UP/UV flag handling per FIDO2 spec
- **Strong**: alwaysUV option support
- **Strong**: makeCredUvNotRqd option support
- **Strong**: credProtect extension support (levels 1-3)

---

## Recommendations

### High Priority
1. Remove debug output from production code paths (SEC-001)
2. Add input size validation for all untrusted fields (SEC-002)

### Medium Priority
3. Document security implications of default configuration
4. Add credential ID size validation (SEC-006)

### Low Priority
5. Consider increasing default min_pin_length to 6
6. Consider changing force_resident_keys default to false

---

## Compliance Checklist

| Requirement | Status | Notes |
|-------------|--------|-------|
| RP ID validation | Pass | Empty RP ID rejected |
| Challenge validation | Pass | 32-byte hash required |
| Signature verification | Pass | Proper ECDSA verification |
| UP flag handling | Pass | Per FIDO2 spec |
| UV flag handling | Pass | Per FIDO2 spec |
| Counter handling | Pass | Optional constant counter |
| PIN protocol V1 | Pass | AES-256-CBC + HMAC |
| PIN protocol V2 | Pass | HMAC-SHA256 |
| Token permissions | Pass | Scoped to RP |
| Token expiration | Pass | 19s usage, 10m max |
| Constant-time crypto | Pass | subtle crate |
| Memory protection | Pass | zeroize crate |
| Input size limits | Partial | Fixed in this audit |
| Error handling | Pass | No sensitive data in errors |
| CBOR validation | Pass | Proper parsing errors |

---

## Appendix: Security-Relevant Configuration

### AuthenticatorConfig Security Options

```rust
AuthenticatorConfig {
    // Cryptographic settings
    aaguid: [0u8; 16],              // Authenticator identifier
    algorithms: vec![-7],           // ES256 only by default
    
    // Security options
    options: AuthenticatorOptions {
        always_uv: false,           // Require UV for all operations
        client_pin: Some(true),     // PIN support enabled
        uv: Some(true),             // Built-in UV support
        up: true,                   // User presence required
        make_cred_uv_not_rqd: false, // UV optional for non-rk creds
    },
    
    // Limits
    max_credentials: 100,           // Credential storage limit
    max_msg_size: Some(7609),       // CTAP max message size
    min_pin_length: Some(4),        // PIN minimum (increase for prod)
    
    // Testing conveniences (disable for production)
    force_resident_keys: true,      // Set false for production
    constant_sign_count: false,     // Set true for privacy
}
```

### Recommended Production Configuration

```rust
let config = AuthenticatorConfig::new()
    .with_force_resident_keys(false)  // Match hardware behavior
    .with_constant_sign_count(true);   // Privacy enhancement

// Increase minimum PIN length
auth.set_min_pin_length(6)?;
```

---

## Conclusion

The soft-fido2 implementation demonstrates a solid understanding of FIDO2 security requirements with appropriate use of cryptographic primitives and proper protocol implementation. The identified issues are primarily around defense-in-depth measures (input size limits) and code hygiene (debug output removal), rather than fundamental security flaws.

After implementing the fixes for SEC-001, SEC-002, and SEC-006, the implementation provides a secure foundation for FIDO2/WebAuthn authentication in testing and development environments.

**Note:** This is a software/virtual authenticator implementation intended for testing and development. Production deployments requiring hardware-backed security should use dedicated security keys or platform authenticators.
