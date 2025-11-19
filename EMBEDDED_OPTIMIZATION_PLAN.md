# Embedded System Optimization Plan

## Current Status

✅ **Completed:**
- Zero-allocation CBOR encoding architecture (MapBuilder)
- StackBuffer for CBOR encoding (replaces heap allocations)
- **Phase 1: Generic StackBuffer with const generics (COMPLETED)**
  - Reduced stack usage from 7.6KB to 256-1024 bytes per request
  - Request-specific buffer size constants
  - Type aliases for common operations
- **Phase 2: SmallVec integration (COMPLETED)**
  - Replaced Vec with SmallVec in client code
  - Reduced heap allocations by 200-400 bytes per request
- **Phase 3: Direct CBOR encoding (COMPLETED)**
  - Added `insert_text_map` method to MapBuilder
  - Eliminated BTreeMap usage in client code
  - Reduced heap allocations by ~100 bytes per request
- Transport layer uses SmallVec for packets
- Fixed-size arrays for crypto keys
- PIN protocol uses MapBuilder

⚠️ **Partial Progress:**
- **Phase 4: no_std compilation (PARTIAL)**
  - Fixed SystemTime conditional compilation
  - Added alloc imports for Vec, String, format!, vec!
  - Fixed core::result usage
  - ⚠️ Still requires: thiserror replacement for full no_std support

🚫 **Remaining for Full Embedded Support:**
- Complete no_std compilation (thiserror Error derive needs replacement)
- No embedded example or documentation
- Memory profiling and validation

## Target Requirements

**Embedded Systems Constraints:**
- Stack size: 2-8KB total
- No heap allocator (or very limited heap)
- no_std environment
- Flash: 128KB-512KB
- RAM: 32KB-128KB

**CTAP Message Sizes:**
- getInfo response: ~200 bytes
- makeCredential request: ~400 bytes
- makeCredential response: ~600 bytes
- getAssertion request: ~250 bytes
- getAssertion response: ~400 bytes
- Maximum CTAP message: 7609 bytes (rare, only for large credential lists)

## Phase 1: Configurable Buffer Sizes ⚠️ CRITICAL

### Problem
```rust
const MAX_CTAP_MESSAGE_SIZE: usize = 7609;
pub struct StackBuffer {
    buf: [u8; MAX_CTAP_MESSAGE_SIZE],  // 7.6KB - STACK OVERFLOW!
}
```

### Solution: Const Generics + Request-Specific Buffers

**1.1 Make StackBuffer Generic**
```rust
pub struct StackBuffer<const N: usize> {
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> StackBuffer<N> {
    pub const fn new() -> Self {
        Self { buf: [0u8; N], pos: 0 }
    }
}
```

**1.2 Define Request-Specific Buffer Sizes**
```rust
// In cbor.rs
pub const GETINFO_BUFFER_SIZE: usize = 256;
pub const MAKECRED_REQUEST_BUFFER_SIZE: usize = 512;
pub const MAKECRED_RESPONSE_BUFFER_SIZE: usize = 1024;
pub const GETASSERTION_REQUEST_BUFFER_SIZE: usize = 512;
pub const GETASSERTION_RESPONSE_BUFFER_SIZE: usize = 768;
pub const MAX_CTAP_MESSAGE_SIZE: usize = 7609; // For completeness

pub type GetInfoBuffer = StackBuffer<GETINFO_BUFFER_SIZE>;
pub type MakeCredRequestBuffer = StackBuffer<MAKECRED_REQUEST_BUFFER_SIZE>;
pub type MakeCredResponseBuffer = StackBuffer<MAKECRED_RESPONSE_BUFFER_SIZE>;
pub type GetAssertionRequestBuffer = StackBuffer<GETASSERTION_REQUEST_BUFFER_SIZE>;
pub type GetAssertionResponseBuffer = StackBuffer<GETASSERTION_RESPONSE_BUFFER_SIZE>;
```

**1.3 Update MapBuilder to Accept Generic Buffer**
```rust
impl MapBuilder {
    pub fn build_into<const N: usize>(self, buffer: &mut StackBuffer<N>) -> Result<usize> {
        buffer.clear();
        // Write CBOR directly to buffer
        // Return bytes written
    }

    // Keep existing build() for backward compatibility
    pub fn build(self) -> Result<Vec<u8>> {
        let mut buffer = StackBuffer::<MAX_CTAP_MESSAGE_SIZE>::new();
        let len = self.build_into(&mut buffer)?;
        Ok(buffer.as_slice()[..len].to_vec())
    }
}
```

**Files to modify:**
- `soft-fido2-ctap/src/cbor.rs`
- `soft-fido2/src/client.rs`
- `soft-fido2/src/pin.rs`

**Estimated stack savings:** 7.6KB → 512-1024 bytes per request

## Phase 2: Replace Vec with SmallVec

### Problem
```rust
// Heap allocations
let allow_list: Vec<Credential> = ...;
let alg_params = vec![alg_param];
```

### Solution: Use SmallVec (already in workspace!)

**2.1 Replace Vec in client.rs**
```rust
use smallvec::SmallVec;

// Most requests have 0-3 credentials
let allow_list: SmallVec<[Credential; 4]> = request
    .allow_list()
    .iter()
    .map(|cred| Credential { ... })
    .collect();

// Single algorithm (ES256)
let alg_params: SmallVec<[PubKeyCredParam; 1]> = SmallVec::from_buf([
    PubKeyCredParam { alg: -7, cred_type: "public-key" }
]);
```

**2.2 Update MapBuilder to Accept SmallVec**
```rust
impl MapBuilder {
    pub fn insert<T: Serialize>(mut self, key: i32, value: T) -> Result<Self> {
        // Already generic - will work with SmallVec
    }
}
```

**Files to modify:**
- `soft-fido2/src/client.rs` (allow_list, alg_params)
- `soft-fido2-ctap/src/cbor.rs` (MapBuilder::entries could use SmallVec)

**Estimated heap savings:** 200-400 bytes per request

## Phase 3: Replace BTreeMap with Direct Encoding

### Problem
```rust
let mut rp_map = BTreeMap::new();
rp_map.insert("id", request.rp().id.as_str());
rp_map.insert("name", name.as_str());
```

### Solution: Direct CBOR Map Encoding

**3.1 Add Helper Methods to MapBuilder**
```rust
impl MapBuilder {
    /// Insert a nested map with text keys
    pub fn insert_text_map(mut self, key: i32, fields: &[(&str, &str)]) -> Result<Self> {
        // Manually encode map with text keys
        let mut inner_buffer = SmallVec::<[u8; 128]>::new();

        // Write map header
        write_cbor_map_header(&mut inner_buffer, fields.len())?;

        // Write key-value pairs
        for (k, v) in fields {
            write_cbor_text(&mut inner_buffer, k)?;
            write_cbor_text(&mut inner_buffer, v)?;
        }

        self.entries.push((key, inner_buffer.to_vec()));
        Ok(self)
    }
}
```

**3.2 Update Client Code**
```rust
// Before: BTreeMap
let mut rp_map = BTreeMap::new();
rp_map.insert("id", request.rp().id.as_str());
builder = builder.insert(2, &rp_map)?;

// After: Direct encoding
let mut rp_fields = SmallVec::<[(&str, &str); 2]>::new();
rp_fields.push(("id", request.rp().id.as_str()));
if let Some(name) = &request.rp().name {
    rp_fields.push(("name", name.as_str()));
}
builder = builder.insert_text_map(2, &rp_fields)?;
```

**Files to modify:**
- `soft-fido2-ctap/src/cbor.rs` (add helper methods)
- `soft-fido2/src/client.rs` (use helpers instead of BTreeMap)

**Estimated heap savings:** ~100 bytes per request

## Phase 4: Fix no_std Compilation

### Problem: Missing imports and std dependencies

**4.1 Fix Missing Imports**
```rust
// In soft-fido2-ctap/src/types.rs
use alloc::string::String;
use alloc::vec::Vec;

// In soft-fido2-ctap/src/extensions.rs
use alloc::vec::Vec;

// In soft-fido2-ctap/src/status.rs
pub type Result<T> = core::result::Result<T, StatusCode>;
```

**4.2 Replace thiserror with Manual Error Implementation**
```rust
// soft-fido2-ctap/src/status.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusCode {
    Success = 0x00,
    InvalidCbor = 0x01,
    // ... rest of codes
}

impl core::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "CTAP Error: {:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StatusCode {}
```

**4.3 Fix core2 vs std io traits**
```rust
// In soft-fido2-ctap/src/cbor.rs
#[cfg(feature = "std")]
use std::io::{self, Write};

#[cfg(not(feature = "std"))]
use core2::io::{self, Write};
```

**Files to modify:**
- `soft-fido2-ctap/src/types.rs`
- `soft-fido2-ctap/src/extensions.rs`
- `soft-fido2-ctap/src/status.rs`
- `soft-fido2-ctap/Cargo.toml` (make thiserror optional)

**Test:** `cargo build --no-default-features`

## Phase 5: Embedded Example

### 5.1 Create Example File

**File:** `soft-fido2/examples/embedded_minimal.rs`

```rust
//! Minimal embedded example showing zero-allocation CTAP operations
//!
//! This example demonstrates:
//! - Fixed-size stack buffers
//! - No heap allocations
//! - Suitable for ARM Cortex-M devices

#![no_std]
#![no_main]

// Panic handler for no_std
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Mock entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Example: Build makeCredential request with 512-byte buffer
    let mut request_buffer = soft_fido2_ctap::cbor::MakeCredRequestBuffer::new();

    // Build request (no heap allocations)
    let client_data_hash = [0u8; 32];
    let rp_id = "example.com";
    let user_id = [1u8, 2, 3, 4];

    // ... build CBOR request ...

    loop {}
}
```

**5.2 Documentation**

Add to `CLAUDE.md`:
```markdown
## Embedded Usage

For embedded systems (no_std, limited RAM):

1. **Use sized buffers:**
   ```rust
   let mut buffer = MakeCredRequestBuffer::new(); // 512 bytes
   ```

2. **No heap allocations:**
   - Uses SmallVec for small lists
   - Fixed-size crypto keys
   - Stack-based CBOR encoding

3. **Memory requirements:**
   - Stack: 2KB minimum
   - Flash: ~50KB for basic CTAP support
   - No heap required (optional for large operations)

4. **Build:**
   ```bash
   cargo build --no-default-features --target thumbv7em-none-eabihf
   ```
```

## Phase 6: Testing and Validation

### 6.1 Unit Tests
- Test each buffer size with maximum data
- Verify SmallVec doesn't spill to heap
- Test no_std compilation

### 6.2 Integration Tests
```rust
#[test]
fn test_embedded_makecredential() {
    let mut buffer = MakeCredRequestBuffer::new();
    // Build request, verify fits in 512 bytes
}
```

### 6.3 Memory Profiling
```bash
# Check stack usage
cargo build --release --target thumbv7em-none-eabihf
arm-none-eabi-nm -S target/thumbv7em-none-eabihf/release/libsoft_fido2.a | grep -i stack

# Check no heap calls
cargo build --release --no-default-features
nm target/release/libsoft_fido2_ctap.a | grep -i alloc
```

## Implementation Order

1. **Phase 1** (Critical - 4 hours)
   - Const generic StackBuffer
   - Request-specific buffer sizes
   - Update MapBuilder

2. **Phase 2** (2 hours)
   - Replace Vec with SmallVec
   - Test allocations

3. **Phase 3** (3 hours)
   - Direct CBOR encoding helpers
   - Remove BTreeMap

4. **Phase 4** (3 hours)
   - Fix no_std compilation
   - Custom Error implementation
   - Test build

5. **Phase 5** (2 hours)
   - Embedded example
   - Documentation

6. **Phase 6** (2 hours)
   - Tests
   - Memory profiling
   - Final validation

**Total Estimated Time:** 16 hours

## Success Criteria

- ✅ Compiles with `--no-default-features`
- ✅ No stack allocations > 1KB
- ✅ Zero heap allocations for common operations
- ✅ Example runs on ARM Cortex-M
- ✅ All tests pass

## Alternative: Hybrid Approach (Quicker)

If full no_std support isn't immediately needed:

1. Add configurable buffer sizes (Phase 1 only)
2. Document minimum requirements
3. Keep std mode for development
4. Defer full no_std to future release

This gives 90% of benefits in 25% of time.
