# Zero Dynamic Allocation Migration Plan

## Goal
Transform soft-fido2 into a zero dynamic allocation library suitable for embedded systems and security-critical applications.

## Architecture Strategy

**Dual API Approach**: Maintain backward compatibility while adding zero-allocation variants
- Keep existing heap-based API (default)
- Add `#![no_std]` zero-allocation API (opt-in via `no-alloc` feature)
- Use const generics for compile-time sizing

## Current Allocation Analysis

### CBOR Layer (soft-fido2-ctap/src/cbor.rs)
- ✅ StackBuffer encoding: Zero allocations during encode
- ❌ `encode()` returns Vec<u8>: Allocates on return
- ❌ `MapBuilder::entries`: Vec<(i32, Vec<u8>)>
- ❌ `MapParser::map`: BTreeMap<i32, Vec<u8>>
- ❌ All decode operations allocate

### Type Definitions (soft-fido2-ctap/src/types.rs)
- ❌ RelyingParty: String fields (id: max 128 bytes, name: max 64 bytes)
- ❌ User: Vec<u8> + String fields (id: max 64 bytes)
- ❌ Credential: Multiple Vec<u8> and String fields
- ❌ PublicKeyCredentialDescriptor: Vec<u8> + Vec<String>

### Collections
- ❌ Credential storage: HashMap<Vec<u8>, Credential>
- ❌ Extension parsing: BTreeMap usage
- ❌ Thread safety: Arc<Mutex<T>>

### Response Building
- ❌ All commands return Vec<u8>
- ❌ Intermediate buffers allocate

## Migration Phases

---

## PHASE 1: Infrastructure Setup

### 1.1 Add heapless dependency
**File**: `Cargo.toml`
```toml
[workspace.dependencies]
heapless = "0.8"
```

### 1.2 Create feature flags
**File**: `soft-fido2-ctap/Cargo.toml`
```toml
[features]
default = ["std"]
std = ["alloc", "soft-fido2-crypto/std"]
alloc = []  # Allow heap allocations
no-alloc = []  # Zero allocations, incompatible with alloc
```

### 1.3 Add conditional compilation infrastructure
**File**: `soft-fido2-ctap/src/lib.rs`
```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "no-alloc")]
compile_error!("no-alloc and alloc features are mutually exclusive");
```

### Estimated effort: 2 hours
### Files modified: 3 (Cargo.toml, soft-fido2-ctap/Cargo.toml, lib.rs)

---

## PHASE 2: Fixed-Size Type System

### 2.1 Create fixed-size string type
**File**: `soft-fido2-ctap/src/fixed_types.rs` (new)
```rust
use core::fmt;

/// Fixed-size string (stack-allocated)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FixedString<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> FixedString<N> {
    pub const fn new() -> Self {
        Self { bytes: [0; N], len: 0 }
    }

    pub fn from_str(s: &str) -> Result<Self, StatusCode> {
        if s.len() > N {
            return Err(StatusCode::InvalidParameter);
        }
        let mut bytes = [0u8; N];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        Ok(Self { bytes, len: s.len() as u8 })
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap()
    }
}
```

### 2.2 Create fixed-size Vec type
```rust
/// Fixed-size byte vector (stack-allocated)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FixedVec<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> FixedVec<N> {
    pub const fn new() -> Self {
        Self { bytes: [0; N], len: 0 }
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, StatusCode> {
        if slice.len() > N {
            return Err(StatusCode::InvalidParameter);
        }
        let mut bytes = [0u8; N];
        bytes[..slice.len()].copy_from_slice(slice);
        Ok(Self { bytes, len: slice.len() as u8 })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}
```

### 2.3 Define CTAP size constants
**File**: `soft-fido2-ctap/src/constants.rs` (new)
```rust
/// CTAP specification maximum sizes
pub mod max_sizes {
    pub const RP_ID: usize = 128;
    pub const RP_NAME: usize = 64;
    pub const USER_ID: usize = 64;
    pub const USER_NAME: usize = 64;
    pub const USER_DISPLAY_NAME: usize = 64;
    pub const CREDENTIAL_ID: usize = 64;
    pub const PRIVATE_KEY: usize = 32;
    pub const AAGUID: usize = 16;
    pub const EXTENSION_ID: usize = 32;
    pub const CTAP_MESSAGE: usize = 7609;
}
```

### 2.4 Create fixed-size type definitions
**File**: `soft-fido2-ctap/src/types_fixed.rs` (new)
```rust
use super::constants::max_sizes;
use super::fixed_types::{FixedString, FixedVec};

#[cfg(feature = "no-alloc")]
pub type RpId = FixedString<{ max_sizes::RP_ID }>;
#[cfg(feature = "no-alloc")]
pub type RpName = FixedString<{ max_sizes::RP_NAME }>;
#[cfg(feature = "no-alloc")]
pub type UserId = FixedVec<{ max_sizes::USER_ID }>;
#[cfg(feature = "no-alloc")]
pub type UserName = FixedString<{ max_sizes::USER_NAME }>;
#[cfg(feature = "no-alloc")]
pub type CredentialId = FixedVec<{ max_sizes::CREDENTIAL_ID }>;
#[cfg(feature = "no-alloc")]
pub type PrivateKey = [u8; max_sizes::PRIVATE_KEY];

/// Zero-allocation relying party
#[cfg(feature = "no-alloc")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RelyingParty {
    pub id: RpId,
    pub name: Option<RpName>,
}

/// Zero-allocation user
#[cfg(feature = "no-alloc")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct User {
    pub id: UserId,
    pub name: Option<UserName>,
    pub display_name: Option<FixedString<{ max_sizes::USER_DISPLAY_NAME }>>,
}

/// Zero-allocation credential
#[cfg(feature = "no-alloc")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Credential {
    pub id: CredentialId,
    pub rp_id: RpId,
    pub rp_name: Option<RpName>,
    pub user_id: UserId,
    pub user_name: Option<UserName>,
    pub user_display_name: Option<FixedString<{ max_sizes::USER_DISPLAY_NAME }>>,
    pub private_key: PrivateKey,
    pub algorithm: i32,
    pub sign_count: u32,
    pub created: i64,
    pub discoverable: bool,
    pub cred_protect: u8,
}
```

### Estimated effort: 8 hours
### Files created: 3 (fixed_types.rs, constants.rs, types_fixed.rs)

---

## PHASE 3: Zero-Copy CBOR APIs

### 3.1 Add slice-based encode API
**File**: `soft-fido2-ctap/src/cbor.rs`
```rust
/// Encode to user-provided buffer (truly zero allocation)
pub fn encode_to_slice<T: Serialize>(value: &T, buffer: &mut [u8]) -> Result<usize> {
    struct SliceWriter<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }

    impl<'a> Write for SliceWriter<'a> {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.pos + data.len() > self.buf.len() {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "buffer full"));
            }
            self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
            self.pos += data.len();
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    let mut writer = SliceWriter { buf: buffer, pos: 0 };
    cbor4ii::serde::to_writer(&mut writer, value).map_err(|_| StatusCode::InvalidCbor)?;
    Ok(writer.pos)
}
```

### 3.2 Add borrowing decode API
```rust
/// Decode from bytes into user-provided storage (zero allocation for Copy types)
pub fn decode_into<'de, T: Deserialize<'de> + Copy>(
    data: &'de [u8],
    dest: &mut T,
) -> Result<()> {
    *dest = cbor4ii::serde::from_slice(data).map_err(|_| StatusCode::InvalidCbor)?;
    Ok(())
}
```

### 3.3 Replace MapBuilder with fixed-size version
```rust
#[cfg(feature = "no-alloc")]
pub struct FixedMapBuilder<const MAX_ENTRIES: usize> {
    entries: [(i32, [u8; 256]); MAX_ENTRIES],  // Max 256 bytes per value
    lengths: [usize; MAX_ENTRIES],
    count: usize,
}

#[cfg(feature = "no-alloc")]
impl<const MAX_ENTRIES: usize> FixedMapBuilder<MAX_ENTRIES> {
    pub const fn new() -> Self {
        Self {
            entries: [(0, [0; 256]); MAX_ENTRIES],
            lengths: [0; MAX_ENTRIES],
            count: 0,
        }
    }

    pub fn insert<T: Serialize>(&mut self, key: i32, value: &T) -> Result<&mut Self> {
        if self.count >= MAX_ENTRIES {
            return Err(StatusCode::LimitExceeded);
        }

        let len = encode_to_slice(value, &mut self.entries[self.count].1)?;
        self.entries[self.count].0 = key;
        self.lengths[self.count] = len;
        self.count += 1;
        Ok(self)
    }

    pub fn build_to_slice(&self, buffer: &mut [u8]) -> Result<usize> {
        // Encode map directly to buffer without intermediate allocation
        // Implementation similar to current MapBuilder but writes directly
        todo!("Implement direct CBOR map encoding")
    }
}
```

### Estimated effort: 6 hours
### Files modified: 1 (cbor.rs)

---

## PHASE 4: Fixed-Size Collections

### 4.1 Replace HashMap with fixed array
**File**: `soft-fido2-ctap/src/storage_fixed.rs` (new)
```rust
use super::types_fixed::Credential;

/// Compile-time credential storage (zero allocation)
#[cfg(feature = "no-alloc")]
pub struct FixedCredentialStore<const MAX_CREDS: usize> {
    credentials: [Option<Credential>; MAX_CREDS],
    count: usize,
}

#[cfg(feature = "no-alloc")]
impl<const MAX_CREDS: usize> FixedCredentialStore<MAX_CREDS> {
    pub const fn new() -> Self {
        Self {
            credentials: [None; MAX_CREDS],
            count: 0,
        }
    }

    pub fn insert(&mut self, cred: Credential) -> Result<()> {
        // Linear search for empty slot
        for slot in &mut self.credentials {
            if slot.is_none() {
                *slot = Some(cred);
                self.count += 1;
                return Ok(());
            }
        }
        Err(StatusCode::KeyStoreFull)
    }

    pub fn find(&self, cred_id: &[u8]) -> Option<&Credential> {
        for slot in &self.credentials {
            if let Some(cred) = slot {
                if cred.id.as_slice() == cred_id {
                    return Some(cred);
                }
            }
        }
        None
    }

    pub fn remove(&mut self, cred_id: &[u8]) -> Result<()> {
        for slot in &mut self.credentials {
            if let Some(cred) = slot {
                if cred.id.as_slice() == cred_id {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(StatusCode::NoCredentials)
    }
}
```

### 4.2 Add static storage option
```rust
#[cfg(feature = "no-alloc")]
use spin::Mutex;

#[cfg(feature = "no-alloc")]
static CREDENTIAL_STORE: Mutex<FixedCredentialStore<100>> =
    Mutex::new(FixedCredentialStore::new());

#[cfg(feature = "no-alloc")]
pub fn get_credential_store() -> &'static Mutex<FixedCredentialStore<100>> {
    &CREDENTIAL_STORE
}
```

### Estimated effort: 4 hours
### Files created: 1 (storage_fixed.rs)

---

## PHASE 5: Command Handler Refactoring

### 5.1 Add zero-allocation command trait
**File**: `soft-fido2-ctap/src/commands_fixed.rs` (new)
```rust
#[cfg(feature = "no-alloc")]
pub trait CommandHandlerFixed {
    /// Process command with pre-allocated response buffer
    /// Returns length of response written to buffer
    fn handle_to_buffer(
        &mut self,
        cmd: u8,
        request: &[u8],
        response: &mut [u8; max_sizes::CTAP_MESSAGE],
    ) -> Result<usize>;
}
```

### 5.2 Implement zero-allocation makeCredential
```rust
#[cfg(feature = "no-alloc")]
pub fn make_credential_fixed(
    request: &[u8],
    response: &mut [u8; max_sizes::CTAP_MESSAGE],
) -> Result<usize> {
    // Parse request without allocating
    let mut parser = FixedMapParser::from_bytes(request)?;

    // Extract parameters into stack-allocated types
    let mut rp_id = RpId::new();
    parser.get_string(0x01, &mut rp_id)?;

    // ... process credential creation ...

    // Build response directly into buffer
    let mut builder = FixedMapBuilder::<10>::new();
    builder.insert(0x01, &fmt)?;
    builder.insert_bytes(0x02, &auth_data)?;
    builder.insert_bytes(0x03, &attestation_statement)?;

    builder.build_to_slice(response)
}
```

### Estimated effort: 16 hours (all commands)
### Files created: 1 (commands_fixed.rs)

---

## PHASE 6: Callback Interface Updates

### 6.1 Add zero-allocation callback trait
**File**: `soft-fido2-ctap/src/callbacks_fixed.rs` (new)
```rust
#[cfg(feature = "no-alloc")]
pub trait AuthenticatorCallbacksFixed {
    fn request_up(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UpResult>;
    fn request_uv(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UvResult>;

    /// Write credential (no allocation - credential is Copy)
    fn write_credential(&self, cred_id: &[u8], rp_id: &str, cred: Credential) -> Result<()>;

    /// Read credential (no allocation - credential is Copy)
    fn read_credential(&self, cred_id: &[u8], rp_id: &str) -> Result<Option<Credential>>;

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()>;

    /// List credentials with pre-allocated buffer
    fn list_credentials(
        &self,
        rp_id: &str,
        user_id: Option<&[u8]>,
        buffer: &mut [Credential; 100],
    ) -> Result<usize>;
}
```

### Estimated effort: 3 hours
### Files created: 1 (callbacks_fixed.rs)

---

## PHASE 7: Integration & Testing

### 7.1 Create no-alloc example
**File**: `soft-fido2/examples/no_alloc_authenticator.rs` (new)
```rust
#![no_std]
#![no_main]

use soft_fido2_ctap::*;

struct NoAllocCallbacks;

impl AuthenticatorCallbacksFixed for NoAllocCallbacks {
    fn write_credential(&self, cred_id: &[u8], _rp_id: &str, cred: Credential) -> Result<()> {
        get_credential_store().lock().insert(cred)
    }

    fn read_credential(&self, cred_id: &[u8], _rp_id: &str) -> Result<Option<Credential>> {
        Ok(get_credential_store().lock().find(cred_id).copied())
    }

    // ... other callbacks ...
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    let mut response_buffer = [0u8; max_sizes::CTAP_MESSAGE];

    loop {
        // Read command from transport
        let (cmd, request) = read_command();

        // Process without any heap allocation
        match make_credential_fixed(&request, &mut response_buffer) {
            Ok(len) => send_response(&response_buffer[..len]),
            Err(e) => send_error(e),
        }
    }
}
```

### 7.2 Add allocation tracking test
**File**: `soft-fido2-ctap/tests/no_alloc_test.rs` (new)
```rust
#![cfg_attr(feature = "no-alloc", no_std)]

#[cfg(feature = "no-alloc")]
#[global_allocator]
static ALLOCATOR: PanicAllocator = PanicAllocator;

#[cfg(feature = "no-alloc")]
struct PanicAllocator;

#[cfg(feature = "no-alloc")]
unsafe impl GlobalAlloc for PanicAllocator {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 {
        panic!("Attempted heap allocation in no-alloc mode!");
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
        panic!("Attempted heap deallocation in no-alloc mode!");
    }
}

#[cfg(feature = "no-alloc")]
#[test]
fn test_make_credential_no_alloc() {
    // This test will panic if any allocation occurs
    let mut response = [0u8; 7609];
    let request = build_make_credential_request();

    let len = make_credential_fixed(&request, &mut response).unwrap();
    assert!(len > 0);
}
```

### 7.3 Benchmark comparison
**File**: `soft-fido2-ctap/benches/alloc_comparison.rs` (new)
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_with_alloc(c: &mut Criterion) {
    c.bench_function("makeCredential (alloc)", |b| {
        b.iter(|| {
            let request = build_request();
            soft_fido2_ctap::commands::make_credential::handle(black_box(&request))
        });
    });
}

fn benchmark_no_alloc(c: &mut Criterion) {
    c.bench_function("makeCredential (no-alloc)", |b| {
        let mut response = [0u8; 7609];
        b.iter(|| {
            let request = build_request();
            make_credential_fixed(black_box(&request), black_box(&mut response))
        });
    });
}

criterion_group!(benches, benchmark_with_alloc, benchmark_no_alloc);
criterion_main!(benches);
```

### Estimated effort: 8 hours
### Files created: 3 (example, test, benchmark)

---

## PHASE 8: Documentation

### 8.1 Update README.md
- Add "Zero-Allocation Mode" section
- Document feature flags
- Provide embedded usage examples
- Memory footprint comparison

### 8.2 Add architecture documentation
**File**: `ZERO_ALLOC.md` (new)
- Explain dual-API design
- Document size limits from CTAP spec
- Provide migration guide from alloc to no-alloc
- Memory layout diagrams

### 8.3 Add inline documentation
- Document all const generic parameters
- Explain buffer sizing decisions
- Add safety notes for static storage

### Estimated effort: 4 hours
### Files created: 2 (README updates, ZERO_ALLOC.md)

---

## Summary

### Total Estimated Effort
- **Phase 1**: 2 hours
- **Phase 2**: 8 hours
- **Phase 3**: 6 hours
- **Phase 4**: 4 hours
- **Phase 5**: 16 hours
- **Phase 6**: 3 hours
- **Phase 7**: 8 hours
- **Phase 8**: 4 hours
- **Total**: **51 hours** (~6.5 working days)

### Files to Create
- fixed_types.rs
- constants.rs
- types_fixed.rs
- storage_fixed.rs
- commands_fixed.rs
- callbacks_fixed.rs
- examples/no_alloc_authenticator.rs
- tests/no_alloc_test.rs
- benches/alloc_comparison.rs
- ZERO_ALLOC.md

### Files to Modify
- Cargo.toml (workspace)
- soft-fido2-ctap/Cargo.toml
- soft-fido2-ctap/src/lib.rs
- soft-fido2-ctap/src/cbor.rs
- README.md

### Key Dependencies
- heapless = "0.8" (zero-alloc collections)
- spin = "0.9" (no-std Mutex)

### Feature Flags
```toml
default = ["std"]
std = ["alloc", ...]
alloc = []
no-alloc = []  # Mutually exclusive with alloc
```

### Memory Footprint (Estimated)
**Alloc mode** (current):
- Credential: ~500 bytes heap per credential
- Variable based on usage

**No-alloc mode** (target):
- FixedCredentialStore<100>: ~50 KB stack/static
- StackBuffer: 7.6 KB stack
- Per-operation: <1 KB stack
- **Total static**: ~60 KB
- **Peak stack**: ~10 KB
- **Heap**: 0 bytes

### Performance Impact
- **Encoding**: +10-20% faster (no final Vec allocation)
- **Decoding**: Similar (still uses serde)
- **Storage lookup**: Linear search slower for >50 credentials
- **Memory fragmentation**: Eliminated

### Compatibility
- ✅ Backward compatible (alloc mode unchanged)
- ✅ Can mix alloc/no-alloc in different parts
- ❌ Cannot enable both features simultaneously
- ⚠️ No-alloc requires const generic support (MSRV 1.51+)
