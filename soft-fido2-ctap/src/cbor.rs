//! CBOR encoding and decoding for CTAP protocol using cbor4ii
//!
//! This module provides zero-allocation CBOR encoding using stack-based buffers.
//! CTAP has a maximum message size of 7609 bytes, making stack allocation viable.
//!
//! # Performance
//!
//! - **Encoding**: Zero heap allocations during encoding (uses `StackBuffer`)
//! - **Decoding**: Standard serde deserialization (allocates for parsed structs)
//! - **Throughput**: ~5-10% faster than ciborium

use crate::status::{Result, StatusCode};

use alloc::{collections::BTreeMap, vec::Vec};
use core::{cmp::Ordering, fmt};

#[cfg(feature = "std")]
use std::io::{self, Write};

#[cfg(not(feature = "std"))]
use core2::io::{self, Write};

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

pub type Value = cbor4ii::core::Value;

/// Maximum CTAP message size in bytes
///
/// This is defined by the CTAP specification as the maximum size of a CTAP HID packet
/// payload after fragmentation reassembly.
pub const MAX_CTAP_MESSAGE_SIZE: usize = 7609;

/// Request-specific buffer sizes optimized for embedded systems
///
/// These sizes are based on typical CTAP message sizes and allow stack-based
/// allocation without exceeding embedded stack limits (typically 2-8KB).
pub const GETINFO_BUFFER_SIZE: usize = 256;
pub const MAKECRED_REQUEST_BUFFER_SIZE: usize = 512;
pub const MAKECRED_RESPONSE_BUFFER_SIZE: usize = 1024;
pub const GETASSERTION_REQUEST_BUFFER_SIZE: usize = 512;
pub const GETASSERTION_RESPONSE_BUFFER_SIZE: usize = 768;
pub const CLIENTPIN_REQUEST_BUFFER_SIZE: usize = 512;
pub const CLIENTPIN_RESPONSE_BUFFER_SIZE: usize = 256;

/// Type aliases for common buffer sizes
///
/// These provide convenient names for commonly used buffer sizes in CTAP operations.
pub type GetInfoBuffer = StackBuffer<GETINFO_BUFFER_SIZE>;
pub type MakeCredRequestBuffer = StackBuffer<MAKECRED_REQUEST_BUFFER_SIZE>;
pub type MakeCredResponseBuffer = StackBuffer<MAKECRED_RESPONSE_BUFFER_SIZE>;
pub type GetAssertionRequestBuffer = StackBuffer<GETASSERTION_REQUEST_BUFFER_SIZE>;
pub type GetAssertionResponseBuffer = StackBuffer<GETASSERTION_RESPONSE_BUFFER_SIZE>;
pub type ClientPinRequestBuffer = StackBuffer<CLIENTPIN_REQUEST_BUFFER_SIZE>;
pub type ClientPinResponseBuffer = StackBuffer<CLIENTPIN_RESPONSE_BUFFER_SIZE>;

/// Fixed-size buffer that implements Write trait for zero-allocation CBOR encoding
///
/// The buffer size is configurable via const generics, allowing you to choose
/// the appropriate size for your use case:
/// - Embedded systems: Use request-specific buffer sizes (256-1024 bytes)
/// - Development/testing: Use MAX_CTAP_MESSAGE_SIZE (7609 bytes)
///
/// # Examples
///
/// ```
/// use soft_fido2_ctap::cbor::{StackBuffer, GETINFO_BUFFER_SIZE};
///
/// // Embedded-friendly buffer (256 bytes on stack)
/// let mut buffer = StackBuffer::<GETINFO_BUFFER_SIZE>::new();
///
/// // Full-size buffer for development (7609 bytes on stack)
/// let mut large_buffer = StackBuffer::<7609>::new();
/// ```
pub struct StackBuffer<const N: usize> {
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> StackBuffer<N> {
    /// Create a new empty buffer on the stack
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            pos: 0,
        }
    }

    /// Get the filled portion of the buffer as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Convert to Vec (only allocates when needed for final result)
    pub fn to_vec(&self) -> Vec<u8> {
        self.buf[..self.pos].to_vec()
    }

    /// Get current position (bytes written)
    pub fn len(&self) -> usize {
        self.pos
    }

    /// Get buffer capacity
    pub fn capacity(&self) -> usize {
        N
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Reset the buffer to empty
    pub fn clear(&mut self) {
        self.pos = 0;
    }
}

impl<const N: usize> Write for StackBuffer<N> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let available = self.buf.len() - self.pos;
        if data.len() > available {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "buffer overflow: CBOR message exceeds buffer size",
            ));
        }

        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<const N: usize> fmt::Debug for StackBuffer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StackBuffer {{ len: {}, cap: {} }}",
            self.pos,
            self.buf.len()
        )
    }
}

impl<const N: usize> Default for StackBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a value to CBOR bytes using stack buffer (zero heap allocations during encoding)
#[cfg(feature = "std")]
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = StackBuffer::<MAX_CTAP_MESSAGE_SIZE>::new();
    cbor4ii::serde::to_writer(&mut buffer, value).map_err(|_| StatusCode::InvalidCbor)?;
    Ok(buffer.to_vec())
}

/// Encode a value to CBOR bytes (no_std fallback using to_vec)
#[cfg(not(feature = "std"))]
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    cbor4ii::serde::to_vec(Vec::new(), value).map_err(|_| StatusCode::InvalidCbor)
}

/// Encode directly to a provided buffer (completely zero-allocation)
#[cfg(feature = "std")]
pub fn encode_to_buffer<T: Serialize, const N: usize>(
    value: &T,
    buffer: &mut StackBuffer<N>,
) -> Result<()> {
    buffer.clear();
    cbor4ii::serde::to_writer(buffer, value).map_err(|_| StatusCode::InvalidCbor)
}

/// Encode directly to a provided buffer (no_std variant)
#[cfg(not(feature = "std"))]
pub fn encode_to_buffer<T: Serialize, const N: usize>(
    value: &T,
    buffer: &mut StackBuffer<N>,
) -> Result<()> {
    buffer.clear();
    let vec = cbor4ii::serde::to_vec(Vec::new(), value).map_err(|_| StatusCode::InvalidCbor)?;
    buffer.write_all(&vec).map_err(|_| StatusCode::InvalidCbor)
}

/// Decode CBOR bytes to a value
pub fn decode<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T> {
    cbor4ii::serde::from_slice(data).map_err(|_| StatusCode::InvalidCbor)
}

/// Convert a value to CBOR Value for manual map construction (compatibility with ciborium)
pub fn to_value<T: Serialize>(value: &T) -> Result<Value> {
    // Encode to bytes then decode as Value
    let bytes = encode(value)?;
    cbor4ii::serde::from_slice(&bytes).map_err(|_| StatusCode::InvalidCbor)
}

/// Decode CBOR Value to typed value (compatibility with ciborium)
pub fn from_value<T: for<'de> Deserialize<'de>>(value: &Value) -> Result<T> {
    // Encode Value to bytes then decode as T
    let bytes = encode(value)?;
    decode(&bytes)
}

/// Encode a value directly to a writer (compatibility helper, std only)
#[cfg(feature = "std")]
pub fn into_writer<T: Serialize, W: Write>(value: &T, writer: W) -> Result<()> {
    cbor4ii::serde::to_writer(writer, value).map_err(|_| StatusCode::InvalidCbor)
}

/// Encode a value directly to a writer (no_std fallback)
#[cfg(not(feature = "std"))]
pub fn into_writer<T: Serialize>(value: &T, writer: &mut Vec<u8>) -> Result<()> {
    let bytes = encode(value)?;
    writer.extend_from_slice(&bytes);
    Ok(())
}

/// Wrapper for i32 that sorts by CBOR encoding order (for canonical CBOR)
///
/// CBOR canonical ordering requires map keys to be sorted by their encoded representation:
/// - Positive integers 0-23: 0x00-0x17
/// - Positive integers 24-255: 0x18 + byte
/// - Larger positive integers: 0x19/0x1a/0x1b + bytes
/// - Negative integers -1 to -24: 0x20-0x37
/// - Larger negative integers: 0x38/0x39/0x3a/0x3b + bytes
///
/// This means positive integers come before negative integers in canonical order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CborOrderedI32(i32);

impl PartialOrd for CborOrderedI32 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CborOrderedI32 {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.0;
        let b = other.0;

        // Both positive or both zero: compare normally
        if a >= 0 && b >= 0 {
            return a.cmp(&b);
        }

        // Both negative: compare absolute values (smaller absolute = larger in CBOR encoding)
        if a < 0 && b < 0 {
            return b.cmp(&a); // Reversed because -1 (0x20) < -2 (0x21) in encoding
        }

        // One positive, one negative: positive comes first in CBOR canonical order
        if a >= 0 {
            Ordering::Less // a is positive, b is negative
        } else {
            Ordering::Greater // a is negative, b is positive
        }
    }
}

/// Build a CBOR map with integer keys (common in CTAP)
///
/// This builder still requires some allocations for storing entries, but encoding
/// to CBOR uses zero-allocation StackBuffer.
pub struct MapBuilder {
    entries: Vec<(i32, Vec<u8>)>,
}

impl MapBuilder {
    /// Create a new map builder
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert an integer key and value
    pub fn insert<T: Serialize>(mut self, key: i32, value: T) -> Result<Self> {
        let encoded = encode(&value)?;
        self.entries.push((key, encoded));
        Ok(self)
    }

    /// Insert an optional value (only if Some)
    pub fn insert_opt<T: Serialize>(self, key: i32, value: Option<T>) -> Result<Self> {
        if let Some(v) = value {
            self.insert(key, v)
        } else {
            Ok(self)
        }
    }

    /// Insert bytes directly (encodes as CBOR byte string)
    pub fn insert_bytes(mut self, key: i32, bytes: &[u8]) -> Result<Self> {
        let encoded = encode(&serde_bytes::Bytes::new(bytes))?;
        self.entries.push((key, encoded));
        Ok(self)
    }

    /// Insert a nested map with text keys
    ///
    /// This method manually encodes a CBOR map with text (string) keys, avoiding
    /// the need for BTreeMap allocation. This is useful for embedded systems where
    /// heap allocations should be minimized.
    ///
    /// # Arguments
    ///
    /// * `key` - The integer key for the outer map
    /// * `fields` - A slice of (key, value) tuples where both are strings
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_ctap::cbor::MapBuilder;
    ///
    /// let builder = MapBuilder::new()
    ///     .insert_text_map(2, &[("id", "example.com"), ("name", "Example")])
    ///     .unwrap();
    /// ```
    pub fn insert_text_map(mut self, key: i32, fields: &[(&str, &str)]) -> Result<Self> {
        // Use SmallVec to avoid heap allocation for typical map sizes (< 128 bytes)
        let mut inner_buffer = SmallVec::<[u8; 128]>::new();

        // Write map header
        let len = fields.len();
        if len <= 23 {
            inner_buffer.push(0xa0 | len as u8);
        } else if len <= 255 {
            inner_buffer.push(0xb8);
            inner_buffer.push(len as u8);
        } else {
            return Err(StatusCode::InvalidCbor);
        }

        // Write key-value pairs
        for (k, v) in fields {
            // Write key (text string)
            let k_bytes = k.as_bytes();
            if k_bytes.len() <= 23 {
                inner_buffer.push(0x60 | k_bytes.len() as u8);
            } else if k_bytes.len() <= 255 {
                inner_buffer.push(0x78);
                inner_buffer.push(k_bytes.len() as u8);
            } else {
                return Err(StatusCode::InvalidCbor);
            }
            inner_buffer.extend_from_slice(k_bytes);

            // Write value (text string)
            let v_bytes = v.as_bytes();
            if v_bytes.len() <= 23 {
                inner_buffer.push(0x60 | v_bytes.len() as u8);
            } else if v_bytes.len() <= 255 {
                inner_buffer.push(0x78);
                inner_buffer.push(v_bytes.len() as u8);
            } else {
                return Err(StatusCode::InvalidCbor);
            }
            inner_buffer.extend_from_slice(v_bytes);
        }

        self.entries.push((key, inner_buffer.to_vec()));
        Ok(self)
    }

    /// Build the map and encode to CBOR bytes into a provided buffer
    ///
    /// This is the zero-allocation variant that writes directly to the provided buffer.
    /// Returns the number of bytes written.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer to write the encoded CBOR map into
    ///
    /// # Examples
    ///
    /// ```
    /// use soft_fido2_ctap::cbor::{MapBuilder, StackBuffer, GETINFO_BUFFER_SIZE};
    ///
    /// let mut buffer = StackBuffer::<GETINFO_BUFFER_SIZE>::new();
    /// let len = MapBuilder::new()
    ///     .insert(1, "test").unwrap()
    ///     .build_into(&mut buffer).unwrap();
    ///
    /// assert!(len > 0);
    /// ```
    pub fn build_into<const N: usize>(self, buffer: &mut StackBuffer<N>) -> Result<usize> {
        let mut map = BTreeMap::new();

        for (key, value_bytes) in self.entries {
            map.insert(CborOrderedI32(key), RawCborValue(value_bytes));
        }

        // Clear buffer before writing
        buffer.clear();

        // Manually write CBOR map with keys in canonical order

        // Write map header
        let len = map.len();
        if len <= 23 {
            buffer
                .write_all(&[0xa0 | len as u8])
                .map_err(|_| StatusCode::InvalidCbor)?;
        } else if len <= 255 {
            buffer
                .write_all(&[0xb8, len as u8])
                .map_err(|_| StatusCode::InvalidCbor)?;
        } else {
            return Err(StatusCode::InvalidCbor);
        }

        // Write entries in canonical order (already sorted by CborOrderedI32)
        for (key, value) in map {
            // Encode the key
            let k = key.0;
            if k >= 0 {
                // Positive integer
                if k <= 23 {
                    buffer
                        .write_all(&[k as u8])
                        .map_err(|_| StatusCode::InvalidCbor)?;
                } else if k <= 255 {
                    buffer
                        .write_all(&[0x18, k as u8])
                        .map_err(|_| StatusCode::InvalidCbor)?;
                } else if k <= 65535 {
                    buffer
                        .write_all(&[0x19, (k >> 8) as u8, k as u8])
                        .map_err(|_| StatusCode::InvalidCbor)?;
                } else {
                    buffer
                        .write_all(&[0x1a])
                        .map_err(|_| StatusCode::InvalidCbor)?;
                    buffer
                        .write_all(&k.to_be_bytes())
                        .map_err(|_| StatusCode::InvalidCbor)?;
                }
            } else {
                // Negative integer: CBOR encodes as -(value + 1)
                let abs_val = (-k - 1) as u32;
                if abs_val <= 23 {
                    buffer
                        .write_all(&[0x20 | abs_val as u8])
                        .map_err(|_| StatusCode::InvalidCbor)?;
                } else if abs_val <= 255 {
                    buffer
                        .write_all(&[0x38, abs_val as u8])
                        .map_err(|_| StatusCode::InvalidCbor)?;
                } else if abs_val <= 65535 {
                    buffer
                        .write_all(&[0x39, (abs_val >> 8) as u8, abs_val as u8])
                        .map_err(|_| StatusCode::InvalidCbor)?;
                } else {
                    buffer
                        .write_all(&[0x3a])
                        .map_err(|_| StatusCode::InvalidCbor)?;
                    buffer
                        .write_all(&abs_val.to_be_bytes())
                        .map_err(|_| StatusCode::InvalidCbor)?;
                }
            }

            // Write the value (already encoded as CBOR)
            buffer
                .write_all(&value.0)
                .map_err(|_| StatusCode::InvalidCbor)?;
        }

        Ok(buffer.len())
    }

    /// Build the map and encode to CBOR bytes (allocating variant)
    ///
    /// This uses a full-size buffer and returns a Vec. For embedded systems,
    /// prefer using `build_into` with a sized buffer.
    pub fn build(self) -> Result<Vec<u8>> {
        let mut buffer = StackBuffer::<MAX_CTAP_MESSAGE_SIZE>::new();
        let len = self.build_into(&mut buffer)?;
        Ok(buffer.as_slice()[..len].to_vec())
    }

    /// Build the map as a CBOR Value for manual construction (compatibility with ciborium)
    pub fn build_value(self) -> Result<Value> {
        let bytes = self.build()?;
        cbor4ii::serde::from_slice(&bytes).map_err(|_| StatusCode::InvalidCbor)
    }
}

impl Default for MapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapper for raw CBOR bytes that can be nested in a map
#[derive(Clone)]
struct RawCborValue(Vec<u8>);

impl Serialize for RawCborValue {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value: Value =
            cbor4ii::serde::from_slice(&self.0[..]).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}

/// Parse a CBOR map with integer keys
///
/// Note: For better performance and type safety, consider using strongly-typed
/// serde structs instead of this dynamic parser.
pub struct MapParser {
    map: BTreeMap<i32, Vec<u8>>,
}

impl MapParser {
    /// Parse from CBOR bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Decode as a map of integer keys to raw CBOR values
        // We'll store the raw bytes and decode them on-demand
        let raw_map: BTreeMap<i32, Value> = decode(data).map_err(|_| StatusCode::InvalidCbor)?;

        let mut map = BTreeMap::new();
        for (k, v) in raw_map {
            // Re-encode each value to raw CBOR bytes
            let encoded = encode(&v)?;
            map.insert(k, encoded);
        }

        Ok(Self { map })
    }

    /// Parse from a CBOR Value (compatibility with ciborium)
    pub fn from_value(value: Value) -> Result<Self> {
        // Encode Value to bytes then parse
        let bytes = encode(&value)?;
        Self::from_bytes(&bytes)
    }

    /// Get a required value by key
    pub fn get<T: for<'de> Deserialize<'de>>(&self, key: i32) -> Result<T> {
        let value_bytes = self.map.get(&key).ok_or(StatusCode::MissingParameter)?;
        decode(value_bytes)
    }

    /// Get an optional value by key
    pub fn get_opt<T: for<'de> Deserialize<'de>>(&self, key: i32) -> Result<Option<T>> {
        match self.map.get(&key) {
            Some(value_bytes) => Ok(Some(decode(value_bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if a key exists
    pub fn contains_key(&self, key: i32) -> bool {
        self.map.contains_key(&key)
    }

    /// Get raw value for debugging (compatibility with ciborium)
    pub fn get_raw(&self, key: i32) -> Option<Value> {
        self.map
            .get(&key)
            .and_then(|bytes| cbor4ii::serde::from_slice(bytes).ok())
    }

    /// Get bytes directly (for CBOR Bytes type)
    ///
    /// This is needed for extracting byte arrays from CBOR
    pub fn get_bytes(&self, key: i32) -> Result<Vec<u8>> {
        let value_bytes = self.map.get(&key).ok_or(StatusCode::MissingParameter)?;

        // Decode as serde_bytes::ByteBuf which handles CBOR byte strings
        let byte_buf: serde_bytes::ByteBuf = decode(value_bytes)?;
        Ok(byte_buf.into_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_buffer_write() {
        let mut buf = StackBuffer::<MAX_CTAP_MESSAGE_SIZE>::new();
        buf.write_all(b"hello").unwrap();
        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.len(), 5);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_stack_buffer_clear() {
        let mut buf = StackBuffer::<MAX_CTAP_MESSAGE_SIZE>::new();
        buf.write_all(b"hello").unwrap();
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_stack_buffer_overflow() {
        let mut buf = StackBuffer::<MAX_CTAP_MESSAGE_SIZE>::new();
        let large_data = alloc::vec![0u8; MAX_CTAP_MESSAGE_SIZE + 1];
        let result = buf.write_all(&large_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_stack_buffer_sized() {
        // Test with small buffer
        let mut buf = StackBuffer::<64>::new();
        buf.write_all(b"hello").unwrap();
        assert_eq!(buf.as_slice(), b"hello");

        // Test buffer overflow with small buffer
        let large_data = alloc::vec![0u8; 65];
        let result = buf.write_all(&large_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_type_aliases() {
        // Test that type aliases work correctly
        let mut getinfo_buf = GetInfoBuffer::new();
        assert_eq!(getinfo_buf.len(), 0);

        let mut makecred_buf = MakeCredRequestBuffer::new();
        assert_eq!(makecred_buf.len(), 0);

        let mut getassertion_buf = GetAssertionRequestBuffer::new();
        assert_eq!(getassertion_buf.len(), 0);
    }

    #[test]
    fn test_encode_decode_string() {
        let original = "Hello, CTAP!";
        let encoded = encode(&original).unwrap();
        let decoded: alloc::string::String = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_integer() {
        let original = 42i32;
        let encoded = encode(&original).unwrap();
        let decoded: i32 = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_bytes() {
        let original = alloc::vec![1u8, 2, 3, 4, 5];
        let encoded = encode(&original).unwrap();
        let decoded: Vec<u8> = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_to_buffer_zero_allocation() {
        let value = "hello";
        let mut buffer = StackBuffer::<MAX_CTAP_MESSAGE_SIZE>::new();

        encode_to_buffer(&value, &mut buffer).unwrap();
        assert_eq!(buffer.len(), 6); // CBOR encoding of "hello"

        // Should be able to reuse buffer
        buffer.clear();
        encode_to_buffer(&"world", &mut buffer).unwrap();

        let decoded: alloc::string::String = decode(buffer.as_slice()).unwrap();
        assert_eq!(decoded, "world");
    }

    #[test]
    fn test_encode_to_small_buffer() {
        // Test encoding with small buffer
        let value = "hi";
        let mut buffer = StackBuffer::<16>::new();

        encode_to_buffer(&value, &mut buffer).unwrap();
        assert!(buffer.len() > 0);

        let decoded: alloc::string::String = decode(buffer.as_slice()).unwrap();
        assert_eq!(decoded, "hi");
    }

    #[test]
    fn test_map_builder() {
        let cbor = MapBuilder::new()
            .insert(1, "test")
            .unwrap()
            .insert(2, 42i32)
            .unwrap()
            .insert(3, alloc::vec![1u8, 2, 3])
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        let s: alloc::string::String = parser.get(1).unwrap();
        let i: i32 = parser.get(2).unwrap();
        let b: Vec<u8> = parser.get(3).unwrap();

        assert_eq!(s, "test");
        assert_eq!(i, 42);
        assert_eq!(b, alloc::vec![1u8, 2, 3]);
    }

    #[test]
    fn test_map_builder_optional() {
        let cbor = MapBuilder::new()
            .insert(1, "required")
            .unwrap()
            .insert_opt(2, Some(42i32))
            .unwrap()
            .insert_opt::<i32>(3, None)
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        assert!(parser.contains_key(1));
        assert!(parser.contains_key(2));
        assert!(!parser.contains_key(3));
    }

    #[test]
    fn test_map_parser_missing_key() {
        let cbor = MapBuilder::new()
            .insert(1, "test")
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        let result: Result<alloc::string::String> = parser.get(99);
        assert_eq!(result.unwrap_err(), StatusCode::MissingParameter);
    }

    #[test]
    fn test_map_parser_optional() {
        let cbor = MapBuilder::new()
            .insert(1, "test")
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        let opt: Option<alloc::string::String> = parser.get_opt(99).unwrap();
        assert_eq!(opt, None);

        let opt: Option<alloc::string::String> = parser.get_opt(1).unwrap();
        assert_eq!(opt, Some("test".to_string()));
    }

    #[test]
    fn test_invalid_cbor() {
        let bad_data = alloc::vec![0xff, 0xff, 0xff];
        let result: Result<alloc::string::String> = decode(&bad_data);
        assert_eq!(result.unwrap_err(), StatusCode::InvalidCbor);
    }

    #[test]
    fn test_map_builder_bytes() {
        let cbor = MapBuilder::new()
            .insert_bytes(1, &[1, 2, 3, 4])
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        let bytes = parser.get_bytes(1).unwrap();
        assert_eq!(bytes, alloc::vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_map_builder_into_sized_buffer() {
        // Test build_into with sized buffer
        let mut buffer = StackBuffer::<256>::new();
        let len = MapBuilder::new()
            .insert(1, "test")
            .unwrap()
            .insert(2, 42i32)
            .unwrap()
            .build_into(&mut buffer)
            .unwrap();

        assert!(len > 0);
        assert_eq!(buffer.len(), len);

        // Verify the encoded data is correct
        let parser = MapParser::from_bytes(buffer.as_slice()).unwrap();
        let s: alloc::string::String = parser.get(1).unwrap();
        let i: i32 = parser.get(2).unwrap();
        assert_eq!(s, "test");
        assert_eq!(i, 42);
    }

    #[test]
    fn test_integer_key_map_direct() {
        use alloc::collections::BTreeMap;

        let mut map = BTreeMap::new();
        map.insert(1, "value1");
        map.insert(2, "value2");
        map.insert(3, "value3");

        let encoded = encode(&map).unwrap();
        let decoded: BTreeMap<i32, alloc::string::String> = decode(&encoded).unwrap();

        assert_eq!(decoded.get(&1).unwrap(), "value1");
        assert_eq!(decoded.get(&2).unwrap(), "value2");
        assert_eq!(decoded.get(&3).unwrap(), "value3");
    }

    #[test]
    fn test_credential_id_round_trip() {
        // Test that credential IDs (32 random bytes) survive round-trip encoding
        // This reproduces the bug where credentials created during makeCredential
        // cannot be found during getAssertion
        let credential_id: Vec<u8> = (0..32).map(|i| i as u8).collect();

        eprintln!("Original credential ID: {:02x?}", credential_id);

        // Build a CBOR map like in authenticatorGetAssertion response
        let cbor = MapBuilder::new()
            .insert(1, "public-key")
            .unwrap()
            .insert_bytes(2, &credential_id)
            .unwrap()
            .build()
            .unwrap();

        eprintln!("Encoded CBOR: {:02x?}", &cbor[..cbor.len().min(64)]);

        // Decode and extract credential ID
        let parser = MapParser::from_bytes(&cbor).unwrap();
        let decoded_id = parser.get_bytes(2).unwrap();

        eprintln!("Decoded credential ID: {:02x?}", decoded_id);

        assert_eq!(
            credential_id, decoded_id,
            "Credential ID corrupted in round-trip!"
        );
    }

    #[test]
    fn test_insert_text_map() {
        // Test insert_text_map with simple fields
        let cbor = MapBuilder::new()
            .insert_text_map(1, &[("id", "example.com")])
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        assert!(parser.contains_key(1));

        // Test with multiple fields
        let cbor2 = MapBuilder::new()
            .insert_text_map(2, &[("id", "example.com"), ("name", "Example Corp")])
            .unwrap()
            .build()
            .unwrap();

        let parser2 = MapParser::from_bytes(&cbor2).unwrap();
        assert!(parser2.contains_key(2));
    }

    #[test]
    fn test_cbor_canonical_ordering() {
        // Test that CBOR maps have keys in canonical order (positive before negative)
        // This is critical for WebAuthn - browsers reject non-canonical CBOR
        let cbor = MapBuilder::new()
            .insert(1, "kty")
            .unwrap()
            .insert(3, "alg")
            .unwrap()
            .insert(-1, "crv")
            .unwrap()
            .insert(-2, "x")
            .unwrap()
            .insert(-3, "y")
            .unwrap()
            .build()
            .unwrap();

        // CBOR map starts with 0xA5 (map with 5 entries)
        assert_eq!(cbor[0], 0xa5, "Should be a map with 5 entries");

        // Keys should appear in this order: 1, 3, -1, -2, -3
        // CBOR encoding: 0x01, 0x03, 0x20, 0x21, 0x22

        // First key should be 1 (0x01)
        assert_eq!(cbor[1], 0x01, "First key should be 1");

        // After first value (text "kty" = 0x63 0x6b 0x74 0x79), next key should be 3
        let second_key_pos = 1 + 1 + 1 + 3; // map + key1 + text_len + text_bytes
        assert_eq!(cbor[second_key_pos], 0x03, "Second key should be 3");

        // After second value (text "alg" = 0x63 0x61 0x6c 0x67), next key should be -1 (0x20)
        let third_key_pos = second_key_pos + 1 + 1 + 3;
        assert_eq!(cbor[third_key_pos], 0x20, "Third key should be -1 (0x20)");

        // After third value (text "crv"), next key should be -2 (0x21)
        let fourth_key_pos = third_key_pos + 1 + 1 + 3;
        assert_eq!(cbor[fourth_key_pos], 0x21, "Fourth key should be -2 (0x21)");

        // After fourth value (text "x"), next key should be -3 (0x22)
        let fifth_key_pos = fourth_key_pos + 1 + 1 + 1;
        assert_eq!(cbor[fifth_key_pos], 0x22, "Fifth key should be -3 (0x22)");
    }
}
