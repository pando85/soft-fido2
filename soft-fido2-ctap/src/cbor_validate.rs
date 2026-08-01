//! Validation for the restricted CBOR profile accepted by CTAP commands.
//!
//! The generic Serde decoder remains responsible for typed deserialization, but
//! this module rejects ambiguous or resource-hostile encodings before any command
//! handler performs authorization or cryptographic verification.

use crate::status::{Result, StatusCode};
use alloc::vec::Vec;

/// CTAP permits at most four nested container levels.
const MAX_NESTING_DEPTH: usize = 4;

/// Validate exactly one deterministic CBOR item.
pub(crate) fn validate_ctap_cbor(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Err(StatusCode::InvalidCbor);
    }

    let mut offset = 0;
    parse_item(data, &mut offset, 0)?;

    if offset != data.len() {
        return Err(StatusCode::InvalidCbor);
    }

    Ok(())
}

fn parse_item(data: &[u8], offset: &mut usize, container_depth: usize) -> Result<()> {
    let initial = *data.get(*offset).ok_or(StatusCode::InvalidCbor)?;
    *offset += 1;

    let major = initial >> 5;
    let additional = initial & 0x1f;

    match major {
        // Unsigned and negative integers.
        0 | 1 => {
            read_argument(data, offset, additional)?;
        }
        // Byte and text strings. Indefinite strings are rejected by
        // read_argument().
        2 | 3 => {
            let length = read_length(data, offset, additional)?;
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= data.len())
                .ok_or(StatusCode::InvalidCbor)?;

            if major == 3 {
                core::str::from_utf8(&data[*offset..end]).map_err(|_| StatusCode::InvalidCbor)?;
            }
            *offset = end;
        }
        // Arrays.
        4 => {
            if container_depth >= MAX_NESTING_DEPTH {
                return Err(StatusCode::InvalidCbor);
            }
            let count = read_length(data, offset, additional)?;
            for _ in 0..count {
                parse_item(data, offset, container_depth + 1)?;
            }
        }
        // Maps. Canonical encodings make the raw key bytes a stable identity,
        // allowing duplicate keys to be rejected without allocating decoded keys.
        5 => {
            if container_depth >= MAX_NESTING_DEPTH {
                return Err(StatusCode::InvalidCbor);
            }
            let count = read_length(data, offset, additional)?;
            let mut keys: Vec<(usize, usize)> = Vec::with_capacity(count.min(32));

            for _ in 0..count {
                let key_start = *offset;
                parse_item(data, offset, container_depth + 1)?;
                let key_end = *offset;

                if keys
                    .iter()
                    .any(|&(start, end)| data[start..end] == data[key_start..key_end])
                {
                    return Err(StatusCode::InvalidCbor);
                }
                keys.push((key_start, key_end));

                parse_item(data, offset, container_depth + 1)?;
            }
        }
        // CTAP CBOR does not use semantic tags.
        6 => return Err(StatusCode::InvalidCbor),
        // Only false, true, and null are needed by CTAP command structures.
        // Floats, undefined, break, and extended simple values are rejected.
        7 => match additional {
            20..=22 => {}
            _ => return Err(StatusCode::InvalidCbor),
        },
        _ => return Err(StatusCode::InvalidCbor),
    }

    Ok(())
}

fn read_length(data: &[u8], offset: &mut usize, additional: u8) -> Result<usize> {
    let value = read_argument(data, offset, additional)?;
    usize::try_from(value).map_err(|_| StatusCode::InvalidCbor)
}

/// Read a CBOR integer/length argument while enforcing its shortest encoding.
fn read_argument(data: &[u8], offset: &mut usize, additional: u8) -> Result<u64> {
    match additional {
        value @ 0..=23 => Ok(value as u64),
        24 => {
            let value = read_exact::<1>(data, offset)?[0] as u64;
            if value < 24 {
                return Err(StatusCode::InvalidCbor);
            }
            Ok(value)
        }
        25 => {
            let value = u16::from_be_bytes(read_exact::<2>(data, offset)?) as u64;
            if value <= u8::MAX as u64 {
                return Err(StatusCode::InvalidCbor);
            }
            Ok(value)
        }
        26 => {
            let value = u32::from_be_bytes(read_exact::<4>(data, offset)?) as u64;
            if value <= u16::MAX as u64 {
                return Err(StatusCode::InvalidCbor);
            }
            Ok(value)
        }
        27 => {
            let value = u64::from_be_bytes(read_exact::<8>(data, offset)?);
            if value <= u32::MAX as u64 {
                return Err(StatusCode::InvalidCbor);
            }
            Ok(value)
        }
        // 28-30 are reserved and 31 denotes an indefinite-length item.
        _ => Err(StatusCode::InvalidCbor),
    }
}

fn read_exact<const N: usize>(data: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .filter(|end| *end <= data.len())
        .ok_or(StatusCode::InvalidCbor)?;
    let bytes: [u8; N] = data[*offset..end]
        .try_into()
        .map_err(|_| StatusCode::InvalidCbor)?;
    *offset = end;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_ctap_map() {
        assert_eq!(validate_ctap_cbor(&[0xa1, 0x01, 0x02]), Ok(()));
    }

    #[test]
    fn rejects_duplicate_map_keys() {
        assert_eq!(
            validate_ctap_cbor(&[0xa2, 0x01, 0x02, 0x01, 0x03]),
            Err(StatusCode::InvalidCbor)
        );
    }

    #[test]
    fn rejects_non_minimal_integer_encoding() {
        assert_eq!(
            validate_ctap_cbor(&[0xa1, 0x18, 0x01, 0x02]),
            Err(StatusCode::InvalidCbor)
        );
    }

    #[test]
    fn rejects_tags_indefinite_items_and_floats() {
        assert!(validate_ctap_cbor(&[0xa1, 0x01, 0xc0, 0x02]).is_err());
        assert!(validate_ctap_cbor(&[0xbf, 0xff]).is_err());
        assert!(validate_ctap_cbor(&[0xfa, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn rejects_trailing_data() {
        assert!(validate_ctap_cbor(&[0xa0, 0xa0]).is_err());
    }

    #[test]
    fn rejects_excessive_nesting() {
        assert!(validate_ctap_cbor(&[0x81, 0x81, 0x81, 0x81, 0x81, 0x00]).is_err());
        assert!(validate_ctap_cbor(&[0x81, 0x81, 0x81, 0x81, 0x00]).is_ok());
    }
}
