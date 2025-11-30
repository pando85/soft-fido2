//! PIN/UV authentication helpers

use crate::error::{Error, Result};
use crate::request::PinUvAuthProtocol;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Calculate PIN/UV auth parameter
///
/// V1: Returns first 16 bytes of HMAC-SHA-256
/// V2: Returns full 32 bytes of HMAC-SHA-256
pub fn calculate_auth_param(
    token: &[u8],
    protocol: PinUvAuthProtocol,
    message: &[u8],
) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(token).map_err(|_| Error::Other)?;
    mac.update(message);
    let result = mac.finalize();
    let bytes = result.into_bytes();

    match protocol {
        PinUvAuthProtocol::V1 => Ok(bytes[..16].to_vec()),
        PinUvAuthProtocol::V2 => Ok(bytes.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_param_v1_size() {
        let token = vec![0x42; 32];
        let message = vec![0x01];
        let result = calculate_auth_param(&token, PinUvAuthProtocol::V1, &message).unwrap();
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_auth_param_v2_size() {
        let token = vec![0x42; 32];
        let message = vec![0x01];
        let result = calculate_auth_param(&token, PinUvAuthProtocol::V2, &message).unwrap();
        assert_eq!(result.len(), 32);
    }
}
