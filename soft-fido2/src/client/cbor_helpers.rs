//! CBOR encoding helpers for CTAP2

use crate::error::Result;

use soft_fido2_ctap::cbor::Value;

/// Build credential descriptor CBOR map
///
/// Creates map with "id" and "type" in canonical CBOR order
pub fn build_credential_descriptor(credential_id: &[u8]) -> Result<Value> {
    // Canonical order: "id" (len=2) before "type" (len=4)
    Ok(Value::Map(vec![
        (
            Value::Text("id".to_string()),
            Value::Bytes(credential_id.to_vec()),
        ),
        (
            Value::Text("type".to_string()),
            Value::Text("public-key".to_string()),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_descriptor_canonical_order() {
        let cred_id = vec![1, 2, 3, 4];
        let descriptor = build_credential_descriptor(&cred_id).unwrap();

        match descriptor {
            Value::Map(map) => {
                assert_eq!(map.len(), 2);
                // Check "id" comes before "type"
                assert!(matches!(&map[0].0, Value::Text(s) if s == "id"));
                assert!(matches!(&map[1].0, Value::Text(s) if s == "type"));
            }
            _ => panic!("Expected Map"),
        }
    }
}
