use soft_fido2::{Credential, Extensions, RelyingParty, User};
use soft_fido2_ctap::SecBytes;

#[test]
fn test_credential_from_bytes_roundtrip() {
    // Build a sample credential
    let rp = RelyingParty {
        id: "example.com".to_string(),
        name: Some("Example".to_string()),
    };

    let user = User {
        id: vec![1u8, 2, 3, 4],
        name: Some("alice@example.com".to_string()),
        display_name: Some("Alice".to_string()),
    };

    let private_key = SecBytes::new(vec![0x42u8; 32]);

    let cred = Credential {
        id: vec![9u8, 8, 7],
        rp,
        user,
        sign_count: 7,
        alg: -7,
        private_key: private_key.clone(),
        created: 1_700_000_000,
        discoverable: true,
        extensions: Extensions {
            cred_protect: Some(1),
            hmac_secret: Some(true),
            cred_random: None,
        },
    };

    // Serialize to CBOR bytes
    // Also prepare the CTAP-shaped credential to inspect
    let ctap_cred: soft_fido2_ctap::types::Credential = cred.clone().into();

    let c_value = soft_fido2_ctap::cbor::to_value(&ctap_cred).expect("to_value ctap");
    eprintln!("CTAP CBOR Value: {:?}", c_value);

    let bytes = cred.to_bytes().expect("serialize credential to bytes");
    eprintln!(
        "CBOR bytes len: {} hex: {}",
        bytes.len(),
        hex::encode(&bytes)
    );

    // Also show the CBOR value representation for debugging
    let value = soft_fido2_ctap::cbor::to_value(&cred).expect("to_value");
    eprintln!("CBOR Value: {:?}", value);

    // Deserialize back
    let decoded = match Credential::from_bytes(&bytes) {
        Ok(c) => c,
        Err(e) => {
            // Try decoding to a generic CBOR value to inspect the serialized shape
            if let Ok(v) = soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&bytes) {
                eprintln!("Fallback decoded CBOR Value: {:?}", v);
            } else {
                eprintln!("Failed to decode to generic CBOR Value");
            }

            // Try decoding directly to the CTAP `Credential` type using CTAP cbor::decode
            match soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::types::Credential>(&bytes) {
                Ok(cc) => eprintln!("CTAP decode succeeded: {:?}", cc),
                Err(code) => eprintln!("CTAP decode error: {:?}", code),
            }

            // Try lower-level cbor4ii error to get more detail
            match cbor4ii::serde::from_slice::<soft_fido2_ctap::types::Credential>(&bytes) {
                Ok(_) => eprintln!("cbor4ii low-level decode succeeded"),
                Err(e) => eprintln!("cbor4ii low-level error: {:?}", e),
            }

            panic!("deserialize credential from bytes: {:?}", e);
        }
    };

    // Credentials should be equal
    assert_eq!(cred, decoded);

    // Private key content should match exactly
    assert_eq!(cred.private_key.as_slice(), decoded.private_key.as_slice());
}
