use soft_fido2_ctap::StatusCode;

#[test]
fn ctap_2_3_status_registry_round_trips() {
    let registry = [
        (StatusCode::Success, 0x00),
        (StatusCode::InvalidCommand, 0x01),
        (StatusCode::InvalidParameter, 0x02),
        (StatusCode::InvalidLength, 0x03),
        (StatusCode::InvalidSeq, 0x04),
        (StatusCode::Timeout, 0x05),
        (StatusCode::ChannelBusy, 0x06),
        (StatusCode::LockRequired, 0x0a),
        (StatusCode::InvalidChannel, 0x0b),
        (StatusCode::CborUnexpectedType, 0x11),
        (StatusCode::InvalidCbor, 0x12),
        (StatusCode::MissingParameter, 0x14),
        (StatusCode::LimitExceeded, 0x15),
        (StatusCode::UnsupportedExtension, 0x16),
        (StatusCode::CredentialExcluded, 0x19),
        (StatusCode::Processing, 0x21),
        (StatusCode::InvalidCredential, 0x22),
        (StatusCode::UserActionPending, 0x23),
        (StatusCode::OperationPending, 0x24),
        (StatusCode::NoOperations, 0x25),
        (StatusCode::UnsupportedAlgorithm, 0x26),
        (StatusCode::OperationDenied, 0x27),
        (StatusCode::KeyStoreFull, 0x28),
        (StatusCode::NotBusy, 0x29),
        (StatusCode::NoOperationPending, 0x2a),
        (StatusCode::UnsupportedOption, 0x2b),
        (StatusCode::InvalidOption, 0x2c),
        (StatusCode::KeepaliveCancel, 0x2d),
        (StatusCode::NoCredentials, 0x2e),
        (StatusCode::UserActionTimeout, 0x2f),
        (StatusCode::NotAllowed, 0x30),
        (StatusCode::PinInvalid, 0x31),
        (StatusCode::PinBlocked, 0x32),
        (StatusCode::PinAuthInvalid, 0x33),
        (StatusCode::PinAuthBlocked, 0x34),
        (StatusCode::PinNotSet, 0x35),
        (StatusCode::PuatRequired, 0x36),
        (StatusCode::PinPolicyViolation, 0x37),
        (StatusCode::RequestTooLarge, 0x39),
        (StatusCode::ActionTimeout, 0x3a),
        (StatusCode::UpRequired, 0x3b),
        (StatusCode::UvBlocked, 0x3c),
        (StatusCode::IntegrityFailure, 0x3d),
        (StatusCode::InvalidSubcommand, 0x3e),
        (StatusCode::UvInvalid, 0x3f),
        (StatusCode::UnauthorizedPermission, 0x40),
        (StatusCode::Other, 0x7f),
    ];

    for (status, byte) in registry {
        assert_eq!(status.to_u8(), byte, "wrong wire value for {status:?}");
        assert_eq!(StatusCode::from_u8(byte), status, "failed round-trip for {status:?}");
    }
}

#[test]
fn reserved_or_non_standard_values_are_not_registered() {
    for byte in [0x07, 0x08, 0x09, 0x0c, 0x10, 0x13, 0x17, 0x18, 0x38, 0x41] {
        assert_eq!(StatusCode::from_u8(byte), StatusCode::Other, "0x{byte:02x}");
    }
}
