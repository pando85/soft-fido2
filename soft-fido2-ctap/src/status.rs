//! CTAP2 status codes
//!
//! Status codes defined in FIDO2 specification:
//! <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#error-responses>

use thiserror::Error;

/// CTAP2 status codes
///
/// These status codes are returned in CTAP responses to indicate success or various error conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[repr(u8)]
pub enum StatusCode {
    /// Successful completion of command
    #[error("Success")]
    Success = 0x00,

    /// Invalid command
    #[error("Invalid command")]
    InvalidCommand = 0x01,

    /// Invalid parameter in request
    #[error("Invalid parameter")]
    InvalidParameter = 0x02,

    /// Invalid message or item length
    #[error("Invalid length")]
    InvalidLength = 0x03,

    /// Invalid message sequencing
    #[error("Invalid sequence")]
    InvalidSeq = 0x04,

    /// Message timed out
    #[error("Timeout")]
    Timeout = 0x05,

    /// Channel busy
    #[error("Channel busy")]
    ChannelBusy = 0x06,

    /// Command requires channel lock
    #[error("Lock required")]
    LockRequired = 0x0A,

    /// Invalid channel
    #[error("Invalid channel")]
    InvalidChannel = 0x0B,

    /// CBOR unexpected type
    #[error("CBOR unexpected type")]
    CborUnexpectedType = 0x11,

    /// Invalid CBOR encoding
    #[error("Invalid CBOR")]
    InvalidCbor = 0x12,

    /// Missing required parameter
    #[error("Missing parameter")]
    MissingParameter = 0x14,

    /// Limit exceeded
    #[error("Limit exceeded")]
    LimitExceeded = 0x15,

    /// Unsupported extension
    #[error("Unsupported extension")]
    UnsupportedExtension = 0x16,

    /// Credential excluded (already exists)
    #[error("Credential excluded")]
    CredentialExcluded = 0x19,

    /// Processing (e.g. waiting for user presence)
    #[error("Processing")]
    Processing = 0x21,

    /// Invalid credential
    #[error("Invalid credential")]
    InvalidCredential = 0x22,

    /// User action pending
    #[error("User action pending")]
    UserActionPending = 0x23,

    /// Operation pending
    #[error("Operation pending")]
    OperationPending = 0x24,

    /// No operations pending
    #[error("No operations")]
    NoOperations = 0x25,

    /// Unsupported algorithm
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm = 0x26,

    /// Operation denied by user
    #[error("Operation denied")]
    OperationDenied = 0x27,

    /// Key store full
    #[error("Key store full")]
    KeyStoreFull = 0x28,

    /// Not busy
    #[error("Not busy")]
    NotBusy = 0x29,

    /// No operation pending
    #[error("No operation pending")]
    NoOperationPending = 0x2A,

    /// Unsupported option
    #[error("Unsupported option")]
    UnsupportedOption = 0x2B,

    /// Invalid option
    #[error("Invalid option")]
    InvalidOption = 0x2C,

    /// Keepalive cancel
    #[error("Keepalive cancel")]
    KeepaliveCancel = 0x2D,

    /// No credentials found
    #[error("No credentials")]
    NoCredentials = 0x2E,

    /// User action timeout
    #[error("User action timeout")]
    UserActionTimeout = 0x2F,

    /// Not allowed
    #[error("Not allowed")]
    NotAllowed = 0x30,

    /// PIN invalid
    #[error("PIN invalid")]
    PinInvalid = 0x31,

    /// PIN blocked
    #[error("PIN blocked")]
    PinBlocked = 0x32,

    /// PIN/UV auth parameter invalid
    #[error("PIN auth invalid")]
    PinAuthInvalid = 0x33,

    /// PIN/UV auth blocked
    #[error("PIN auth blocked")]
    PinAuthBlocked = 0x34,

    /// PIN not set
    #[error("PIN not set")]
    PinNotSet = 0x35,

    /// PIN required for this operation
    #[error("PIN required")]
    PinRequired = 0x36,

    /// PIN policy violation
    #[error("PIN policy violation")]
    PinPolicyViolation = 0x37,

    /// PIN token expired
    #[error("PIN token expired")]
    PinTokenExpired = 0x38,

    /// Request too large
    #[error("Request too large")]
    RequestTooLarge = 0x39,

    /// Action timeout
    #[error("Action timeout")]
    ActionTimeout = 0x3A,

    /// User presence required
    #[error("UP required")]
    UpRequired = 0x3B,

    /// User verification blocked
    #[error("UV blocked")]
    UvBlocked = 0x3C,

    /// Integrity failure
    #[error("Integrity failure")]
    IntegrityFailure = 0x3D,

    /// Invalid subcommand
    #[error("Invalid subcommand")]
    InvalidSubcommand = 0x3E,

    /// User verification invalid
    #[error("UV invalid")]
    UvInvalid = 0x3F,

    /// Unauthorized permission
    #[error("Unauthorized permission")]
    UnauthorizedPermission = 0x40,

    /// Other unspecified error
    #[error("Other error")]
    Other = 0x7F,
}

impl StatusCode {
    /// Convert status code to byte value
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Create status code from byte value
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::Success,
            0x01 => Self::InvalidCommand,
            0x02 => Self::InvalidParameter,
            0x03 => Self::InvalidLength,
            0x04 => Self::InvalidSeq,
            0x05 => Self::Timeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            0x11 => Self::CborUnexpectedType,
            0x12 => Self::InvalidCbor,
            0x14 => Self::MissingParameter,
            0x15 => Self::LimitExceeded,
            0x16 => Self::UnsupportedExtension,
            0x19 => Self::CredentialExcluded,
            0x21 => Self::Processing,
            0x22 => Self::InvalidCredential,
            0x23 => Self::UserActionPending,
            0x24 => Self::OperationPending,
            0x25 => Self::NoOperations,
            0x26 => Self::UnsupportedAlgorithm,
            0x27 => Self::OperationDenied,
            0x28 => Self::KeyStoreFull,
            0x29 => Self::NotBusy,
            0x2A => Self::NoOperationPending,
            0x2B => Self::UnsupportedOption,
            0x2C => Self::InvalidOption,
            0x2D => Self::KeepaliveCancel,
            0x2E => Self::NoCredentials,
            0x2F => Self::UserActionTimeout,
            0x30 => Self::NotAllowed,
            0x31 => Self::PinInvalid,
            0x32 => Self::PinBlocked,
            0x33 => Self::PinAuthInvalid,
            0x34 => Self::PinAuthBlocked,
            0x35 => Self::PinNotSet,
            0x36 => Self::PinRequired,
            0x37 => Self::PinPolicyViolation,
            0x38 => Self::PinTokenExpired,
            0x39 => Self::RequestTooLarge,
            0x3A => Self::ActionTimeout,
            0x3B => Self::UpRequired,
            0x3C => Self::UvBlocked,
            0x3D => Self::IntegrityFailure,
            0x3E => Self::InvalidSubcommand,
            0x3F => Self::UvInvalid,
            0x40 => Self::UnauthorizedPermission,
            _ => Self::Other,
        }
    }

    /// Check if this is a success status
    pub fn is_success(self) -> bool {
        self == Self::Success
    }
}

impl From<StatusCode> for u8 {
    fn from(status: StatusCode) -> u8 {
        status.to_u8()
    }
}

impl From<u8> for StatusCode {
    fn from(value: u8) -> Self {
        Self::from_u8(value)
    }
}

impl From<soft_fido2_crypto::CryptoError> for StatusCode {
    fn from(err: soft_fido2_crypto::CryptoError) -> Self {
        match err {
            soft_fido2_crypto::CryptoError::InvalidPublicKey => Self::InvalidParameter,
            soft_fido2_crypto::CryptoError::InvalidPrivateKey => Self::InvalidParameter,
            soft_fido2_crypto::CryptoError::InvalidSignature => Self::InvalidParameter,
            soft_fido2_crypto::CryptoError::DecryptionFailed => Self::PinAuthInvalid,
            soft_fido2_crypto::CryptoError::EncryptionFailed => Self::Other,
            soft_fido2_crypto::CryptoError::InvalidKeyLength { .. } => Self::InvalidParameter,
            soft_fido2_crypto::CryptoError::KeyAgreementFailed => Self::Other,
            soft_fido2_crypto::CryptoError::InvalidCoseKey => Self::InvalidParameter,
        }
    }
}

/// Result type for CTAP operations
pub type Result<T> = std::result::Result<T, StatusCode>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_round_trip() {
        let codes = vec![
            StatusCode::Success,
            StatusCode::InvalidCommand,
            StatusCode::PinInvalid,
            StatusCode::OperationDenied,
        ];

        for code in codes {
            let byte = code.to_u8();
            let recovered = StatusCode::from_u8(byte);
            assert_eq!(code, recovered);
        }
    }

    #[test]
    fn test_unknown_status_code() {
        let unknown = StatusCode::from_u8(0xFF);
        assert_eq!(unknown, StatusCode::Other);
    }

    #[test]
    fn test_is_success() {
        assert!(StatusCode::Success.is_success());
        assert!(!StatusCode::InvalidCommand.is_success());
    }

    #[test]
    fn test_from_crypto_error() {
        let status: StatusCode = soft_fido2_crypto::CryptoError::InvalidPublicKey.into();
        assert_eq!(status, StatusCode::InvalidParameter);

        let status: StatusCode = soft_fido2_crypto::CryptoError::DecryptionFailed.into();
        assert_eq!(status, StatusCode::PinAuthInvalid);
    }
}
