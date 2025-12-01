//! CTAP2 status codes
//!
//! Status codes defined in FIDO2 specification:
//! <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#error-responses>

use core::fmt;

/// CTAP2 status codes
///
/// These status codes are returned in CTAP responses to indicate success or various error conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusCode {
    /// Successful completion of command
    Success = 0x00,

    /// Invalid command
    InvalidCommand = 0x01,

    /// Invalid parameter in request
    InvalidParameter = 0x02,

    /// Invalid message or item length
    InvalidLength = 0x03,

    /// Invalid message sequencing
    InvalidSeq = 0x04,

    /// Message timed out
    Timeout = 0x05,

    /// Channel busy
    ChannelBusy = 0x06,

    /// Command requires channel lock
    LockRequired = 0x0A,

    /// Invalid channel
    InvalidChannel = 0x0B,

    /// CBOR unexpected type
    CborUnexpectedType = 0x11,

    /// Invalid CBOR encoding
    InvalidCbor = 0x12,

    /// Missing required parameter
    MissingParameter = 0x14,

    /// Limit exceeded
    LimitExceeded = 0x15,

    /// Unsupported extension
    UnsupportedExtension = 0x16,

    /// Credential excluded (already exists)
    CredentialExcluded = 0x19,

    /// Processing (e.g. waiting for user presence)
    Processing = 0x21,

    /// Invalid credential
    InvalidCredential = 0x22,

    /// User action pending
    UserActionPending = 0x23,

    /// Operation pending
    OperationPending = 0x24,

    /// No operations pending
    NoOperations = 0x25,

    /// Unsupported algorithm
    UnsupportedAlgorithm = 0x26,

    /// Operation denied by user
    OperationDenied = 0x27,

    /// Key store full
    KeyStoreFull = 0x28,

    /// Not busy
    NotBusy = 0x29,

    /// No operation pending
    NoOperationPending = 0x2A,

    /// Unsupported option
    UnsupportedOption = 0x2B,

    /// Invalid option
    InvalidOption = 0x2C,

    /// Keepalive cancel
    KeepaliveCancel = 0x2D,

    /// No credentials found
    NoCredentials = 0x2E,

    /// User action timeout
    UserActionTimeout = 0x2F,

    /// Not allowed
    NotAllowed = 0x30,

    /// PIN invalid
    PinInvalid = 0x31,

    /// PIN blocked
    PinBlocked = 0x32,

    /// PIN/UV auth parameter invalid
    PinAuthInvalid = 0x33,

    /// PIN/UV auth blocked
    PinAuthBlocked = 0x34,

    /// PIN not set
    PinNotSet = 0x35,

    /// PIN required for this operation
    PinRequired = 0x36,

    /// PIN policy violation
    PinPolicyViolation = 0x37,

    /// PIN token expired
    PinTokenExpired = 0x38,

    /// Request too large
    RequestTooLarge = 0x39,

    /// Action timeout
    ActionTimeout = 0x3A,

    /// User presence required
    UpRequired = 0x3B,

    /// User verification blocked
    UvBlocked = 0x3C,

    /// Integrity failure
    IntegrityFailure = 0x3D,

    /// Invalid subcommand
    InvalidSubcommand = 0x3E,

    /// User verification invalid
    UvInvalid = 0x3F,

    /// Unauthorized permission
    UnauthorizedPermission = 0x40,

    /// PIN/UV auth token required
    PuatRequired = 0x41,

    /// Other unspecified error
    Other = 0x7F,
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Success => "Success",
            Self::InvalidCommand => "Invalid command",
            Self::InvalidParameter => "Invalid parameter",
            Self::InvalidLength => "Invalid length",
            Self::InvalidSeq => "Invalid sequence",
            Self::Timeout => "Timeout",
            Self::ChannelBusy => "Channel busy",
            Self::LockRequired => "Lock required",
            Self::InvalidChannel => "Invalid channel",
            Self::CborUnexpectedType => "CBOR unexpected type",
            Self::InvalidCbor => "Invalid CBOR",
            Self::MissingParameter => "Missing parameter",
            Self::LimitExceeded => "Limit exceeded",
            Self::UnsupportedExtension => "Unsupported extension",
            Self::CredentialExcluded => "Credential excluded",
            Self::Processing => "Processing",
            Self::InvalidCredential => "Invalid credential",
            Self::UserActionPending => "User action pending",
            Self::OperationPending => "Operation pending",
            Self::NoOperations => "No operations",
            Self::UnsupportedAlgorithm => "Unsupported algorithm",
            Self::OperationDenied => "Operation denied",
            Self::KeyStoreFull => "Key store full",
            Self::NotBusy => "Not busy",
            Self::NoOperationPending => "No operation pending",
            Self::UnsupportedOption => "Unsupported option",
            Self::InvalidOption => "Invalid option",
            Self::KeepaliveCancel => "Keepalive cancel",
            Self::NoCredentials => "No credentials",
            Self::UserActionTimeout => "User action timeout",
            Self::NotAllowed => "Not allowed",
            Self::PinInvalid => "PIN invalid",
            Self::PinBlocked => "PIN blocked",
            Self::PinAuthInvalid => "PIN auth invalid",
            Self::PinAuthBlocked => "PIN auth blocked",
            Self::PinNotSet => "PIN not set",
            Self::PinRequired => "PIN required",
            Self::PinPolicyViolation => "PIN policy violation",
            Self::PinTokenExpired => "PIN token expired",
            Self::RequestTooLarge => "Request too large",
            Self::ActionTimeout => "Action timeout",
            Self::UpRequired => "UP required",
            Self::UvBlocked => "UV blocked",
            Self::IntegrityFailure => "Integrity failure",
            Self::InvalidSubcommand => "Invalid subcommand",
            Self::UvInvalid => "UV invalid",
            Self::UnauthorizedPermission => "Unauthorized permission",
            Self::PuatRequired => "PIN/UV auth token required",
            Self::Other => "Other error",
        };
        write!(f, "{}", msg)
    }
}

/// Implement std::error::Error only when std is available
#[cfg(feature = "std")]
impl std::error::Error for StatusCode {}

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
            0x41 => Self::PuatRequired,
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
pub type Result<T> = core::result::Result<T, StatusCode>;

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
