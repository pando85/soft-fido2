//! Error types for CTAP operations

use std::fmt;

/// Error type for CTAP operations
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// The given operation was successful
    Success,
    /// The given value already exists
    DoesAlreadyExist,
    /// The requested value doesn't exist
    DoesNotExist,
    /// Credentials can't be inserted into the key-store
    KeyStoreFull,
    /// The client ran out of memory
    OutOfMemory,
    /// The operation timed out
    Timeout,
    /// Unspecified operation
    Other,
    /// Initialization failed
    InitializationFailed,
    /// Invalid callback result
    InvalidCallbackResult,
    /// CBOR command failed
    CborCommandFailed(i32),
    /// Invalid client data hash (must be 32 bytes)
    InvalidClientDataHash,
    /// CTAP error with status code
    CtapError(u8),
    /// IO error (from transport operations)
    IoError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Success => write!(f, "Success"),
            Error::DoesAlreadyExist => write!(f, "Value already exists"),
            Error::DoesNotExist => write!(f, "Value does not exist"),
            Error::KeyStoreFull => write!(f, "Key store is full"),
            Error::OutOfMemory => write!(f, "Out of memory"),
            Error::Timeout => write!(f, "Operation timed out"),
            Error::Other => write!(f, "Unspecified error"),
            Error::InitializationFailed => write!(f, "Initialization failed"),
            Error::InvalidCallbackResult => write!(f, "Invalid callback result"),
            Error::CborCommandFailed(code) => {
                write!(f, "CBOR command failed with code {}", code)
            }
            Error::InvalidClientDataHash => {
                write!(f, "Invalid client data hash (must be 32 bytes)")
            }
            Error::CtapError(code) => write!(f, "CTAP error: 0x{:02X}", code),
            Error::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

// Conversion from legacy i32 error codes (zig-ffi)
impl From<i32> for Error {
    fn from(value: i32) -> Self {
        match value {
            0 => Error::Success,
            -1 => Error::DoesAlreadyExist,
            -2 => Error::DoesNotExist,
            -3 => Error::KeyStoreFull,
            -4 => Error::OutOfMemory,
            -5 => Error::Timeout,
            -6 => Error::Other,
            _ => Error::CborCommandFailed(value),
        }
    }
}

// Conversion from keylib-ctap StatusCode (pure Rust implementation)
impl From<soft_fido2_ctap::StatusCode> for Error {
    fn from(status: soft_fido2_ctap::StatusCode) -> Self {
        use soft_fido2_ctap::StatusCode;

        match status {
            StatusCode::Success => Error::Success,
            StatusCode::InvalidCommand => Error::CtapError(0x01),
            StatusCode::InvalidParameter => Error::CtapError(0x02),
            StatusCode::InvalidLength => Error::CtapError(0x03),
            StatusCode::InvalidSeq => Error::CtapError(0x04),
            StatusCode::Timeout => Error::Timeout,
            StatusCode::ChannelBusy => Error::CtapError(0x06),
            StatusCode::LockRequired => Error::CtapError(0x0A),
            StatusCode::InvalidChannel => Error::CtapError(0x0B),
            StatusCode::CborUnexpectedType => Error::CtapError(0x11),
            StatusCode::InvalidCbor => Error::CtapError(0x12),
            StatusCode::MissingParameter => Error::CtapError(0x14),
            StatusCode::LimitExceeded => Error::CtapError(0x15),
            StatusCode::UnsupportedExtension => Error::CtapError(0x16),
            StatusCode::CredentialExcluded => Error::CtapError(0x19),
            StatusCode::Processing => Error::CtapError(0x21),
            StatusCode::InvalidCredential => Error::CtapError(0x22),
            StatusCode::UserActionPending => Error::CtapError(0x23),
            StatusCode::OperationPending => Error::CtapError(0x24),
            StatusCode::NoOperations => Error::CtapError(0x25),
            StatusCode::UnsupportedAlgorithm => Error::CtapError(0x26),
            StatusCode::OperationDenied => Error::CtapError(0x27),
            StatusCode::KeyStoreFull => Error::KeyStoreFull,
            StatusCode::NotBusy => Error::CtapError(0x29),
            StatusCode::NoOperationPending => Error::CtapError(0x2A),
            StatusCode::UnsupportedOption => Error::CtapError(0x2B),
            StatusCode::InvalidOption => Error::CtapError(0x2C),
            StatusCode::KeepaliveCancel => Error::CtapError(0x2D),
            StatusCode::NoCredentials => Error::DoesNotExist,
            StatusCode::UserActionTimeout => Error::Timeout,
            StatusCode::NotAllowed => Error::CtapError(0x30),
            StatusCode::PinInvalid => Error::CtapError(0x31),
            StatusCode::PinBlocked => Error::CtapError(0x32),
            StatusCode::PinAuthInvalid => Error::CtapError(0x33),
            StatusCode::PinAuthBlocked => Error::CtapError(0x34),
            StatusCode::PinNotSet => Error::CtapError(0x35),
            StatusCode::PinRequired => Error::CtapError(0x36),
            StatusCode::PinPolicyViolation => Error::CtapError(0x37),
            StatusCode::PinTokenExpired => Error::CtapError(0x38),
            StatusCode::RequestTooLarge => Error::CtapError(0x39),
            StatusCode::ActionTimeout => Error::Timeout,
            StatusCode::UpRequired => Error::CtapError(0x3A),
            StatusCode::UvBlocked => Error::CtapError(0x3C),
            StatusCode::IntegrityFailure => Error::CtapError(0x3D),
            StatusCode::InvalidSubcommand => Error::CtapError(0x3E),
            StatusCode::UvInvalid => Error::CtapError(0x3F),
            StatusCode::UnauthorizedPermission => Error::CtapError(0x40),
            StatusCode::Other => Error::Other,
        }
    }
}

// Conversion to keylib-ctap StatusCode (pure Rust implementation)
impl From<Error> for soft_fido2_ctap::StatusCode {
    fn from(error: Error) -> Self {
        use soft_fido2_ctap::StatusCode;

        match error {
            Error::Success => StatusCode::Success,
            Error::DoesNotExist => StatusCode::NoCredentials,
            Error::KeyStoreFull => StatusCode::KeyStoreFull,
            Error::Timeout => StatusCode::Timeout,
            Error::Other => StatusCode::Other,
            Error::CtapError(code) => {
                // Map back to StatusCode
                match code {
                    0x01 => StatusCode::InvalidCommand,
                    0x02 => StatusCode::InvalidParameter,
                    0x03 => StatusCode::InvalidLength,
                    0x04 => StatusCode::InvalidSeq,
                    0x06 => StatusCode::ChannelBusy,
                    0x0A => StatusCode::LockRequired,
                    0x0B => StatusCode::InvalidChannel,
                    0x11 => StatusCode::CborUnexpectedType,
                    0x12 => StatusCode::InvalidCbor,
                    0x14 => StatusCode::MissingParameter,
                    0x15 => StatusCode::LimitExceeded,
                    0x31 => StatusCode::PinInvalid,
                    0x33 => StatusCode::PinAuthInvalid,
                    0x35 => StatusCode::PinNotSet,
                    0x36 => StatusCode::PinRequired,
                    _ => StatusCode::Other,
                }
            }
            _ => StatusCode::Other,
        }
    }
}

// Conversion from IO errors
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error.to_string())
    }
}

/// Result type alias for common operations
pub type Result<T> = std::result::Result<T, Error>;
