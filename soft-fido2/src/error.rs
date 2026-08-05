//! Error types for CTAP operations

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

use alloc::string::String;

/// Error type for CTAP operations
#[non_exhaustive]
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
    /// No credentials exist for the requested operation
    ///
    /// Returned when:
    /// - Attempting to enumerate credentials for an RP with no credentials
    /// - Attempting to delete a non-existent credential
    NoCredentials,
    /// PIN/UV authentication required but not provided
    PinAuthRequired,
    /// PIN/UV auth token has insufficient permissions
    ///
    /// The token may not have the required permission bit set,
    /// or may have the wrong permissions RP ID.
    UnauthorizedPermission,
    /// Invalid RP ID hash
    ///
    /// RP ID hash must be exactly 32 bytes (SHA-256 output).
    InvalidRpIdHash,
    /// PIN/UV auth token has expired
    PinTokenExpired,
    /// Invalid subcommand for credential management
    InvalidSubcommand,
    /// CTAP error with status code
    CtapError(u8),
    /// IO error (from transport operations)
    IoError(String),
    /// Invalid PIN length (must be 4-63 characters)
    InvalidPinLength,
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
            Error::NoCredentials => write!(f, "No credentials found"),
            Error::PinAuthRequired => write!(f, "PIN/UV authentication required"),
            Error::UnauthorizedPermission => write!(f, "Insufficient permissions"),
            Error::InvalidRpIdHash => write!(f, "Invalid RP ID hash (must be 32 bytes)"),
            Error::PinTokenExpired => write!(f, "PIN/UV auth token expired"),
            Error::InvalidSubcommand => write!(f, "Invalid subcommand"),
            Error::CtapError(code) => write!(f, "CTAP error: 0x{:02X}", code),
            Error::IoError(msg) => write!(f, "IO error: {}", msg),
            Error::InvalidPinLength => write!(f, "Invalid PIN length (must be 4-63 characters)"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

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

impl From<soft_fido2_ctap::StatusCode> for Error {
    fn from(status: soft_fido2_ctap::StatusCode) -> Self {
        use soft_fido2_ctap::StatusCode;

        match status {
            StatusCode::Success => Error::Success,
            StatusCode::Timeout | StatusCode::UserActionTimeout | StatusCode::ActionTimeout => {
                Error::Timeout
            }
            StatusCode::KeyStoreFull => Error::KeyStoreFull,
            StatusCode::NoCredentials => Error::NoCredentials,
            StatusCode::Other => Error::Other,
            _ => Error::CtapError(status.to_u8()),
        }
    }
}

impl From<Error> for soft_fido2_ctap::StatusCode {
    fn from(error: Error) -> Self {
        use soft_fido2_ctap::StatusCode;

        match error {
            Error::Success => StatusCode::Success,
            Error::DoesNotExist | Error::NoCredentials => StatusCode::NoCredentials,
            Error::KeyStoreFull => StatusCode::KeyStoreFull,
            Error::Timeout => StatusCode::Timeout,
            Error::Other => StatusCode::Other,
            Error::CtapError(code) => StatusCode::from_u8(code),
            Error::InvalidPinLength => StatusCode::PinPolicyViolation,
            Error::PinAuthRequired => StatusCode::PuatRequired,
            Error::UnauthorizedPermission => StatusCode::UnauthorizedPermission,
            Error::InvalidRpIdHash => StatusCode::InvalidParameter,
            Error::PinTokenExpired => StatusCode::PinAuthInvalid,
            Error::InvalidSubcommand => StatusCode::InvalidSubcommand,
            _ => StatusCode::Other,
        }
    }
}

// Conversion from IO errors
#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error.to_string())
    }
}

impl Error {
    /// Parse CTAP response and extract CBOR data
    ///
    /// CTAP responses follow the format: `[status_byte, ...cbor_data]`
    /// - `0x00` = success, returns the CBOR data
    /// - `!0x00` = error, converts status byte to Error
    ///
    /// This is the single source of truth for CTAP status code handling.
    pub fn parse_ctap_response(data: &[u8]) -> Result<&[u8]> {
        if data.is_empty() {
            return Err(Error::Other);
        }

        let status_byte = data[0];
        if status_byte == 0x00 {
            // Success - return CBOR data (skip status byte)
            Ok(&data[1..])
        } else {
            // Error - convert status byte to StatusCode, then to Error
            Err(soft_fido2_ctap::StatusCode::from(status_byte).into())
        }
    }
}

/// Result type alias for common operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use soft_fido2_ctap::StatusCode;

    #[test]
    fn status_to_error_uses_the_status_registry() {
        assert_eq!(
            Error::from(StatusCode::PuatRequired),
            Error::CtapError(0x36)
        );
        assert_eq!(Error::from(StatusCode::UpRequired), Error::CtapError(0x3b));
        assert_eq!(
            Error::from(StatusCode::UnauthorizedPermission),
            Error::CtapError(0x40)
        );
    }

    #[test]
    fn ctap_error_round_trips_through_the_status_registry() {
        assert_eq!(
            StatusCode::from(Error::CtapError(0x36)),
            StatusCode::PuatRequired
        );
        assert_eq!(
            StatusCode::from(Error::CtapError(0x3b)),
            StatusCode::UpRequired
        );
        assert_eq!(StatusCode::from(Error::CtapError(0x38)), StatusCode::Other);
        assert_eq!(StatusCode::from(Error::CtapError(0x41)), StatusCode::Other);
    }
}
