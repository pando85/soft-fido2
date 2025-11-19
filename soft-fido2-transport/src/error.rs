//! Transport layer error types

use std::fmt;

/// Transport layer result type
pub type Result<T> = std::result::Result<T, Error>;

/// Transport layer errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid packet format
    InvalidPacket,

    /// Invalid channel ID
    InvalidChannel,

    /// Invalid command
    InvalidCommand,

    /// Invalid sequence number
    InvalidSequence,

    /// Message too large
    MessageTooLarge,

    /// Message fragmentation error
    FragmentationError,

    /// Timeout waiting for message
    Timeout,

    /// Channel busy
    ChannelBusy,

    /// Device not found
    DeviceNotFound,

    /// I/O error
    IoError(String),

    /// Other error
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPacket => write!(f, "Invalid packet format"),
            Error::InvalidChannel => write!(f, "Invalid channel ID"),
            Error::InvalidCommand => write!(f, "Invalid command"),
            Error::InvalidSequence => write!(f, "Invalid sequence number"),
            Error::MessageTooLarge => write!(f, "Message too large"),
            Error::FragmentationError => write!(f, "Message fragmentation error"),
            Error::Timeout => write!(f, "Timeout waiting for message"),
            Error::ChannelBusy => write!(f, "Channel busy"),
            Error::DeviceNotFound => write!(f, "Device not found"),
            Error::IoError(msg) => write!(f, "I/O error: {}", msg),
            Error::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}
