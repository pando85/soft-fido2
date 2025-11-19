//! CTAP Command Types (pure-rust compatibility layer)
//!
//! This module provides API compatibility with zig-ffi for command configuration.
//! In pure-rust implementation, these types are informational only - all commands
//! are supported by default.

/// CTAP 2.1 Command Codes
///
/// This enum is provided for API compatibility with zig-ffi.
/// In pure-rust implementation, all commands are supported by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CtapCommand {
    /// MakeCredential (0x01) - Create a new credential
    MakeCredential = 0x01,
    /// GetAssertion (0x02) - Generate an authentication assertion
    GetAssertion = 0x02,
    /// GetInfo (0x04) - Get authenticator information
    GetInfo = 0x04,
    /// ClientPIN (0x06) - PIN/UV protocol operations
    ClientPin = 0x06,
    /// Reset (0x07) - Reset the authenticator
    Reset = 0x07,
    /// GetNextAssertion (0x08) - Get the next assertion from a batch
    GetNextAssertion = 0x08,
    /// BioEnrollment (0x09) - Biometric enrollment operations
    BioEnrollment = 0x09,
    /// CredentialManagement (0x0a) - Manage stored credentials
    CredentialManagement = 0x0a,
    /// Selection (0x0b) - Authenticator selection
    Selection = 0x0b,
    /// LargeBlobs (0x0c) - Large blob storage operations
    LargeBlobs = 0x0c,
    /// Config (0x0d) - Authenticator configuration
    Config = 0x0d,
}

impl CtapCommand {
    /// Get the command code as a byte value
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Create a CtapCommand from a byte value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::MakeCredential),
            0x02 => Some(Self::GetAssertion),
            0x04 => Some(Self::GetInfo),
            0x06 => Some(Self::ClientPin),
            0x07 => Some(Self::Reset),
            0x08 => Some(Self::GetNextAssertion),
            0x09 => Some(Self::BioEnrollment),
            0x0a => Some(Self::CredentialManagement),
            0x0b => Some(Self::Selection),
            0x0c => Some(Self::LargeBlobs),
            0x0d => Some(Self::Config),
            _ => None,
        }
    }

    /// Get the default set of commands
    pub fn default_commands() -> Vec<Self> {
        vec![
            Self::MakeCredential,
            Self::GetAssertion,
            Self::GetInfo,
            Self::ClientPin,
            Self::Selection,
        ]
    }
}

impl From<CtapCommand> for u8 {
    fn from(cmd: CtapCommand) -> Self {
        cmd.as_u8()
    }
}

impl std::fmt::Display for CtapCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MakeCredential => write!(f, "MakeCredential(0x01)"),
            Self::GetAssertion => write!(f, "GetAssertion(0x02)"),
            Self::GetInfo => write!(f, "GetInfo(0x04)"),
            Self::ClientPin => write!(f, "ClientPin(0x06)"),
            Self::Reset => write!(f, "Reset(0x07)"),
            Self::GetNextAssertion => write!(f, "GetNextAssertion(0x08)"),
            Self::BioEnrollment => write!(f, "BioEnrollment(0x09)"),
            Self::CredentialManagement => write!(f, "CredentialManagement(0x0a)"),
            Self::Selection => write!(f, "Selection(0x0b)"),
            Self::LargeBlobs => write!(f, "LargeBlobs(0x0c)"),
            Self::Config => write!(f, "Config(0x0d)"),
        }
    }
}
