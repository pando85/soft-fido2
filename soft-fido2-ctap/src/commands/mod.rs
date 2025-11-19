//! CTAP command handlers
//!
//! This module contains the implementations of all CTAP 2.0/2.1 commands.
//!
//! See FIDO2 spec section 6 for command definitions:
//! <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#commands>

pub mod client_pin;
pub mod credential_management;
pub mod get_assertion;
pub mod get_info;
pub mod get_next_assertion;
pub mod make_credential;
pub mod selection;

/// CTAP command codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandCode {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
    CredentialManagement = 0x0A,
    Selection = 0x0B,
    LargeBlobs = 0x0C,
    Config = 0x0D,
}

impl CommandCode {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::MakeCredential),
            0x02 => Some(Self::GetAssertion),
            0x04 => Some(Self::GetInfo),
            0x06 => Some(Self::ClientPin),
            0x07 => Some(Self::Reset),
            0x08 => Some(Self::GetNextAssertion),
            0x0A => Some(Self::CredentialManagement),
            0x0B => Some(Self::Selection),
            0x0C => Some(Self::LargeBlobs),
            0x0D => Some(Self::Config),
            _ => None,
        }
    }
}
