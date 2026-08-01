#[cfg(feature = "transport")]
use crate::{callbacks::AuthenticatorCallbacks, dispatcher::CommandDispatcher, status::StatusCode};

/// Bridge between transport CommandHandler and CTAP CommandDispatcher
///
/// Implements the `soft_fido2_transport::CommandHandler` trait to allow
/// the CTAP authenticator to be used with the CTAP HID transport layer.
#[cfg(feature = "transport")]
pub struct TransportBridge<C: AuthenticatorCallbacks> {
    dispatcher: CommandDispatcher<C>,
}

#[cfg(feature = "transport")]
impl<C: AuthenticatorCallbacks> TransportBridge<C> {
    /// Create a new transport bridge
    pub fn new(dispatcher: CommandDispatcher<C>) -> Self {
        Self { dispatcher }
    }

    /// Get a reference to the dispatcher
    pub fn dispatcher(&self) -> &CommandDispatcher<C> {
        &self.dispatcher
    }

    /// Get a mutable reference to the dispatcher
    pub fn dispatcher_mut(&mut self) -> &mut CommandDispatcher<C> {
        &mut self.dispatcher
    }

    /// Consume the bridge and return the dispatcher
    pub fn into_dispatcher(self) -> CommandDispatcher<C> {
        self.dispatcher
    }
}

#[cfg(feature = "transport")]
impl<C: AuthenticatorCallbacks> soft_fido2_transport::CommandHandler for TransportBridge<C> {
    fn handle_command(
        &mut self,
        cmd: soft_fido2_transport::Cmd,
        data: &[u8],
    ) -> soft_fido2_transport::Result<Vec<u8>> {
        match cmd {
            soft_fido2_transport::Cmd::Cbor => {
                // A CTAPHID_CBOR response always begins with a CTAP status byte.
                // CTAP command failures remain CTAPHID_CBOR responses; only
                // HID framing/channel failures are represented as CTAPHID_ERROR.
                match self.dispatcher.dispatch(data) {
                    Ok(payload) => {
                        let mut response = Vec::with_capacity(payload.len() + 1);
                        response.push(StatusCode::Success as u8);
                        response.extend_from_slice(&payload);
                        Ok(response)
                    }
                    Err(status) => Ok(vec![status as u8]),
                }
            }
            soft_fido2_transport::Cmd::Msg => {
                // CTAP1/U2F message - not yet supported
                Err(soft_fido2_transport::Error::Other(
                    "CTAP1/U2F not supported".to_string(),
                ))
            }
            _ => {
                // Other commands should be handled by the transport layer
                // This should not happen in normal operation
                Err(soft_fido2_transport::Error::InvalidCommand)
            }
        }
    }
}

#[cfg(all(test, feature = "transport"))]
mod tests {
    use super::*;

    use crate::{
        authenticator::{Authenticator, AuthenticatorConfig},
        test_utils::MockCallbacks,
    };

    use soft_fido2_transport::CommandHandler;

    #[test]
    fn test_cbor_command() {
        let config = AuthenticatorConfig::new();
        let authenticator = Authenticator::new(config, MockCallbacks);
        let dispatcher = CommandDispatcher::new(authenticator);
        let mut bridge = TransportBridge::new(dispatcher);

        // GetInfo command (0x04) with no data
        let data = vec![0x04];

        let result = bridge.handle_command(soft_fido2_transport::Cmd::Cbor, &data);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.first(), Some(&(StatusCode::Success as u8)));
        assert!(response.len() > 1);
    }

    #[test]
    fn test_cbor_error_is_returned_as_ctap_status() {
        let config = AuthenticatorConfig::new();
        let authenticator = Authenticator::new(config, MockCallbacks);
        let dispatcher = CommandDispatcher::new(authenticator);
        let mut bridge = TransportBridge::new(dispatcher);

        // Unknown CTAP command.
        let result = bridge.handle_command(soft_fido2_transport::Cmd::Cbor, &[0xff]);

        assert_eq!(result.unwrap(), vec![StatusCode::InvalidCommand as u8]);
    }

    #[test]
    fn test_msg_command_unsupported() {
        let config = AuthenticatorConfig::new();
        let authenticator = Authenticator::new(config, MockCallbacks);
        let dispatcher = CommandDispatcher::new(authenticator);
        let mut bridge = TransportBridge::new(dispatcher);

        let data = vec![];
        let result = bridge.handle_command(soft_fido2_transport::Cmd::Msg, &data);
        assert!(result.is_err());
    }
}
