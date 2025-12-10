use super::auth::calculate_auth_param;
use super::cbor_helpers::build_credential_descriptor;

use crate::Transport;
use crate::ctap::CtapCommand;
use crate::error::Result;
use crate::request::{
    CredentialManagementRequest, DeleteCredentialRequest, EnumerateCredentialsRequest,
    UpdateUserRequest,
};
use crate::response::{
    CredentialEnumerationBeginResponse, CredentialInfo, CredentialsMetadata,
    RpEnumerationBeginResponse, RpInfo,
};

use soft_fido2_ctap::cbor::MapBuilder;

/// Credential Management subcommand codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubCommand {
    GetCredsMetadata = 0x01,
    EnumerateRPsBegin = 0x02,
    EnumerateRPsGetNextRP = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

/// Request parameter keys
mod req_keys {
    pub const SUBCOMMAND: i32 = 0x01;
    pub const SUBCOMMAND_PARAMS: i32 = 0x02;
    pub const PIN_UV_AUTH_PROTOCOL: i32 = 0x03;
    pub const PIN_UV_AUTH_PARAM: i32 = 0x04;
}

/// Subcommand parameter keys
mod subparam_keys {
    pub const RP_ID_HASH: i32 = 0x01;
    pub const CREDENTIAL_ID: i32 = 0x02;
    pub const USER: i32 = 0x03;
}

/// Get credentials metadata (total count and remaining slots)
///
/// Returns information about stored discoverable credentials.
/// This is typically the first call when beginning credential management.
pub fn get_credentials_metadata(
    transport: &mut Transport,
    request: CredentialManagementRequest,
) -> Result<CredentialsMetadata> {
    let message = vec![SubCommand::GetCredsMetadata as u8];

    let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
        let pin_uv_auth_param =
            calculate_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

        MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, SubCommand::GetCredsMetadata as u8)?
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, pin_auth.protocol_u8())?
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    } else {
        MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, SubCommand::GetCredsMetadata as u8)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    };

    let response = transport.send_ctap_command(
        CtapCommand::CredentialManagement.as_u8(),
        &request_bytes,
        30000,
    )?;
    CredentialsMetadata::from_cbor(&response)
}

/// Begin RP enumeration
///
/// Returns first RP information and total count.
/// Use `enumerate_rps_get_next` to retrieve remaining RPs,
/// or use `enumerate_rps` convenience method for automatic enumeration.
pub fn enumerate_rps_begin(
    transport: &mut Transport,
    request: CredentialManagementRequest,
) -> Result<RpEnumerationBeginResponse> {
    let message = vec![SubCommand::EnumerateRPsBegin as u8];

    let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
        let pin_uv_auth_param =
            calculate_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

        MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, SubCommand::EnumerateRPsBegin as u8)?
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, pin_auth.protocol_u8())?
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    } else {
        MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, SubCommand::EnumerateRPsBegin as u8)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    };

    let response = transport.send_ctap_command(
        CtapCommand::CredentialManagement.as_u8(),
        &request_bytes,
        30000,
    )?;
    RpEnumerationBeginResponse::from_cbor(&response)
}

/// Get next RP in enumeration
///
/// Stateful command - MUST be called after `enumerate_rps_begin`.
/// Call (total_rps - 1) times to retrieve all remaining RPs.
pub fn enumerate_rps_get_next(transport: &mut Transport) -> Result<RpInfo> {
    let request_bytes = MapBuilder::new()
        .insert(
            req_keys::SUBCOMMAND,
            SubCommand::EnumerateRPsGetNextRP as u8,
        )?
        .build()
        .map_err(|_| crate::error::Error::Other)?;

    let response = transport.send_ctap_command(
        CtapCommand::CredentialManagement.as_u8(),
        &request_bytes,
        30000,
    )?;
    crate::response::RpEnumerationNextResponse::from_cbor(&response)
}

/// Enumerate all RPs (convenience method)
///
/// Automatically handles begin + get_next calls to retrieve all RPs.
/// This is the recommended method for most use cases.
pub fn enumerate_rps(
    transport: &mut Transport,
    request: CredentialManagementRequest,
) -> Result<Vec<RpInfo>> {
    let begin_response = enumerate_rps_begin(transport, request)?;

    let mut rps = Vec::with_capacity(begin_response.total_rps as usize);
    rps.push(begin_response.rp);

    for _ in 1..begin_response.total_rps {
        let rp = enumerate_rps_get_next(transport)?;
        rps.push(rp);
    }

    Ok(rps)
}

/// Begin credential enumeration for an RP
///
/// Returns first credential and total count.
/// Use `enumerate_credentials_get_next` to retrieve remaining credentials,
/// or use `enumerate_credentials` convenience method for automatic enumeration.
pub fn enumerate_credentials_begin(
    transport: &mut Transport,
    request: EnumerateCredentialsRequest,
) -> Result<CredentialEnumerationBeginResponse> {
    let sub_params = MapBuilder::new()
        .insert_bytes(subparam_keys::RP_ID_HASH, request.rp_id_hash())?
        .build()
        .map_err(|_| crate::error::Error::Other)?;

    let mut message = vec![SubCommand::EnumerateCredentialsBegin as u8];
    message.extend_from_slice(&sub_params);

    let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
        let pin_uv_auth_param =
            calculate_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

        let sub_params_value =
            soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                .map_err(|_| crate::error::Error::Other)?;

        MapBuilder::new()
            .insert(
                req_keys::SUBCOMMAND,
                SubCommand::EnumerateCredentialsBegin as u8,
            )?
            .insert(req_keys::SUBCOMMAND_PARAMS, sub_params_value)?
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, pin_auth.protocol_u8())?
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    } else {
        let sub_params_value =
            soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                .map_err(|_| crate::error::Error::Other)?;

        MapBuilder::new()
            .insert(
                req_keys::SUBCOMMAND,
                SubCommand::EnumerateCredentialsBegin as u8,
            )?
            .insert(req_keys::SUBCOMMAND_PARAMS, sub_params_value)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    };

    let response = transport.send_ctap_command(
        CtapCommand::CredentialManagement.as_u8(),
        &request_bytes,
        30000,
    )?;
    CredentialEnumerationBeginResponse::from_cbor(&response)
}

/// Get next credential in enumeration
///
/// Stateful command - MUST be called after `enumerate_credentials_begin`.
/// Call (total_credentials - 1) times to retrieve all remaining credentials.
pub fn enumerate_credentials_get_next(transport: &mut Transport) -> Result<CredentialInfo> {
    let request_bytes = MapBuilder::new()
        .insert(
            req_keys::SUBCOMMAND,
            SubCommand::EnumerateCredentialsGetNextCredential as u8,
        )?
        .build()
        .map_err(|_| crate::error::Error::Other)?;

    let response = transport.send_ctap_command(
        CtapCommand::CredentialManagement.as_u8(),
        &request_bytes,
        30000,
    )?;
    crate::response::CredentialEnumerationNextResponse::from_cbor(&response)
}

/// Enumerate all credentials for an RP (convenience method)
///
/// Automatically handles begin + get_next calls.
pub fn enumerate_credentials(
    transport: &mut Transport,
    request: EnumerateCredentialsRequest,
) -> Result<Vec<CredentialInfo>> {
    let begin_response = enumerate_credentials_begin(transport, request)?;

    let mut credentials = Vec::with_capacity(begin_response.total_credentials as usize);
    credentials.push(begin_response.credential);

    for _ in 1..begin_response.total_credentials {
        let cred = enumerate_credentials_get_next(transport)?;
        credentials.push(cred);
    }

    Ok(credentials)
}

/// Delete a credential
///
/// Permanently removes a credential from the authenticator.
pub fn delete_credential(
    transport: &mut Transport,
    request: DeleteCredentialRequest,
) -> Result<()> {
    let cred_descriptor = build_credential_descriptor(request.credential_id())?;

    let sub_params = MapBuilder::new()
        .insert(subparam_keys::CREDENTIAL_ID, cred_descriptor)?
        .build()
        .map_err(|_| crate::error::Error::Other)?;

    let mut message = vec![SubCommand::DeleteCredential as u8];
    message.extend_from_slice(&sub_params);

    let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
        let pin_uv_auth_param =
            calculate_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

        let sub_params_value =
            soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                .map_err(|_| crate::error::Error::Other)?;

        MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, SubCommand::DeleteCredential as u8)?
            .insert(req_keys::SUBCOMMAND_PARAMS, sub_params_value)?
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, pin_auth.protocol_u8())?
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    } else {
        let sub_params_value =
            soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                .map_err(|_| crate::error::Error::Other)?;

        MapBuilder::new()
            .insert(req_keys::SUBCOMMAND, SubCommand::DeleteCredential as u8)?
            .insert(req_keys::SUBCOMMAND_PARAMS, sub_params_value)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    };

    let _response = transport.send_ctap_command(
        CtapCommand::CredentialManagement.as_u8(),
        &request_bytes,
        30000,
    )?;
    Ok(())
}

/// Update user information for a credential
///
/// Updates the name and displayName fields of a credential's user entity.
pub fn update_user_information(
    transport: &mut Transport,
    request: UpdateUserRequest,
) -> Result<()> {
    let cred_descriptor = build_credential_descriptor(request.credential_id())?;

    let sub_params = MapBuilder::new()
        .insert(subparam_keys::CREDENTIAL_ID, cred_descriptor)?
        .insert(subparam_keys::USER, request.user())?
        .build()
        .map_err(|_| crate::error::Error::Other)?;

    let mut message = vec![SubCommand::UpdateUserInformation as u8];
    message.extend_from_slice(&sub_params);

    let request_bytes = if let Some(pin_auth) = request.pin_uv_auth() {
        let pin_uv_auth_param =
            calculate_auth_param(pin_auth.param(), pin_auth.protocol(), &message)?;

        let sub_params_value =
            soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                .map_err(|_| crate::error::Error::Other)?;

        MapBuilder::new()
            .insert(
                req_keys::SUBCOMMAND,
                SubCommand::UpdateUserInformation as u8,
            )?
            .insert(req_keys::SUBCOMMAND_PARAMS, sub_params_value)?
            .insert(req_keys::PIN_UV_AUTH_PROTOCOL, pin_auth.protocol_u8())?
            .insert_bytes(req_keys::PIN_UV_AUTH_PARAM, &pin_uv_auth_param)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    } else {
        let sub_params_value =
            soft_fido2_ctap::cbor::decode::<soft_fido2_ctap::cbor::Value>(&sub_params)
                .map_err(|_| crate::error::Error::Other)?;

        MapBuilder::new()
            .insert(
                req_keys::SUBCOMMAND,
                SubCommand::UpdateUserInformation as u8,
            )?
            .insert(req_keys::SUBCOMMAND_PARAMS, sub_params_value)?
            .build()
            .map_err(|_| crate::error::Error::Other)?
    };

    let _response = transport.send_ctap_command(
        CtapCommand::CredentialManagement.as_u8(),
        &request_bytes,
        30000,
    )?;
    Ok(())
}
