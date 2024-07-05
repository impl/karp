// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::io;

use thiserror::Error;

use crate::error;

use super::model;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("IO operation failed: {0}")]
    Io(io::Error),
    #[error("WebSocket error: {0}")]
    Websocket(tokio_tungstenite::tungstenite::Error),
    #[error("API error: {0}")]
    Api(#[from] Api),
    #[error("SRP negotiation error: {0}")]
    Srp(#[from] Srp),
    #[error("challenge-response authentication error: {0}")]
    ChallengeResponse(#[from] ChallengeResponse),
}

impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(value: tokio_tungstenite::tungstenite::Error) -> Self {
        // LINT: Deliberate fall-through that should catch future cases added to
        // the enum.
        #[allow(clippy::wildcard_enum_match_arm)]
        match value {
            tokio_tungstenite::tungstenite::Error::Io(e) => Self::Io(e),
            _ => Self::Websocket(value),
        }
    }
}

#[derive(Error, Debug)]
pub(crate) enum Api {
    #[error("server stream terminated during processing")]
    StreamEnded,
    #[error("server sent a message that we did not expect to receive: {0:?}")]
    UnhandledMessage(model::Message),
    #[error("server error: {}: {}", .0.name(), .0.message())]
    ServerError(model::jsonrpc::Error),
    #[error("server security level is too low for us to accept and continue processing (wanted at least {0:?}, but got {1:?})")]
    SecurityLevelTooLow(model::setup::SecurityLevel, model::setup::SecurityLevel),
    #[error("encrypted message could not be authenticated")]
    MessageAuthenticationFailure,
}

impl From<Api> for error::Error {
    fn from(value: Api) -> Self {
        Self::Keepassrpc(Error::Api(value))
    }
}

#[derive(Error, Debug)]
pub(crate) enum Srp {
    #[error("server proof did not match expected value")]
    ServerProofMismatch,
}

impl From<Srp> for error::Error {
    fn from(value: Srp) -> Self {
        Self::Keepassrpc(Error::Srp(value))
    }
}

#[derive(Error, Debug)]
pub(crate) enum ChallengeResponse {
    #[error("client response did not match expected value: {0}")]
    ClientResponseMismatch(model::setup::Error),
    #[error("server response did not match expected value")]
    ServerResponseMismatch,
}

impl From<ChallengeResponse> for error::Error {
    fn from(value: ChallengeResponse) -> Self {
        Self::Keepassrpc(Error::ChallengeResponse(value))
    }
}
