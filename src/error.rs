// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{convert::Infallible, io, result};

use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::{api, model};

pub(crate) type Result<T, E = Error> = result::Result<T, E>;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("IO operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("WebSocket error: {0}")]
    Websocket(tokio_tungstenite::tungstenite::Error),
    #[error("JSON format error: {0}")]
    Json(serde_json::Error),
    #[error("data conversion error: {0}")]
    Conversion(#[from] Conversion),
    #[error("SRP negotiation error: {0}")]
    Srp(#[from] Srp),
    #[error("challenge-response authentication error: {0}")]
    ChallengeResponse(#[from] ChallengeResponse),
    #[error("API error: {0}")]
    Api(#[from] Api),
    #[error("storage error: {0}")]
    Storage(#[from] Storage),
    #[error("password retrieval error: {0}")]
    Password(#[from] Password),
    #[error("internal communication error: {0}")]
    Internal(#[from] Internal),
    #[error("command execution failed")]
    Command,
    #[error("operation cancelled")]
    Cancelled,
    #[error(r#"group "{}" does not have a child group named "{}""#, .parent.path.escape_default(), .name.escape_default())]
    GroupNotFound {
        parent: Box<api::Group>,
        name: String,
    },
    #[error(r#"group "{}" does not have an entry named "{}""#, .parent.path.escape_default(), .name.escape_default())]
    EntryNotFound {
        parent: Box<api::Group>,
        name: String,
    },
}

impl From<pinentry::Error> for Error {
    fn from(value: pinentry::Error) -> Self {
        // LINT: Deliberate fall-through that should catch future cases added to
        // the enum.
        #[allow(
            clippy::wildcard_enum_match_arm,
            clippy::match_wildcard_for_single_variants
        )]
        match value {
            pinentry::Error::Cancelled | pinentry::Error::Timeout => Self::Cancelled,
            pinentry::Error::Io(e) => Self::Io(e),
            pinentry::Error::Encoding(e) => Self::Conversion(Conversion::Encoding(e)),
            _ => Self::Password(Password::Pinentry(value)),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        // LINT: Deliberate fall-through that should catch future cases added to
        // the enum.
        #[allow(clippy::wildcard_enum_match_arm)]
        match value.classify() {
            serde_json::error::Category::Io => Self::Io(value.into()),
            _ => Self::Json(value),
        }
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::Io(value.into())
    }
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

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

#[derive(Error, Debug)]
pub(crate) enum Conversion {
    #[error("unexpected key material length (wanted {0} bytes, but got {1} bytes")]
    KeyMaterialLength(usize, usize),
    #[error("unexpected hash length (wanted {0} bytes, but got {1} bytes)")]
    HashLength(usize, usize),
    #[error("unexpected non-UTF-8-encoded bytes in input: {0}")]
    Encoding(#[from] std::str::Utf8Error),
    #[error("could not parse data as a number: {0}")]
    Range(#[from] num_bigint::ParseBigIntError),
    #[error("unexpected numerical representation: {0}")]
    NumericalRepresentation(#[from] num_bigint::TryFromBigIntError<num_bigint::BigInt>),
    #[error("encrypted data has invalid padding: {0}")]
    Padding(#[from] block_padding::UnpadError),
}

#[derive(Error, Debug)]
pub(crate) enum Srp {
    #[error("server proof did not match expected value")]
    ServerProofMismatch,
}

#[derive(Error, Debug)]
pub(crate) enum ChallengeResponse {
    #[error("client response did not match expected value: {0}")]
    ClientResponseMismatch(model::setup::Error),
    #[error("server response did not match expected value")]
    ServerResponseMismatch,
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

#[derive(Error, Debug)]
pub(crate) enum Storage {
    #[error("client identifier in storage differs from identifier bound to stream (are you running multiple instances at the same time?)")]
    Conflict,
    #[error("secret service error: {0}")]
    SecretService(#[from] oo7::Error),
}

#[derive(Error, Debug)]
pub(crate) enum Password {
    #[error("no password prompt available")]
    NoPrompt,
    #[error("Pinentry implementation error: {0}")]
    Pinentry(pinentry::Error),
}

#[derive(Error, Debug)]
pub(crate) enum Internal {
    #[error("channel is closed")]
    ChannelClosed,
}

impl<T> From<mpsc::error::SendError<T>> for Internal {
    fn from(_: mpsc::error::SendError<T>) -> Self {
        Self::ChannelClosed
    }
}

impl From<oneshot::error::RecvError> for Internal {
    fn from(_: oneshot::error::RecvError) -> Self {
        Self::ChannelClosed
    }
}
