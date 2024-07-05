// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{convert::Infallible, io, result};

use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};

use crate::client;
use crate::keepass::error as keepass_error;
use crate::keepassxc::error as keepassxc_error;

pub(crate) type Result<T, E = Error> = result::Result<T, E>;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("IO operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("JSON format error: {0}")]
    Json(serde_json::Error),
    #[error("data conversion error: {0}")]
    Conversion(#[from] Conversion),
    #[error("storage error: {0}")]
    Storage(#[from] Storage),
    #[error("password retrieval error: {0}")]
    Password(#[from] Password),
    #[error("KeePassRPC error: {0}")]
    Keepassrpc(keepass_error::Error),
    #[error("KeePassXC error: {0}")]
    Keepassxc(#[from] keepassxc_error::Error),
    #[error("internal communication error: {0}")]
    Internal(#[from] Internal),
    #[error("command execution failed")]
    Command,
    #[error("operation cancelled")]
    Cancelled,
    #[error(r#"group "{}" does not have a child group named "{}""#, .parent.path.escape_default(), .name.escape_default())]
    GroupNotFound { parent: client::Group, name: String },
    #[error(r#"group "{}" does not have an entry named "{}""#, .parent.path.escape_default(), .name.escape_default())]
    EntryNotFound { parent: client::Group, name: String },
}

impl From<keepass_error::Error> for Error {
    fn from(value: keepass_error::Error) -> Self {
        match value {
            keepass_error::Error::Io(e) => Self::Io(e),
            err @ (keepass_error::Error::Websocket(_)
            | keepass_error::Error::Api(_)
            | keepass_error::Error::Srp(_)
            | keepass_error::Error::ChallengeResponse(_)) => Self::Keepassrpc(err),
        }
    }
}

impl From<pinentry::Error> for Error {
    fn from(value: pinentry::Error) -> Self {
        match value {
            pinentry::Error::Cancelled | pinentry::Error::Timeout => Self::Cancelled,
            pinentry::Error::Io(e) => Self::Io(e),
            pinentry::Error::Encoding(e) => Self::Conversion(Conversion::Encoding(e)),
            err @ pinentry::Error::Gpg(_) => Self::Password(Password::Pinentry(err)),
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
pub(crate) enum Storage {
    #[error("client identifier in storage differs from identifier bound to stream (are you running multiple instances at the same time?)")]
    Conflict,
    #[cfg(feature = "keychain")]
    #[error("no OS-specific filesystem configuration found")]
    NoProjectDirs,
    #[cfg(feature = "secret-service")]
    #[error("secret service error: {0}")]
    SecretService(#[from] oo7::Error),
    #[cfg(feature = "keychain")]
    #[error("Security framework error: {0}")]
    SecurityFramework(#[from] security_framework::base::Error),
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

impl<T> From<watch::error::SendError<T>> for Internal {
    fn from(_: watch::error::SendError<T>) -> Self {
        Self::ChannelClosed
    }
}

impl From<watch::error::RecvError> for Internal {
    fn from(_: watch::error::RecvError) -> Self {
        Self::ChannelClosed
    }
}

impl From<oneshot::error::RecvError> for Internal {
    fn from(_: oneshot::error::RecvError) -> Self {
        Self::ChannelClosed
    }
}
