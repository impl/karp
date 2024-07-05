// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

use crate::error;

use super::model;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("API error: {0}")]
    Api(#[from] Api),
    #[error("Cryptography error: {0}")]
    Cryptography(#[from] crypto_box::aead::Error),
}

#[derive(Error, Debug)]
pub(crate) enum Api {
    #[error("server stream terminated during processing")]
    StreamEnded,
    #[error("nonce provided by host did not match expected value")]
    InvalidNonce,
    #[error("server error ({:?}): {}", .0.error_code(), .0.error())]
    ServerError(model::Error),
}

impl From<Api> for error::Error {
    fn from(value: Api) -> Self {
        Self::Keepassxc(Error::Api(value))
    }
}
