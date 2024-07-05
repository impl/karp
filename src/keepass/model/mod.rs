// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

mod encrypted_json;
pub(super) mod hash;
pub(super) mod jsonrpc;
pub(super) mod key_material;
pub(super) mod setup;

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "protocol", rename_all = "camelCase")]
pub(crate) enum Message {
    #[serde(rename_all = "camelCase")]
    Setup(setup::Setup),
    Jsonrpc {
        jsonrpc: encrypted_json::EncryptedJson<jsonrpc::Jsonrpc>,
    },
}

impl Message {
    pub(super) fn new_from_jsonrpc(
        session_key: &hash::Secret,
        jsonrpc: &jsonrpc::Jsonrpc,
    ) -> Result<Self> {
        Ok(Self::Jsonrpc {
            jsonrpc: encrypted_json::EncryptedJson::encrypt(session_key, jsonrpc)?,
        })
    }

    pub(super) const fn as_setup(&self) -> Option<&setup::Setup> {
        match *self {
            Message::Setup(ref setup) => Some(setup),
            Message::Jsonrpc { .. } => None,
        }
    }

    pub(super) fn as_jsonrpc(
        &self,
        session_key: &hash::Secret,
    ) -> Option<Result<jsonrpc::Jsonrpc>> {
        match *self {
            Message::Setup(_) => None,
            Message::Jsonrpc { ref jsonrpc } => Some(jsonrpc.decrypt(session_key)),
        }
    }
}
