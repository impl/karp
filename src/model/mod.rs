// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

mod encrypted_json;
pub(crate) mod hash;
pub(crate) mod jsonrpc;
pub(crate) mod key_material;
pub(crate) mod setup;

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
    pub(crate) fn new_from_jsonrpc(
        session_key: &hash::Secret,
        jsonrpc: &jsonrpc::Jsonrpc,
    ) -> Result<Self> {
        Ok(Self::Jsonrpc {
            jsonrpc: encrypted_json::EncryptedJson::encrypt(session_key, jsonrpc)?,
        })
    }

    pub(crate) const fn as_setup(&self) -> Option<&setup::Setup> {
        match *self {
            Message::Setup(ref setup) => Some(setup),
            Message::Jsonrpc { .. } => None,
        }
    }

    pub(crate) fn as_jsonrpc(
        &self,
        session_key: &hash::Secret,
    ) -> Option<Result<jsonrpc::Jsonrpc>> {
        match *self {
            Message::Setup(_) => None,
            Message::Jsonrpc { ref jsonrpc } => Some(jsonrpc.decrypt(session_key)),
        }
    }
}
