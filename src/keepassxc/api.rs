// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, json::JsonString, serde_as};
use tokio::sync::{mpsc, oneshot};

use crate::{
    client,
    error::{self, Result},
};

use super::model;

#[derive(Debug)]
pub(super) struct Call {
    pub(super) action: String,
    pub(super) req: serde_json::Value,
    pub(super) tx: oneshot::Sender<Result<serde_json::Value>>,
}

impl Call {
    pub(super) fn new(
        action: String,
        req: serde_json::Value,
        tx: oneshot::Sender<Result<serde_json::Value>>,
    ) -> Self {
        Self { action, req, tx }
    }
}

impl model::HasAction for Call {
    fn action(&self) -> &str {
        &self.action
    }
}

impl Serialize for Call {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.req.serialize(serializer)
    }
}

pub(super) trait HasConstAction {
    const ACTION: &'static str;
}

impl<T: HasConstAction> model::HasAction for T {
    fn action(&self) -> &str {
        Self::ACTION
    }
}

#[async_trait]
pub(super) trait Executor: model::HasAction {
    type Response;

    async fn execute(self, tx: mpsc::Sender<Call>) -> Result<Self::Response>
    where
        Self: Serialize + Sized,
        Self::Response: for<'de> Deserialize<'de>,
    {
        let req = serde_json::to_value(&self)?;
        let (ltx, lrx) = oneshot::channel();
        tx.send(Call::new(self.action().to_owned(), req, ltx))
            .await
            .map_err(error::Internal::from)?;
        Ok(serde_json::from_value(
            lrx.await.map_err(error::Internal::from)??,
        )?)
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Entry {
    pub(super) login: String,
    pub(super) name: String,
    pub(super) password: SecretString,
    pub(super) uuid: String,
    pub(super) group: String,
    pub(super) totp: Option<String>,
    #[serde_as(as = "JsonString")]
    #[serde(default)]
    pub(super) expired: bool,
}

impl From<Entry> for client::Entry {
    fn from(value: Entry) -> Self {
        let form_fields = vec![
            client::FormField {
                type_: client::FormFieldType::Username,
                display_name: "KeePass username".to_owned(),
                value: value.login.into(),
            },
            client::FormField {
                type_: client::FormFieldType::Password,
                display_name: "KeePass password".to_owned(),
                value: value.password,
            },
        ];

        client::Entry {
            id: value.uuid,
            parent: if value.group.is_empty() {
                None
            } else {
                Some(client::Group { path: value.group })
            },
            title: value.name,
            form_fields,
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChangePublicKeysRequest {
    #[serde_as(as = "Base64")]
    pub(super) nonce: [u8; model::key_material::NONCE_SIZE],
    #[serde_as(as = "Base64")]
    pub(super) public_key: [u8; model::key_material::KEY_SIZE],
}

impl HasConstAction for ChangePublicKeysRequest {
    const ACTION: &'static str = "change-public-keys";
}

impl model::HasNonce for ChangePublicKeysRequest {
    fn nonce(&self) -> &model::key_material::Nonce {
        model::key_material::Nonce::from_slice(&self.nonce)
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChangePublicKeysResponse {
    #[serde_as(as = "Base64")]
    pub(super) nonce: [u8; model::key_material::NONCE_SIZE],
    #[serde_as(as = "Base64")]
    pub(super) public_key: [u8; model::key_material::KEY_SIZE],
}

impl model::HasNonce for ChangePublicKeysResponse {
    fn nonce(&self) -> &model::key_material::Nonce {
        model::key_material::Nonce::from_slice(&self.nonce)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GetDatabaseHashRequest {
    pub(super) action: String,
}

impl HasConstAction for GetDatabaseHashRequest {
    const ACTION: &'static str = "get-databasehash";
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GetDatabaseHashResponse {
    pub(super) hash: String,
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AssociateRequest {
    #[serde_as(as = "Base64")]
    pub(super) key: [u8; model::key_material::KEY_SIZE],
    #[serde_as(as = "Base64")]
    pub(super) id_key: [u8; model::key_material::KEY_SIZE],
}

impl HasConstAction for AssociateRequest {
    const ACTION: &'static str = "associate";
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AssociateResponse {
    pub(super) id: String,
    pub(super) hash: String,
}

#[serde_as]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TestAssociateRequest {
    pub(super) id: String,
    #[serde_as(as = "Base64")]
    pub(super) key: [u8; model::key_material::KEY_SIZE],
}

impl HasConstAction for TestAssociateRequest {
    const ACTION: &'static str = "test-associate";
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TestAssociateResponse {
    pub(super) id: String,
    pub(super) hash: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GetLoginsRequest {
    pub(super) url: String,
    pub(super) submit_url: Option<String>,
    pub(super) http_auth: Option<bool>,
}

impl HasConstAction for GetLoginsRequest {
    const ACTION: &'static str = "get-logins";
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GetLoginsResponse {
    pub(super) count: u64,
    pub(super) entries: Vec<Entry>,
}

impl Executor for GetLoginsRequest {
    type Response = GetLoginsResponse;
}

#[derive(Debug)]
pub(super) enum Signal {
    DatabaseLocked,
    DatabaseUnlocked,
}

impl model::HasAction for Signal {
    fn action(&self) -> &str {
        match *self {
            Signal::DatabaseLocked => "database-locked",
            Signal::DatabaseUnlocked => "database-unlocked",
        }
    }
}
