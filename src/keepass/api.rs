// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use async_trait::async_trait;
use secrecy::SecretString;
use serde::Deserialize;
use serde_repr::Deserialize_repr;
use serde_with::{base64::Base64, serde_as};
use tokio::sync::{mpsc, oneshot};

use crate::{
    client,
    error::{self, Result},
};

use super::{
    error as keepass_error,
    model::jsonrpc::{Jsonrpc, Request, Response, ResponseVariant},
};

#[derive(Debug)]
pub(super) struct Call {
    pub(super) req: Jsonrpc,
    pub(super) tx: oneshot::Sender<Result<Response>>,
}

impl Call {
    pub(super) fn new<T: Into<Request>>(req: T, tx: oneshot::Sender<Result<Response>>) -> Self {
        Self {
            req: Jsonrpc::Request(req.into()),
            tx,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub(super) enum FormFieldType {
    #[serde(rename = "FFTradio")]
    Radio,
    #[serde(rename = "FFTusername")]
    Username,
    #[serde(rename = "FFTtext")]
    Text,
    #[serde(rename = "FFTpassword")]
    Password,
    #[serde(rename = "FFTselect")]
    Select,
    #[serde(rename = "FFTcheckbox")]
    Checkbox,
}

impl From<FormFieldType> for client::FormFieldType {
    fn from(value: FormFieldType) -> Self {
        match value {
            FormFieldType::Radio => Self::Radio,
            FormFieldType::Username => Self::Username,
            FormFieldType::Text => Self::Text,
            FormFieldType::Password => Self::Password,
            FormFieldType::Select => Self::Select,
            FormFieldType::Checkbox => Self::Checkbox,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub(super) enum PlaceholderHandling {
    Default,
    Enabled,
    Disabled,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FormField {
    pub(super) type_: FormFieldType,
    pub(super) display_name: String,
    pub(super) value: SecretString,
    pub(super) id: String,
    pub(super) name: String,
    pub(super) page: i32,
    pub(super) placeholder_handling: PlaceholderHandling,
}

impl From<FormField> for client::FormField {
    fn from(value: FormField) -> Self {
        Self {
            type_: value.type_.into(),
            display_name: value.display_name,
            value: value.value,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize_repr, PartialEq)]
#[repr(u8)]
pub(super) enum MatchAccuracy {
    Best = 50,
    Close = 40,
    HostnameAndPort = 30,
    HostnameExcludingPort = 20,
    Domain = 10,
    None = 0,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Entry {
    #[serde(rename = "uniqueID")]
    pub(super) unique_id: String,
    #[serde(rename = "uRLs")]
    pub(super) urls: Vec<String>,
    pub(super) parent: Option<Group>,
    pub(super) title: String,
    pub(super) username_value: Option<String>,
    pub(super) username_name: Option<String>,
    #[serde_as(as = "Base64")]
    pub(super) icon_image_data: Vec<u8>,
    #[serde(rename = "hTTPRealm")]
    pub(super) http_realm: Option<String>,
    pub(super) form_field_list: Option<Vec<FormField>>,
    pub(super) match_accuracy: Option<MatchAccuracy>,
    pub(super) always_auto_fill: Option<bool>,
    pub(super) never_auto_fill: Option<bool>,
    pub(super) always_auto_submit: Option<bool>,
    pub(super) never_auto_submit: Option<bool>,
    pub(super) relevancy: Option<i32>,
    pub(super) db: Option<Database>,
}

impl From<Entry> for client::Entry {
    fn from(value: Entry) -> Self {
        Self {
            id: value.unique_id,
            parent: value.parent.map(client::Group::from),
            title: value.title,
            form_fields: value
                .form_field_list
                .unwrap_or_default()
                .into_iter()
                .map(client::FormField::from)
                .collect(),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Group {
    pub(super) title: String,
    #[serde(rename = "uniqueID")]
    pub(super) unique_id: String,
    #[serde_as(as = "Base64")]
    pub(super) icon_image_data: Vec<u8>,
    pub(super) path: String,
    pub(super) child_groups: Option<Vec<Group>>,
    #[serde(alias = "childLightEntries")]
    pub(super) child_entries: Option<Vec<Entry>>,
}

impl From<Group> for client::Group {
    fn from(value: Group) -> Self {
        Self { path: value.path }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Database {
    pub(super) name: String,
    pub(super) file_name: String,
    pub(super) root: Group,
    pub(super) active: bool,
    #[serde_as(as = "Base64")]
    pub(super) icon_image_data: Vec<u8>,
}

#[async_trait]
pub(super) trait Executor {
    type Response;

    async fn execute(self, tx: mpsc::Sender<Call>) -> Result<Self::Response>
    where
        Self: TryInto<Request>,
        error::Error: From<<Self as TryInto<Request>>::Error>,
        Self::Response: for<'de> Deserialize<'de>,
    {
        let req = self.try_into()?;
        let (ltx, lrx) = oneshot::channel();
        tx.send(Call::new(req, ltx))
            .await
            .map_err(error::Internal::from)?;
        match *lrx.await.map_err(error::Internal::from)??.variant() {
            ResponseVariant::Result(ref r) => Ok(serde_json::from_value(r.clone())?),
            ResponseVariant::Error(ref e) => Err(keepass_error::Api::ServerError(e.clone()).into()),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub(super) struct FindLogins {
    pub(super) unsanitized_urls: Vec<String>,
    pub(super) action_url: Option<String>,
    pub(super) http_realm: Option<String>,
    pub(super) require_full_url_matches: bool,
    pub(super) unique_id: Option<String>,
    pub(super) db_root_id: Option<String>,
    pub(super) free_text_search: Option<String>,
    pub(super) username: Option<String>,
}

impl TryFrom<FindLogins> for Request {
    type Error = error::Error;

    fn try_from(value: FindLogins) -> Result<Self, Self::Error> {
        Ok(Self::new(
            "FindLogins",
            [
                serde_json::to_value(&value.unsanitized_urls)?,
                serde_json::to_value(value.action_url.as_ref())?,
                serde_json::to_value(value.http_realm.as_ref())?,
                // This is the former LoginSearchType field, which is no longer used.
                serde_json::Value::Null,
                value.require_full_url_matches.into(),
                serde_json::to_value(value.unique_id.as_ref())?,
                serde_json::to_value(value.db_root_id.as_ref())?,
                serde_json::to_value(value.free_text_search.as_ref())?,
                serde_json::to_value(value.username.as_ref())?,
            ],
        ))
    }
}

impl Executor for FindLogins {
    type Response = Vec<Entry>;
}

pub(super) struct GetAllChildEntries {
    pub(super) uuid: String,
}

impl From<GetAllChildEntries> for Request {
    fn from(value: GetAllChildEntries) -> Self {
        Self::new("GetAllChildEntries", [value.uuid.into()])
    }
}

impl Executor for GetAllChildEntries {
    type Response = Vec<Entry>;
}

pub(super) struct GetAllDatabases {
    pub(super) full_details: bool,
}

impl From<GetAllDatabases> for Request {
    fn from(value: GetAllDatabases) -> Self {
        Self::new("GetAllDatabases", [value.full_details.into()])
    }
}

impl Executor for GetAllDatabases {
    type Response = Vec<Database>;
}

pub(super) struct GetChildGroups {
    pub(super) uuid: String,
}

impl From<GetChildGroups> for Request {
    fn from(value: GetChildGroups) -> Self {
        Self::new("GetChildGroups", [value.uuid.into()])
    }
}

impl Executor for GetChildGroups {
    type Response = Vec<Group>;
}

pub(super) struct GetRoot;

impl From<GetRoot> for Request {
    fn from(_: GetRoot) -> Self {
        Self::new("GetRoot", [])
    }
}

impl Executor for GetRoot {
    type Response = Group;
}
