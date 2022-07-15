// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use async_trait::async_trait;
use clap::{clap_derive::ArgEnum, ValueEnum};
use futures_util::{Stream, StreamExt};
use inflector::Inflector;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_repr::Deserialize_repr;
use serde_with::{base64::Base64, serde_as};
use tabled::Tabled;
use tokio::sync::{mpsc, oneshot};

use crate::{
    error::{self, Result},
    manager,
    model::jsonrpc::{Request, ResponseVariant},
};

#[derive(ArgEnum, Copy, Clone, Debug, Deserialize, PartialEq, Tabled)]
pub(crate) enum FormFieldType {
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

impl std::fmt::Display for FormFieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.to_possible_value().ok_or(std::fmt::Error)?.get_name();
        write!(f, "{}", name.to_title_case())
    }
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub(crate) enum PlaceholderHandling {
    Default,
    Enabled,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Tabled)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FormField {
    #[tabled(rename = "Type")]
    pub(crate) type_: FormFieldType,
    #[tabled(rename = "Display Name")]
    pub(crate) display_name: String,
    #[tabled(rename = "Value", display_with("Self::format_value", args))]
    pub(crate) value: SecretString,
    #[tabled(rename = "HTML ID")]
    pub(crate) id: String,
    #[tabled(rename = "HTML Form Name")]
    pub(crate) name: String,
    #[tabled(skip)]
    pub(crate) page: i32,
    #[tabled(skip)]
    pub(crate) placeholder_handling: PlaceholderHandling,
}

impl FormField {
    fn format_value(&self) -> String {
        match self.type_ {
            FormFieldType::Password => "⋆⋆⋆⋆⋆⋆⋆⋆⋆⋆".to_owned(),
            FormFieldType::Radio
            | FormFieldType::Username
            | FormFieldType::Text
            | FormFieldType::Select
            | FormFieldType::Checkbox => self.value.expose_secret().clone(),
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize_repr, PartialEq)]
#[repr(u8)]
pub(crate) enum MatchAccuracy {
    Best = 50,
    Close = 40,
    HostnameAndPort = 30,
    HostnameExcludingPort = 20,
    Domain = 10,
    None = 0,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Tabled)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Entry {
    #[serde(rename = "uniqueID")]
    #[tabled(rename = "ID")]
    pub(crate) unique_id: String,
    #[serde(rename = "uRLs")]
    #[tabled(skip)]
    pub(crate) urls: Vec<String>,
    #[tabled(rename = "Group", display_with = "Self::format_group")]
    pub(crate) parent: Option<Group>,
    #[tabled(rename = "Title")]
    pub(crate) title: String,
    #[tabled(skip)]
    pub(crate) username_value: Option<String>,
    #[tabled(skip)]
    pub(crate) username_name: Option<String>,
    #[serde_as(as = "Base64")]
    #[tabled(skip)]
    pub(crate) icon_image_data: Vec<u8>,
    #[serde(rename = "hTTPRealm")]
    #[tabled(skip)]
    pub(crate) http_realm: Option<String>,
    #[tabled(skip)]
    pub(crate) form_field_list: Option<Vec<FormField>>,
    #[tabled(skip)]
    pub(crate) match_accuracy: Option<MatchAccuracy>,
    #[tabled(skip)]
    pub(crate) always_auto_fill: Option<bool>,
    #[tabled(skip)]
    pub(crate) never_auto_fill: Option<bool>,
    #[tabled(skip)]
    pub(crate) always_auto_submit: Option<bool>,
    #[tabled(skip)]
    pub(crate) never_auto_submit: Option<bool>,
    #[tabled(skip)]
    pub(crate) relevancy: Option<i32>,
    #[tabled(skip)]
    pub(crate) db: Option<Database>,
}

impl Entry {
    fn format_group(group: &Option<Group>) -> String {
        match group.as_ref() {
            Some(g) => g.path.clone(),
            None => String::new(),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Group {
    pub(crate) title: String,
    #[serde(rename = "uniqueID")]
    pub(crate) unique_id: String,
    #[serde_as(as = "Base64")]
    pub(crate) icon_image_data: Vec<u8>,
    pub(crate) path: String,
    pub(crate) child_groups: Option<Vec<Group>>,
    #[serde(alias = "childLightEntries")]
    pub(crate) child_entries: Option<Vec<Entry>>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Database {
    pub(crate) name: String,
    pub(crate) file_name: String,
    pub(crate) root: Group,
    pub(crate) active: bool,
    #[serde_as(as = "Base64")]
    pub(crate) icon_image_data: Vec<u8>,
}

#[async_trait]
pub(crate) trait Executor {
    type Response;

    async fn execute(self, tx: mpsc::Sender<manager::JsonrpcCall>) -> Result<Self::Response>
    where
        Self: TryInto<Request>,
        error::Error: From<<Self as TryInto<Request>>::Error>,
        Self::Response: for<'de> Deserialize<'de>,
    {
        let req = self.try_into()?;
        let (ltx, lrx) = oneshot::channel();
        tx.send(manager::JsonrpcCall::new(req, ltx))
            .await
            .map_err(error::Internal::from)?;
        match *lrx.await.map_err(error::Internal::from)??.variant() {
            ResponseVariant::Result(ref r) => Ok(serde_json::from_value(r.clone())?),
            ResponseVariant::Error(ref e) => Err(error::Api::ServerError(e.clone()).into()),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub(crate) struct FindLogins {
    pub(crate) unsanitized_urls: Vec<String>,
    pub(crate) action_url: Option<String>,
    pub(crate) http_realm: Option<String>,
    pub(crate) require_full_url_matches: bool,
    pub(crate) unique_id: Option<String>,
    pub(crate) db_root_id: Option<String>,
    pub(crate) free_text_search: Option<String>,
    pub(crate) username: Option<String>,
}

impl TryFrom<FindLogins> for Request {
    type Error = error::Error;

    fn try_from(value: FindLogins) -> Result<Self, Self::Error> {
        Ok(Self::new(
            "FindLogins",
            &[
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

pub(crate) struct GetAllChildEntries {
    pub(crate) uuid: String,
}

impl From<GetAllChildEntries> for Request {
    fn from(value: GetAllChildEntries) -> Self {
        Self::new("GetAllChildEntries", &[value.uuid.into()])
    }
}

impl Executor for GetAllChildEntries {
    type Response = Vec<Entry>;
}

pub(crate) struct GetAllDatabases {
    pub(crate) full_details: bool,
}

impl From<GetAllDatabases> for Request {
    fn from(value: GetAllDatabases) -> Self {
        Self::new("GetAllDatabases", &[value.full_details.into()])
    }
}

impl Executor for GetAllDatabases {
    type Response = Vec<Database>;
}

pub(crate) struct GetChildGroups {
    pub(crate) uuid: String,
}

impl From<GetChildGroups> for Request {
    fn from(value: GetChildGroups) -> Self {
        Self::new("GetChildGroups", &[value.uuid.into()])
    }
}

impl Executor for GetChildGroups {
    type Response = Vec<Group>;
}

pub(crate) struct GetRoot;

impl From<GetRoot> for Request {
    fn from(_: GetRoot) -> Self {
        Self::new("GetRoot", &[])
    }
}

impl Executor for GetRoot {
    type Response = Group;
}

pub(crate) async fn get_entry_in_group_hierarchy<
    'groups,
    T: AsRef<str> + Send,
    G: Send + Stream<Item = T> + Unpin,
>(
    tx: mpsc::Sender<manager::JsonrpcCall>,
    mut group_names: G,
    entry_title: &str,
) -> Result<Entry> {
    let mut group = GetRoot.execute(tx.clone()).await?;
    while let Some(group_name) = group_names.next().await {
        let mut child_groups = GetChildGroups {
            uuid: group.unique_id.clone(),
        }
        .execute(tx.clone())
        .await?;

        let idx = child_groups
            .iter()
            .position(|g| g.title == group_name.as_ref())
            .ok_or(error::Error::GroupNotFound {
                parent: Box::new(group),
                name: group_name.as_ref().to_owned(),
            })?;
        group = child_groups.swap_remove(idx);
    }

    let mut entries = GetAllChildEntries {
        uuid: group.clone().unique_id,
    }
    .execute(tx.clone())
    .await?;

    let idx = entries
        .iter()
        .position(|entry| entry.title == entry_title)
        .ok_or(error::Error::EntryNotFound {
            parent: Box::new(group),
            name: entry_title.to_owned(),
        })?;
    Ok(entries.swap_remove(idx))
}
