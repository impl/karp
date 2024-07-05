// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use clap::ValueEnum;
use futures_util::future::BoxFuture;
use inflector::Inflector as _;
use secrecy::{ExposeSecret as _, SecretString};
use tabled::Tabled;

use crate::error::Result;

#[derive(Copy, Clone, Debug, PartialEq, Tabled, ValueEnum)]
pub(crate) enum FormFieldType {
    Username,
    Password,
    Text,
    Select,
    Radio,
    Checkbox,
}

impl std::fmt::Display for FormFieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self.to_possible_value().ok_or(std::fmt::Error)?;
        write!(f, "{}", value.get_name().to_title_case())
    }
}

#[derive(Clone, Debug, Tabled)]
pub(crate) struct FormField {
    #[tabled(rename = "Type")]
    pub(crate) type_: FormFieldType,
    #[tabled(rename = "Display Name")]
    pub(crate) display_name: String,
    #[tabled(rename = "Value", display_with("Self::format_value", self))]
    pub(crate) value: SecretString,
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

#[derive(Clone, Debug, Tabled)]
pub(crate) struct Group {
    #[tabled(rename = "Path")]
    pub(crate) path: String,
}

#[derive(Clone, Debug, Tabled)]
pub(crate) struct Entry {
    #[tabled(rename = "ID")]
    pub(crate) id: String,
    #[tabled(rename = "Group", display_with = "Self::format_group")]
    pub(crate) parent: Option<Group>,
    #[tabled(rename = "Title")]
    pub(crate) title: String,
    #[tabled(skip)]
    pub(crate) form_fields: Vec<FormField>,
}

impl Entry {
    fn format_group(group: &Option<Group>) -> String {
        match group.as_ref() {
            Some(g) => g.path.clone(),
            None => String::new(),
        }
    }
}

#[async_trait]
pub(crate) trait Client {
    async fn get_entry(
        &self,
        group_names: &mut (dyn Iterator<Item = &str> + Send + Sync),
        title: &str,
    ) -> Result<Entry>;

    async fn find_entries(&self, query: &str) -> Result<Vec<Entry>>;
}

#[async_trait]
impl Client for Box<dyn Client + Send + Sync + '_> {
    async fn get_entry(
        &self,
        group_names: &mut (dyn Iterator<Item = &str> + Send + Sync),
        title: &str,
    ) -> Result<Entry> {
        <dyn Client>::get_entry(self.as_ref(), group_names, title).await
    }

    async fn find_entries(&self, query: &str) -> Result<Vec<Entry>> {
        <dyn Client>::find_entries(self.as_ref(), query).await
    }
}

#[async_trait]
pub(crate) trait Protocol<'channel> {
    async fn channel(
        &self,
    ) -> Result<(
        BoxFuture<'channel, Result<()>>,
        Box<dyn Client + Send + Sync + 'channel>,
    )>;
}
