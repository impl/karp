// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::rng;

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub(crate) enum Id {
    String(String),
    Number(serde_json::Number),
}

#[derive(Debug, Default, Deserialize, Clone, Serialize, PartialEq)]
pub(crate) struct Request {
    id: Option<Id>,
    method: String,
    params: Vec<serde_json::Value>,
}

impl Request {
    pub(crate) fn new<P>(method: &str, params: P) -> Self
    where
        P: AsRef<[serde_json::Value]>,
    {
        rng::map(|rng| Self {
            id: Some(Id::String(
                uuid::Builder::from_random_bytes(rng.gen())
                    .into_uuid()
                    .to_string(),
            )),
            method: method.to_owned(),
            params: params.as_ref().into(),
        })
    }

    pub(crate) const fn id(&self) -> &Option<Id> {
        &self.id
    }
}

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
pub(crate) struct Error {
    name: String,
    message: String,
    errors: Option<Vec<Error>>,
}

impl Error {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ResponseVariant {
    Result(serde_json::Value),
    Error(Error),
}

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
pub(crate) struct Response {
    id: Id,
    #[serde(flatten)]
    variant: ResponseVariant,
}

impl Response {
    pub(crate) const fn id(&self) -> &Id {
        &self.id
    }

    pub(crate) const fn variant(&self) -> &ResponseVariant {
        &self.variant
    }
}

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub(crate) enum Jsonrpc {
    Request(Request),
    Response(Response),
}
