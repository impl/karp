// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model;

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Data {
    identifier: Uuid,
    session_key: Option<model::hash::Secret>,
}

impl Data {
    pub(crate) const fn new_unauthenticated(identifier: Uuid) -> Self {
        Self {
            identifier,
            session_key: None,
        }
    }

    pub(crate) const fn new_authenticated(
        identifier: Uuid,
        session_key: model::hash::Secret,
    ) -> Self {
        Self {
            identifier,
            session_key: Some(session_key),
        }
    }

    pub(crate) const fn identifier(&self) -> Uuid {
        self.identifier
    }

    pub(crate) const fn session_key(&self) -> &Option<model::hash::Secret> {
        &self.session_key
    }
}
