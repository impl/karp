// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::model;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Key {
    pub(super) id: String,
    pub(super) id_key: model::key_material::SecretKey,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct Data {
    pub(super) keys: HashMap<String, Key>,
}
