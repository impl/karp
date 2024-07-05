// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;

use crate::{client::Client, error::Result};

pub(crate) mod get_form_fields;
pub(crate) mod search;

#[async_trait]
pub(crate) trait Command {
    async fn execute(self, proto: impl Client + Send) -> Result<()>;
}
