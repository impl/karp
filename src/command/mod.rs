// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{error::Result, manager};

pub(crate) mod get_form_fields;
pub(crate) mod search;

#[async_trait]
pub(crate) trait Command {
    async fn execute(self, tx: mpsc::Sender<manager::JsonrpcCall>) -> Result<()>;
}
