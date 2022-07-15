// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use core::num;

use async_trait::async_trait;
use clap::Parser;
use tabled::{object::Segment, Alignment, Modify, Style, Table};
use tokio::sync::mpsc;

use crate::{
    api::{self, Executor},
    error::Result,
    manager,
};

/// Free-text search for a given entry.
#[derive(Debug, Parser)]
pub(crate) struct Command {
    /// The number of possible entries to return.
    #[clap(short, long)]
    count: Option<num::NonZeroUsize>,

    /// The text to search for.
    #[clap()]
    query: String,
}

#[async_trait]
impl super::Command for Command {
    async fn execute(self, tx: mpsc::Sender<manager::JsonrpcCall>) -> Result<()> {
        let entries = api::FindLogins {
            unsanitized_urls: vec![],
            action_url: None,
            http_realm: None,
            require_full_url_matches: false,
            unique_id: None,
            db_root_id: None,
            free_text_search: Some(self.query),
            username: None,
        }
        .execute(tx.clone())
        .await?;

        if !entries.is_empty() {
            println!(
                "{}",
                Table::new(
                    entries
                        .iter()
                        .take(self.count.map_or(usize::MAX, num::NonZeroUsize::get))
                )
                .with(Style::rounded())
                .with(Modify::new(Segment::new(1.., 1..=2)).with(Alignment::left()))
            );
        }
        Ok(())
    }
}
