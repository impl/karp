// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use core::num;

use async_trait::async_trait;
use clap::Parser;
use tabled::{
    settings::{object::Segment, Alignment, Modify, Style},
    Table,
};

use crate::{client::Client, error::Result};

/// Free-text search for a given entry.
#[derive(Debug, Parser)]
pub(crate) struct Command {
    /// The number of possible entries to return.
    #[arg(short, long)]
    count: Option<num::NonZeroUsize>,

    /// The text to search for.
    #[clap()]
    query: String,
}

#[async_trait]
impl super::Command for Command {
    async fn execute(self, client: impl Client + Send) -> Result<()> {
        let entries = client.find_entries(&self.query).await?;

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
