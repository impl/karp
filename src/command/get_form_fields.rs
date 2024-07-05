// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use clap::Parser;
use log::error;
use secrecy::ExposeSecret;
use tabled::{
    settings::{object::Cell, Format, Modify, Style},
    Table,
};

use crate::{
    client::{Client, FormFieldType},
    error::{self, Result},
};

/// Get the form fields of an entry at a given path.
#[derive(Debug, Parser)]
#[command(allow_missing_positional = true)]
pub(crate) struct Command {
    /// Filter the form fields returned to those matching a particular type.
    #[arg(long, short, value_enum)]
    type_: Option<FormFieldType>,

    /// The numerical index of a particular field to select. Indexing is
    /// performed after any filtering is applied. When this option is selected,
    /// only the field's value is printed.
    #[arg(long, short)]
    index: Option<usize>,

    /// The location of the entry to look up within the group hierarchy.
    #[clap()]
    groups: Vec<String>,

    /// The name of the entry to look up.
    #[clap()]
    entry: String,
}

#[async_trait]
impl super::Command for Command {
    async fn execute(self, client: impl Client + Send) -> Result<()> {
        let entry = client
            .get_entry(&mut self.groups.iter().map(String::as_ref), &self.entry)
            .await?;

        let mut fields_iter = entry.form_fields.into_iter().filter(|field| {
            self.type_
                .map_or(true, |field_type| field.type_ == field_type)
        });

        if let Some(n) = self.index {
            if let Some(field) = fields_iter.nth(n) {
                println!("{}", field.value.expose_secret());
                Ok(())
            } else {
                error!("No form field with index {}", n);
                Err(error::Error::Command)
            }
        } else {
            println!(
                "{}",
                Table::new((0_u32..).zip(fields_iter))
                    .with(Style::rounded())
                    .with(
                        Modify::new(Cell::new(0, 0)).with(Format::content(|_| "Index".to_owned()))
                    )
            );
            Ok(())
        }
    }
}
