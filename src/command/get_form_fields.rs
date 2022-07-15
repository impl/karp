// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use clap::Parser;
use futures_util::stream;
use log::error;
use secrecy::ExposeSecret;
use tabled::{object::Cell, Format, Modify, Style, Table};
use tokio::sync::mpsc;

use crate::{
    api,
    error::{self, Result},
    manager,
};

/// Get the form fields of an entry at a given path.
#[derive(Debug, Parser)]
#[clap(allow_missing_positional = true)]
pub(crate) struct Command {
    /// Filter the form fields returned to those matching a particular type.
    #[clap(long, short, arg_enum, value_parser)]
    type_: Option<api::FormFieldType>,

    /// The numerical index of a particular field to select. Indexing is
    /// performed after any filtering is applied. When this option is selected,
    /// only the field's value is printed.
    #[clap(long, short)]
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
    async fn execute(self, tx: mpsc::Sender<manager::JsonrpcCall>) -> Result<()> {
        let entry =
            api::get_entry_in_group_hierarchy(tx, stream::iter(self.groups), &self.entry).await?;

        let mut fields_iter = entry
            .form_field_list
            .as_ref()
            .map_or_else(|| [].iter(), IntoIterator::into_iter)
            .filter(|field| {
                self.type_
                    .map_or(true, |field_type| field.type_ == field_type)
            });

        match self.index {
            Some(n) => match fields_iter.nth(n) {
                Some(field) => {
                    println!("{}", field.value.expose_secret());
                    Ok(())
                }
                None => {
                    error!("No form field with index {}", n);
                    Err(error::Error::Command)
                }
            },
            None => {
                println!(
                    "{}",
                    Table::new((0_u32..).zip(fields_iter))
                        .with(Style::rounded())
                        .with(Modify::new(Cell(0, 0)).with(Format::new(|_| "Index".to_owned())))
                );
                Ok(())
            }
        }
    }
}
