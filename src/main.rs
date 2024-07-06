// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(elided_lifetimes_in_paths)]
#![warn(
    rust_2018_idioms,
    future_incompatible,
    unused,
    unused_lifetimes,
    unused_qualifications,
    unused_results,
    anonymous_parameters,
    deprecated_in_future,
    elided_lifetimes_in_paths,
    explicit_outlives_requirements,
    keyword_idents,
    macro_use_extern_crate,
    missing_doc_code_examples,
    private_doc_tests,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    clippy::all,
    clippy::pedantic,
    clippy::cargo,
    clippy::unseparated_literal_suffix,
    clippy::decimal_literal_representation,
    clippy::single_char_lifetime_names,
    clippy::fallible_impl_from,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::wildcard_enum_match_arm,
    clippy::deref_by_slicing,
    clippy::default_numeric_fallback,
    clippy::shadow_reuse,
    clippy::clone_on_ref_ptr,
    clippy::todo,
    clippy::string_add,
    clippy::use_debug,
    clippy::future_not_send
)]
#![cfg_attr(not(test), warn(clippy::panic_in_result_fn))]

mod client;
mod command;
mod error;
mod keepass;
mod keepassxc;
mod metadata;
mod password;
mod rng;
mod storage;

use std::{path::PathBuf, process, sync::Arc};

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use client::{Client, Protocol};
use error::Result;
use futures_util::lock::Mutex;
use log::{error, warn};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Subcommand)]
enum Command {
    GetFormFields(command::get_form_fields::Command),
    Search(command::search::Command),
}

#[async_trait]
impl command::Command for Command {
    async fn execute(self, client: impl Client + Send) -> Result<()> {
        match self {
            Self::GetFormFields(cmd) => cmd.execute(client).await,
            Self::Search(cmd) => cmd.execute(client).await,
        }
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    /// The URL to connect to. For KeePassRPC, this is a WebSocket. For
    /// KeePassXC, this is a file path to a Unix domain socket.
    #[arg(long, env = "KARP_URL", default_value = "ws://127.0.0.1:12546", value_parser = Url::parse)]
    url: Url,

    /// Turn off caching of the shared key derived by connection negotiation.
    #[arg(long)]
    no_cache_session_key: bool,

    /// The path to the Pinentry program to use when requesting the initial
    /// password from the plugin.
    #[arg(long, value_hint = clap::ValueHint::ExecutablePath)]
    pinentry_program: Option<PathBuf>,

    #[clap(subcommand)]
    command: Command,
}

async fn get_session_storage<
    T: Send + Serialize + Sync + for<'de> Deserialize<'de> + Clone + 'static,
>(
    args: &Args,
) -> Box<dyn storage::Storage<T>> {
    if !args.no_cache_session_key {
        #[cfg(feature = "secret-service")]
        match storage::SecretService::new(&args.url).await {
            Ok(secret_service_storage) => return Box::new(secret_service_storage),
            Err(e) => {
                warn!("We need to fall back to unencrypted file storage because we can't connect to the secret service: {}", e);
            }
        }

        #[cfg(feature = "keychain")]
        match storage::Keychain::new(&args.url) {
            Ok(keychain_storage) => return Box::new(keychain_storage),
            Err(e) => {
                warn!("We need to fall back to unencrypted file storage because we can't connect to Keychain: {}", e);
            }
        }

        if let Some(file_storage) = storage::File::new("session.json") {
            return Box::new(file_storage);
        }
    }

    Box::new(storage::Memory::<T>::new())
}

async fn run(args: Args) -> Result<()> {
    let prompt: Vec<Box<dyn password::Prompt>> = vec![
        Box::new(args.pinentry_program.clone().map_or_else(
            password::PinentryPrompt::new,
            password::PinentryPrompt::new_with_executable,
        )),
        Box::new(password::RpasswordPrompt),
    ];

    let proto: Box<dyn Protocol<'_> + Send> = match args.url.scheme() {
        "ws" | "wss" => Box::new(keepass::Protocol::new(
            Arc::new(Mutex::new(get_session_storage(&args).await)),
            Arc::new(prompt),
            args.url,
        )),
        "file" => Box::new(keepassxc::Protocol::new(
            Arc::new(Mutex::new(get_session_storage(&args).await)),
            args.url.to_file_path().map_err(|()| {
                error!("The URL {} is not a valid file path", args.url);
                error::Error::Command
            })?,
        )),
        _ => {
            error!(
                "The URL scheme {} of URL {} is not supported",
                args.url.scheme(),
                args.url
            );
            return Err(error::Error::Command);
        }
    };
    let (worker, client) = proto.channel().await?;
    let worker_task = tokio::spawn(worker);

    let result = command::Command::execute(args.command, client).await;
    worker_task.await??;

    result
}

#[tokio::main]
async fn main() {
    let logger_env = env_logger::Env::new()
        .filter_or("KARP_LOG", "warn")
        .write_style("KARP_LOG_STYLE");
    env_logger::Builder::from_env(logger_env).init();

    if let Err(e) = run(Args::parse()).await {
        error!("We encountered an error: {}", e);
        process::exit(1);
    };
}
