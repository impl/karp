// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
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
    clippy::pattern_type_mismatch,
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

mod api;
mod command;
mod error;
mod manager;
mod message;
mod metadata;
mod model;
mod password;
mod rng;
mod session;
mod srp;
mod storage;

use std::{path::PathBuf, process};

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use error::Result;
use log::{error, warn};
use tokio::{net::TcpStream, sync::mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{header, HeaderValue},
    },
    MaybeTlsStream,
};
use url::Url;

#[derive(Debug, Subcommand)]
enum Command {
    GetFormFields(command::get_form_fields::Command),
    Search(command::search::Command),
}

#[async_trait]
impl command::Command for Command {
    async fn execute(self, tx: mpsc::Sender<manager::JsonrpcCall>) -> Result<()> {
        match self {
            Self::GetFormFields(cmd) => cmd.execute(tx).await,
            Self::Search(cmd) => cmd.execute(tx).await,
        }
    }
}

#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct Args {
    /// The WebSocket URL to connect to.
    #[clap(long, default_value = "ws://127.0.0.1:12546", value_parser = Url::parse)]
    url: Url,

    /// Turn off caching of the shared key derived by connection negotiation.
    #[clap(long)]
    no_cache_session_key: bool,

    /// The path to the Pinentry program to use when requesting the initial
    /// password from the plugin.
    #[clap(long, value_hint = clap::ValueHint::ExecutablePath)]
    pinentry_program: Option<PathBuf>,

    #[clap(subcommand)]
    command: Command,
}

async fn get_session_storage(args: &Args) -> Box<dyn storage::Storage<session::Data>> {
    if !args.no_cache_session_key {
        match storage::SecretService::new(&args.url).await {
            Ok(secret_service_storage) => return Box::new(secret_service_storage),
            Err(e) => {
                warn!("We need to fall back to unencrypted file storage because we can't connect to the secret service: {}", e);
            }
        }

        if let Some(file_storage) = storage::File::new("session.json") {
            return Box::new(file_storage);
        }
    }

    Box::new(storage::Memory::<session::Data>::new())
}

async fn open(url: Url) -> Result<message::WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let mut req = url.into_client_request()?;
    let _ = req
        .headers_mut()
        .append(header::ORIGIN, HeaderValue::from_static("karp://karp"));

    let (stream, _) = connect_async(req).await?;
    Ok(stream.into())
}

async fn run(args: Args) -> Result<()> {
    let mut storage = get_session_storage(&args).await;
    let prompt: Vec<Box<dyn password::Prompt>> = vec![
        Box::new(args.pinentry_program.map_or_else(
            password::PinentryPrompt::new,
            password::PinentryPrompt::new_with_executable,
        )),
        Box::new(password::RpasswordPrompt),
    ];
    let (tx, rx) = mpsc::channel(16);
    let mut message_stream = open(args.url).await?;

    let manager = tokio::spawn(async move {
        manager::run(
            &mut storage,
            &prompt,
            &mut message_stream,
            &mut ReceiverStream::new(rx),
        )
        .await
    });

    let result = command::Command::execute(args.command, tx).await;
    manager.await??;

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
