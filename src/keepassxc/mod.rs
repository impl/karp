// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

mod api;
pub(crate) mod error;
mod manager;
mod message;
mod model;
pub(crate) mod session;

use std::{path::PathBuf, sync::Arc};

use api::Executor as _;
use async_trait::async_trait;
use futures_util::{future::BoxFuture, lock::Mutex};
use tokio::{net::UnixStream, sync::mpsc};
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    client,
    error::{self as base_error, Result},
    storage,
};

struct Client {
    tx: mpsc::Sender<api::Call>,
}

impl Client {
    pub(crate) fn new(tx: mpsc::Sender<api::Call>) -> Self {
        Self { tx }
    }
}

#[async_trait]
impl client::Client for Client {
    async fn get_entry(
        &self,
        group_names: &mut (dyn Iterator<Item = &str> + Send + Sync),
        entry_title: &str,
    ) -> Result<client::Entry> {
        // This "looks" like a URL, but it isn't. It shouldn't be
        // percent-encoded or anything.
        let mut path = group_names.collect::<Vec<_>>();
        path.push(entry_title);

        let mut url = "keepassxc://by-path/".to_owned();
        url.push_str(&path.join("/"));

        let resp = api::GetLoginsRequest {
            url,
            submit_url: None,
            http_auth: None,
        }
        .execute(self.tx.clone())
        .await
        .map_err(|err| {
            if let base_error::Error::Keepassxc(error::Error::Api(error::Api::ServerError(e))) =
                &err
            {
                if e.error_code() == model::ErrorCode::NoLoginsFound {
                    return base_error::Error::EntryNotFound {
                        parent: client::Group {
                            path: path[..path.len() - 1].join("/"),
                        },
                        name: entry_title.to_owned(),
                    };
                }
            }

            err
        })?;

        Ok(resp
            .entries
            .into_iter()
            .next()
            .ok_or(base_error::Error::EntryNotFound {
                parent: client::Group {
                    path: path[..path.len() - 1].join("/"),
                },
                name: entry_title.to_owned(),
            })?
            .into())
    }

    async fn find_entries(&self, query: &str) -> Result<Vec<client::Entry>> {
        let resp = api::GetLoginsRequest {
            url: query.to_owned(),
            submit_url: None,
            http_auth: None,
        }
        .execute(self.tx.clone())
        .await
        .or_else(|err| {
            if let base_error::Error::Keepassxc(error::Error::Api(error::Api::ServerError(e))) =
                &err
            {
                if e.error_code() == model::ErrorCode::NoLoginsFound {
                    return Ok(api::GetLoginsResponse {
                        count: 0,
                        entries: vec![],
                    });
                }
            }

            Err(err)
        })?;

        Ok(resp.entries.into_iter().map(Into::into).collect())
    }
}

pub(crate) struct Protocol<Storage: storage::Storage<session::Data>> {
    storage: Arc<Mutex<Storage>>,
    socket_path: PathBuf,
}

impl<Storage: storage::Storage<session::Data>> Protocol<Storage> {
    pub(crate) fn new(storage: Arc<Mutex<Storage>>, socket_path: PathBuf) -> Self {
        Self {
            storage,
            socket_path,
        }
    }

    async fn new_stream(&self) -> Result<message::JsonMessageStream<UnixStream>> {
        UnixStream::connect(&self.socket_path)
            .await
            .map_err(Into::into)
            .map(Into::into)
    }
}

#[async_trait]
impl<'channel, Storage: storage::Storage<session::Data> + 'channel> client::Protocol<'channel>
    for Protocol<Storage>
{
    async fn channel(
        &self,
    ) -> Result<(
        BoxFuture<'channel, Result<()>>,
        Box<dyn client::Client + Send + Sync + 'channel>,
    )> {
        let storage = Arc::clone(&self.storage);
        let (tx, rx) = mpsc::channel(16);
        let mut message_stream = self.new_stream().await?;

        let worker = async move {
            manager::Manager::new(storage, message_stream.as_mut(), ReceiverStream::new(rx))
                .await?
                .run()
                .await
        };

        Ok((Box::pin(worker), Box::new(Client::new(tx))))
    }
}
