// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

mod api;
pub(crate) mod error;
mod manager;
mod message;
mod model;
pub(crate) mod session;
mod srp;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{future::BoxFuture, lock::Mutex};
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

use crate::{
    client,
    error::{self as base_error, Result},
    password, storage,
};

use api::Executor as _;

struct Client {
    tx: mpsc::Sender<api::Call>,
}

impl Client {
    fn new(tx: mpsc::Sender<api::Call>) -> Self {
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
        let mut group = api::GetRoot.execute(self.tx.clone()).await?;
        for group_name in group_names {
            let child_groups = api::GetChildGroups {
                uuid: group.unique_id.clone(),
            }
            .execute(self.tx.clone())
            .await?;

            group = child_groups
                .into_iter()
                .find(|g| g.title == group_name)
                .ok_or(base_error::Error::GroupNotFound {
                    parent: group.into(),
                    name: group_name.to_owned(),
                })?;
        }

        let entries = api::GetAllChildEntries {
            uuid: group.clone().unique_id,
        }
        .execute(self.tx.clone())
        .await?;

        Ok(entries
            .into_iter()
            .find(|entry| entry.title == entry_title)
            .ok_or(base_error::Error::EntryNotFound {
                parent: group.into(),
                name: entry_title.to_owned(),
            })?
            .into())
    }

    async fn find_entries(&self, query: &str) -> Result<Vec<client::Entry>> {
        Ok(api::FindLogins {
            unsanitized_urls: vec![],
            action_url: None,
            http_realm: None,
            require_full_url_matches: false,
            unique_id: None,
            db_root_id: None,
            free_text_search: Some(query.to_string()),
            username: None,
        }
        .execute(self.tx.clone())
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
    }
}

pub(crate) struct Protocol<Storage: storage::Storage<session::Data>, Prompt: password::Prompt> {
    storage: Arc<Mutex<Storage>>,
    prompt: Arc<Prompt>,
    url: Url,
}

impl<Storage: storage::Storage<session::Data>, Prompt: password::Prompt> Protocol<Storage, Prompt> {
    pub(crate) fn new(storage: Arc<Mutex<Storage>>, prompt: Arc<Prompt>, url: Url) -> Self {
        Self {
            storage,
            prompt,
            url,
        }
    }

    async fn new_stream(&self) -> Result<message::WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let mut req = self
            .url
            .as_ref()
            .into_client_request()
            .map_err(Into::<error::Error>::into)?;
        let _ = req
            .headers_mut()
            .append(header::ORIGIN, HeaderValue::from_static("karp://karp"));

        let (stream, _) = connect_async(req)
            .await
            .map_err(Into::<error::Error>::into)?;
        Ok(stream.into())
    }
}

#[async_trait]
impl<
        'channel,
        Storage: storage::Storage<session::Data> + 'channel,
        Prompt: password::Prompt + 'channel,
    > client::Protocol<'channel> for Protocol<Storage, Prompt>
{
    async fn channel(
        &self,
    ) -> Result<(
        BoxFuture<'channel, Result<()>>,
        Box<dyn client::Client + Send + Sync + 'channel>,
    )> {
        let storage = Arc::clone(&self.storage);
        let prompt = Arc::clone(&self.prompt);
        let (tx, rx) = mpsc::channel(16);
        let message_stream = self.new_stream().await?;

        let worker = async move {
            manager::run(storage, prompt, message_stream, ReceiverStream::new(rx)).await
        };

        Ok((Box::pin(worker), Box::new(Client::new(tx))))
    }
}
