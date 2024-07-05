// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::{
    lock::Mutex,
    stream::{SplitSink, SplitStream},
    SinkExt as _, Stream, StreamExt as _,
};
use log::{debug, info, warn};
use secrecy::ExposeSecret;
use tokio::{select, sync::watch};

use crate::{
    error::{self, Result},
    keepassxc::{api::HasConstAction as _, model::HasNonce as _},
    storage,
};

use super::{
    api::{self, Call},
    error as keepassxc_error, message,
    model::{self, HasAction as _},
    session,
};

struct SignalForwardingStream<S: message::Stream> {
    message_rx: SplitStream<S>,
    signal_tx: watch::Sender<Option<api::Signal>>,
}

fn forward_signals<S: message::Stream>(
    message_rx: SplitStream<S>,
) -> (
    SignalForwardingStream<S>,
    watch::Receiver<Option<api::Signal>>,
) {
    let (signal_tx, signal_rx) = watch::channel(None);
    (
        SignalForwardingStream {
            message_rx,
            signal_tx,
        },
        signal_rx,
    )
}

impl<S: message::Stream> Stream for SignalForwardingStream<S> {
    type Item = Result<model::Response>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let next = Pin::new(&mut self.message_rx).poll_next(cx);
            if let Poll::Ready(Some(Ok(ref resp))) = next {
                let signal_opt = [api::Signal::DatabaseLocked, api::Signal::DatabaseUnlocked]
                    .into_iter()
                    .find(|signal| resp.action() == signal.action());
                if let Some(signal) = signal_opt {
                    if let Err(err) = self.signal_tx.send(Some(signal)) {
                        return Poll::Ready(Some(Err(error::Error::Internal(err.into()))));
                    }
                    continue;
                }
            }

            return next;
        }
    }
}

pub(super) struct Manager<
    Storage: storage::Storage<session::Data>,
    MessageStream: message::Stream,
    CallStream: Stream<Item = Call> + Send + Unpin,
> {
    storage: Arc<Mutex<Storage>>,
    message_tx: SplitSink<MessageStream, model::Request>,
    message_rx: SignalForwardingStream<MessageStream>,
    message_builder: model::EncryptedMessageBuilder,
    signal_rx: watch::Receiver<Option<api::Signal>>,
    call_rx: CallStream,
    calls: HashMap<model::key_material::Nonce, Call>,
    key: Option<model::Key>,
}

impl<
        Storage: storage::Storage<session::Data>,
        MessageStream: message::Stream,
        CallStream: Stream<Item = Call> + Send + Unpin,
    > Manager<Storage, MessageStream, CallStream>
{
    pub(super) async fn new(
        storage: Arc<Mutex<Storage>>,
        message_stream: MessageStream,
        call_rx: CallStream,
    ) -> Result<Self> {
        let (mut message_tx, message_rx) = message_stream.split();
        let (mut message_forwarding_rx, signal_rx) = forward_signals(message_rx);
        let message_builder = model::MessageBuilder::new();
        let (req, nonce) = message_builder.encode_request(
            &api::ChangePublicKeysRequest {
                nonce: model::key_material::generate_nonce().into(),
                public_key: message_builder.client_key().to_bytes(),
            },
            false,
        )?;
        message_tx.send(req).await?;

        let resp: api::ChangePublicKeysResponse = model::MessageBuilder::decode_response(
            message_forwarding_rx
                .next()
                .await
                .ok_or(keepassxc_error::Api::StreamEnded)??,
            &nonce,
        )?;

        Ok(Self {
            storage,
            message_tx,
            message_rx: message_forwarding_rx,
            message_builder: message_builder
                .encrypt(&model::key_material::PublicKey::from_bytes(resp.public_key)),
            signal_rx,
            call_rx,
            calls: HashMap::new(),
            key: None,
        })
    }

    pub(super) async fn run(mut self) -> Result<()> {
        loop {
            if self.key.is_none() {
                self.key = self.authenticate().await.map(Some).or_else(|err| {
                    if let error::Error::Keepassxc(keepassxc_error::Error::Api(
                        keepassxc_error::Api::ServerError(e),
                    )) = &err
                    {
                        if e.error_code() == model::ErrorCode::DatabaseNotOpened {
                            info!("Database is locked; waiting for unlock signal");
                            return Ok(None);
                        }
                    }

                    Err(err)
                })?;
            }

            select! {
                candidate = self.signal_rx.changed() => {
                    candidate.map_err(Into::<error::Internal>::into)?;
                    self.handle_signal();
                }
                candidate = self.message_rx.next() => {
                    let msg = candidate.ok_or(keepassxc_error::Api::StreamEnded)??;
                    self = self.handle_message(msg)?;
                }
                candidate = self.call_rx.next(), if self.key.is_some() => {
                    match candidate {
                        Some(call) => self = self.handle_call(call).await?,
                        None => return Ok(()),
                    }
                }
            }
        }
    }

    fn handle_signal(&mut self) {
        if let Some(signal) = self.signal_rx.borrow_and_update().as_ref() {
            debug!("Received signal: {:?}", signal);
            match *signal {
                api::Signal::DatabaseLocked => {
                    self.key = None;
                }
                api::Signal::DatabaseUnlocked => {}
            }
        }
    }

    fn handle_message(mut self, msg: model::Response) -> Result<Self> {
        if self.key.is_none() {
            warn!("Received spurious message before authentication: {:?}", msg);
            return Ok(self);
        }

        debug!("Received response: {:?}", msg);

        let action = msg.action().to_owned();
        let resp: Result<(serde_json::Value, Call)> =
            self.message_builder
                .decode_response_with(msg, |encrypted_value| {
                    self.calls
                        .remove(encrypted_value.nonce())
                        .ok_or(keepassxc_error::Api::InvalidNonce.into())
                });
        match resp {
            Ok((value, call)) => {
                if call.tx.send(Ok(value)).is_err() {
                    warn!(
                        "Failed to inform disconnected call receiver {:?} of response",
                        call.req
                    );
                }
            }
            Err(error::Error::Keepassxc(keepassxc_error::Error::Api(
                keepassxc_error::Api::ServerError(err),
            ))) => {
                self.calls = self
                    .calls
                    .into_iter()
                    .filter_map(|(nonce, call)| {
                        if call.action() == action {
                            let result = call.tx.send(Err(error::Error::Keepassxc(
                                keepassxc_error::Error::Api(keepassxc_error::Api::ServerError(
                                    err.clone(),
                                )),
                            )));
                            if result.is_err() {
                                warn!(
                                    "Failed to inform disconnected call receiver {:?} of error",
                                    call.req
                                );
                            }
                            None
                        } else {
                            Some((nonce, call))
                        }
                    })
                    .collect();
            }
            Err(err) => return Err(err),
        }

        Ok(self)
    }

    async fn handle_call(mut self, call: Call) -> Result<Self> {
        debug!("Sending request: {:?}", call);

        let (req, nonce) = self.message_builder.encode_request(
            &self.key.clone().into_iter().collect::<Vec<_>>(),
            &call,
            false,
        )?;
        self.message_tx.send(req).await?;

        assert!(self.calls.insert(nonce, call).is_none());

        Ok(self)
    }

    async fn authenticate(&mut self) -> Result<model::Key> {
        let get_database_hash_resp: api::GetDatabaseHashResponse = {
            let (req, nonce) = self.message_builder.encode_request(
                &[],
                &api::GetDatabaseHashRequest {
                    action: api::GetDatabaseHashRequest::ACTION.to_owned(),
                },
                true,
            )?;
            self.message_tx.send(req).await?;

            self.message_builder.decode_response(
                self.message_rx
                    .next()
                    .await
                    .ok_or(keepassxc_error::Api::StreamEnded)??,
                &nonce,
            )?
        };

        let mut storage = self.storage.lock().await;
        let mut session = storage.get().await?.unwrap_or_default();
        if let Some(key) = session.keys.get(&get_database_hash_resp.hash) {
            let public_key = key.id_key.expose_secret().as_ref().public_key().to_bytes();
            let (req, nonce) = self.message_builder.encode_request(
                &[],
                &api::TestAssociateRequest {
                    id: key.id.clone(),
                    key: public_key,
                },
                false,
            )?;
            self.message_tx.send(req).await?;

            let result: Result<api::TestAssociateResponse> = self.message_builder.decode_response(
                self.message_rx
                    .next()
                    .await
                    .ok_or(keepassxc_error::Api::StreamEnded)??,
                &nonce,
            );
            match result {
                Ok(resp) => {
                    return Ok(model::Key {
                        id: resp.id,
                        key: public_key,
                    })
                }
                Err(error::Error::Keepassxc(keepassxc_error::Error::Api(
                    keepassxc_error::Api::ServerError(err),
                ))) if err.error_code() == model::ErrorCode::AssociationFailed => {
                    warn!("Association failed; reauthenticating");
                }
                Err(err) => return Err(err),
            }
        }

        let id_key = model::key_material::SecretKey::generate();
        let public_key = id_key.expose_secret().as_ref().public_key().to_bytes();

        let associate_resp: api::AssociateResponse = {
            let (req, nonce) = self.message_builder.encode_request(
                &[],
                &api::AssociateRequest {
                    key: self.message_builder.client_key().to_bytes(),
                    id_key: public_key,
                },
                false,
            )?;
            self.message_tx.send(req).await?;

            self.message_builder.decode_response(
                self.message_rx
                    .next()
                    .await
                    .ok_or(keepassxc_error::Api::StreamEnded)??,
                &nonce,
            )?
        };

        _ = session.keys.insert(
            associate_resp.hash.clone(),
            session::Key {
                id: associate_resp.id.clone(),
                id_key,
            },
        );
        storage.update(&session).await?;
        Ok(model::Key {
            id: associate_resp.id,
            key: public_key,
        })
    }
}
