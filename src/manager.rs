// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use async_recursion::async_recursion;
use async_trait::async_trait;
use futures_util::{stream, SinkExt, Stream, StreamExt};
use log::warn;
use num_bigint::RandBigInt;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{select, sync::oneshot};
use uuid::Uuid;

use crate::{
    error::{self, Result},
    message, model, password, rng, session, srp,
    storage::{self, IsPersistent, Storage},
};

#[derive(Debug)]
pub(crate) struct JsonrpcCall {
    req: model::jsonrpc::Jsonrpc,
    tx: oneshot::Sender<Result<model::jsonrpc::Response>>,
}

impl JsonrpcCall {
    pub(crate) fn new<T: Into<model::jsonrpc::Request>>(
        req: T,
        tx: oneshot::Sender<Result<model::jsonrpc::Response>>,
    ) -> Self {
        Self {
            req: model::jsonrpc::Jsonrpc::Request(req.into()),
            tx,
        }
    }
}

/// An implementation of the storage trait that asserts any returned data has
/// the expected identifier.
struct BoundStorage<'delegate, T> {
    delegate: &'delegate mut T,
    identifier: Uuid,
}

impl<T: Storage<session::Data>> BoundStorage<'_, T> {
    async fn map_session_key<R, F: FnOnce(&model::hash::Secret) -> R + Send>(
        &mut self,
        f: F,
    ) -> Result<Option<R>> {
        Ok(self
            .get()
            .await?
            .and_then(|session_data| session_data.session_key().as_ref().map(f)))
    }
}

impl<T: IsPersistent> IsPersistent for BoundStorage<'_, T> {
    fn is_persistent(&self) -> bool {
        self.delegate.is_persistent()
    }
}

#[async_trait]
impl<T: Storage<session::Data>> Storage<session::Data> for BoundStorage<'_, T> {
    async fn get(&mut self) -> Result<Option<session::Data>> {
        let candidate = self.delegate.get().await?;
        match candidate {
            Some(session_data)
                if session_data
                    .identifier()
                    .as_bytes()
                    .ct_eq(self.identifier.as_bytes())
                    .unwrap_u8()
                    == 1_u8 =>
            {
                Ok(Some(session_data))
            }
            Some(_) => Err(error::Storage::Conflict.into()),
            None => Ok(None),
        }
    }

    async fn update(&mut self, data: &session::Data) -> Result<()> {
        if data
            .identifier()
            .as_bytes()
            .ct_eq(self.identifier.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(error::Storage::Conflict.into());
        }

        self.delegate.update(data).await
    }

    async fn clear(&mut self) -> Result<()> {
        self.delegate.clear().await
    }
}

async fn srp_computed<
    'storage,
    Storage: storage::Storage<session::Data>,
    Prompt: password::Prompt,
    MessageStream: message::Stream,
>(
    storage: &'storage mut Storage,
    prompt: &Prompt,
    message_stream: &mut MessageStream,
    negotiate: srp::Protocol<srp::Computed>,
) -> Result<BoundStorage<'storage, Storage>> {
    message_stream
        .send(model::Message::Setup(model::setup::Setup::new(
            model::setup::Variant::SrpProofToServer {
                srp: model::setup::SrpProofToServer::new(&negotiate, storage.security_level()),
            },
        )))
        .await?;

    let msg = message_stream
        .next()
        .await
        .ok_or(error::Api::StreamEnded)??;
    match msg.as_setup().map(model::setup::Setup::variant) {
        Some(&model::setup::Variant::Error { ref error })
            if error == &model::setup::ErrorCode::AuthFailed =>
        {
            warn!("Authentication failed, so you need to try again: {}", error);
            srp_init(
                storage,
                prompt,
                Some("Incorrect password.".to_owned()),
                message_stream,
                srp::ProtocolBuilder::new()
                    .with_identifier(negotiate.identifier())
                    .into_protocol(),
            )
            .await
        }
        Some(&model::setup::Variant::SrpProofToClient { ref srp, .. })
            if srp.security_level() < storage.security_level() =>
        {
            Err(
                error::Api::SecurityLevelTooLow(storage.security_level(), srp.security_level())
                    .into(),
            )
        }
        Some(&model::setup::Variant::SrpProofToClient { ref srp, .. }) => {
            let authenticated = negotiate.authenticate(srp.evidence())?;

            storage
                .update(&session::Data::new_authenticated(
                    authenticated.identifier(),
                    authenticated.session_key().clone(),
                ))
                .await?;

            Ok(BoundStorage {
                delegate: storage,
                identifier: authenticated.identifier(),
            })
        }
        _ => Err(error::Api::UnhandledMessage(msg).into()),
    }
}

#[async_recursion]
async fn srp_init<
    'storage,
    Storage: storage::Storage<session::Data>,
    Prompt: password::Prompt,
    MessageStream: message::Stream,
>(
    storage: &'storage mut Storage,
    prompt: &Prompt,
    prompt_error: Option<String>,
    message_stream: &mut MessageStream,
    negotiate: srp::Protocol<srp::Init>,
) -> Result<BoundStorage<'storage, Storage>> {
    // Write identifier and clear any potential session key since we're
    // starting the initialization over.
    let session_data = session::Data::new_unauthenticated(negotiate.identifier());
    storage.update(&session_data).await?;

    message_stream
        .send(model::Message::Setup(model::setup::Setup::new(
            model::setup::Variant::ClientInit(model::setup::ClientInit::new(
                model::setup::ClientInitVariant::Srp(model::setup::SrpIdentifyToServer::new(
                    &negotiate,
                    storage.security_level(),
                )),
            )),
        )))
        .await?;

    let msg = message_stream
        .next()
        .await
        .ok_or(error::Api::StreamEnded)??;
    match msg.as_setup().map(model::setup::Setup::variant) {
        Some(&model::setup::Variant::SrpIdentifyToClient { ref srp, .. })
            if srp.security_level() < storage.security_level() =>
        {
            Err(
                error::Api::SecurityLevelTooLow(storage.security_level(), srp.security_level())
                    .into(),
            )
        }
        Some(&model::setup::Variant::SrpIdentifyToClient { ref srp, .. }) => {
            // Get matching password from user.
            let mut req = password::RequestBuilder::new();
            if let Some(error) = prompt_error {
                req = req.with_error(&error);
            }

            let password = prompt
                .prompt(req.into_request())
                .await?
                .ok_or(error::Password::NoPrompt)?;

            srp_computed(
                storage,
                prompt,
                message_stream,
                negotiate.compute(srp.public_key(), srp.salt(), password.expose_secret()),
            )
            .await
        }
        _ => Err(error::Api::UnhandledMessage(msg).into()),
    }
}

async fn key_negotiate<
    'storage,
    Storage: storage::Storage<session::Data>,
    MessageStream: message::Stream,
>(
    mut storage: BoundStorage<'storage, Storage>,
    message_stream: &mut MessageStream,
    their_challenge: &str,
) -> Result<BoundStorage<'storage, Storage>> {
    let my_challenge = rng::map(|rng| rng.gen_biguint(256).to_str_radix(16));
    let my_response = Sha256::new_with_prefix("1")
        .chain_update({
            storage
                .map_session_key(|session_key| SecretString::from(session_key))
                .await?
                .ok_or(error::Storage::Conflict)?
                .expose_secret()
        })
        .chain_update(their_challenge)
        .chain_update(&my_challenge)
        .into();

    message_stream
        .send(model::Message::Setup(model::setup::Setup::new(
            model::setup::Variant::KeyClientNegotiation {
                key: model::setup::KeyClientNegotiation::new(&my_challenge, &my_response),
            },
        )))
        .await?;

    let msg = message_stream
        .next()
        .await
        .ok_or(error::Api::StreamEnded)??;
    match msg.as_setup().map(model::setup::Setup::variant) {
        Some(&model::setup::Variant::Error { ref error })
            if error == &model::setup::ErrorCode::AuthFailed =>
        {
            Err(error::ChallengeResponse::ClientResponseMismatch(error.clone()).into())
        }
        Some(&model::setup::Variant::KeyServerResponse { ref key, .. })
            if key.security_level() < storage.security_level() =>
        {
            Err(
                error::Api::SecurityLevelTooLow(storage.security_level(), key.security_level())
                    .into(),
            )
        }
        Some(&model::setup::Variant::KeyServerResponse { ref key }) => {
            let their_response = Sha256::new_with_prefix("0")
                .chain_update({
                    storage
                        .map_session_key(|session_key| SecretString::from(session_key))
                        .await?
                        .ok_or(error::Storage::Conflict)?
                        .expose_secret()
                })
                .chain_update(their_challenge)
                .chain_update(&my_challenge)
                .into();
            if key.server_response() != &their_response {
                return Err(error::ChallengeResponse::ServerResponseMismatch.into());
            }

            Ok(storage)
        }
        _ => Err(error::Api::UnhandledMessage(msg).into()),
    }
}

async fn key_init<
    'storage,
    Storage: storage::Storage<session::Data>,
    Prompt: password::Prompt,
    MessageStream: message::Stream,
>(
    storage: &'storage mut Storage,
    prompt: &Prompt,
    message_stream: &mut MessageStream,
    identifier: Uuid,
) -> Result<BoundStorage<'storage, Storage>> {
    message_stream
        .send(model::Message::Setup(model::setup::Setup::new(
            model::setup::Variant::ClientInit(model::setup::ClientInit::new(
                model::setup::ClientInitVariant::Key {
                    username: identifier.to_string(),
                    security_level: model::setup::SecurityLevel::Medium,
                },
            )),
        )))
        .await?;

    let msg = message_stream
        .next()
        .await
        .ok_or(error::Api::StreamEnded)??;
    match msg.as_setup().map(model::setup::Setup::variant) {
        Some(&model::setup::Variant::Error { ref error })
            if error == &model::setup::ErrorCode::AuthFailed =>
        {
            warn!(
                "Authentication failed, so we have to start over with SRP: {}",
                error
            );
            srp_init(storage, prompt, None, message_stream, srp::Protocol::new()).await
        }
        Some(&model::setup::Variant::KeyServerChallenge { ref key, .. })
            if key.security_level() < storage.security_level() =>
        {
            Err(
                error::Api::SecurityLevelTooLow(storage.security_level(), key.security_level())
                    .into(),
            )
        }
        Some(&model::setup::Variant::KeyServerChallenge { ref key, .. }) => {
            key_negotiate(
                BoundStorage {
                    delegate: storage,
                    identifier,
                },
                message_stream,
                key.server_challenge(),
            )
            .await
        }
        _ => Err(error::Api::UnhandledMessage(msg).into()),
    }
}

/// Authenticate using the given message stream.
///
/// After this function returns, the message stream is ready for encrypted
/// JSON-RPC communication with the session key placed in the storage.
async fn authenticate<
    'storage,
    Storage: storage::Storage<session::Data>,
    Prompt: password::Prompt,
    MessageStream: message::Stream,
>(
    storage: &'storage mut Storage,
    prompt: &Prompt,
    message_stream: &mut MessageStream,
) -> Result<BoundStorage<'storage, Storage>> {
    match storage.get().await {
        Ok(Some(session_data)) => match *session_data.session_key() {
            Some(_) => key_init(storage, prompt, message_stream, session_data.identifier()).await,
            None => {
                srp_init(
                    storage,
                    prompt,
                    None,
                    message_stream,
                    srp::ProtocolBuilder::new()
                        .with_identifier(session_data.identifier())
                        .into_protocol(),
                )
                .await
            }
        },
        Ok(None) => srp_init(storage, prompt, None, message_stream, srp::Protocol::new()).await,
        Err(e) => {
            warn!(
                "Failed to decode session data, so we have to start over: {}",
                e
            );
            srp_init(storage, prompt, None, message_stream, srp::Protocol::new()).await
        }
    }
}

pub(crate) async fn run<
    Storage: storage::Storage<session::Data>,
    Prompt: password::Prompt,
    MessageStream: message::Stream,
    CallStream: Stream<Item = JsonrpcCall> + Send + Unpin,
>(
    storage: &mut Storage,
    prompt: &Prompt,
    message_stream: &mut MessageStream,
    call_stream: &mut CallStream,
) -> Result<()> {
    let mut pending_call: Option<JsonrpcCall> = None;

    'reauthenticate: loop {
        let mut bound_storage = authenticate(storage, prompt, message_stream).await?;

        let mut backfilled_call_stream = stream::iter(pending_call.take()).chain(&mut *call_stream);
        let mut calls: HashMap<model::jsonrpc::Id, JsonrpcCall> = HashMap::new();

        loop {
            select! {
                candidate = message_stream.next() => {
                    let msg = candidate.ok_or(error::Api::StreamEnded)??;
                    let dec = bound_storage
                        .map_session_key(|session_key| msg.as_jsonrpc(session_key))
                        .await
                        .unwrap_or(None);

                    match dec {
                        Some(Some(Ok(model::jsonrpc::Jsonrpc::Response(resp)))) => {
                            if let Some(call) = calls.remove(resp.id()) {
                                if let Err(failed_resp) = call.tx.send(Ok(resp)) {
                                    warn!("Failed to inform disconnected call receiver {:?} of JSON-RPC response", failed_resp?.id());
                                }
                            }
                        }
                        Some(None) => return Err(error::Api::StreamEnded.into()),
                        None => {
                            // We will have no way to decrypt this message, so
                            // we have to drop it, as well as any other
                            // outstanding calls waiting for a response.
                            for call in calls.into_values() {
                                let _result = call.tx.send(Err(error::Storage::Conflict.into()));
                            }
                            continue 'reauthenticate;
                        }
                        _ => return Err(error::Api::UnhandledMessage(msg).into()),
                    };
                },
                candidate = backfilled_call_stream.next() => {
                    match candidate {
                        Some(call) => {
                            let enc = bound_storage
                                .map_session_key(|session_key| {
                                    model::Message::new_from_jsonrpc(session_key, &call.req)
                                })
                                .await
                                .unwrap_or(None)
                                .transpose()?;

                            match enc {
                                Some(msg) => {
                                    message_stream.send(msg).await?;
                                    if let model::jsonrpc::Jsonrpc::Request(ref req) = call.req {
                                        if let Some(id) = req.id().as_ref() {
                                            assert!(calls.insert(id.clone(), call).is_none());
                                        }
                                    };
                                }
                                None => {
                                    pending_call = Some(call);
                                    continue 'reauthenticate;
                                }
                            };
                        }
                        None => {
                            return Ok(());
                        }
                    };
                }
            };
        }
    }
}
