// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use log::debug;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    error::{self, Result},
    model,
};

pub(crate) trait Sink:
    futures_util::Sink<model::Message, Error = error::Error> + Send + Sync + Unpin
{
}

impl<T: futures_util::Sink<model::Message, Error = error::Error> + Send + Sync + Unpin> Sink for T {}

pub(crate) trait Stream: Sink + futures_util::Stream<Item = Result<model::Message>> {}

impl<T: Sink + futures_util::Stream<Item = Result<model::Message>>> Stream for T {}

pub(crate) struct WebSocketStream<S>(tokio_tungstenite::WebSocketStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> futures_util::Stream for WebSocketStream<S> {
    type Item = Result<model::Message>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0)
            .poll_next(cx)
            .map_err(Into::into)
            .map(|inner| {
                let msg = inner?.and_then(|msg| {
                    Ok(serde_json::from_str(&{
                        let text = msg.into_text()?;
                        debug!("Received raw message: {}", text);
                        text
                    })?)
                });
                debug!("Decoded message: {:?}", msg);
                Some(msg)
            })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> futures_util::Sink<model::Message> for WebSocketStream<S> {
    type Error = error::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, item: model::Message) -> Result<(), Self::Error> {
        debug!("Sending message: {:?}", item);
        Pin::new(&mut self.0)
            .start_send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::to_string(&item)?,
            ))
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_close(cx).map_err(Into::into)
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Sync + Unpin> From<tokio_tungstenite::WebSocketStream<S>>
    for WebSocketStream<S>
{
    fn from(s: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self(s)
    }
}
