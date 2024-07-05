// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{fmt::Debug, marker::PhantomData};

use log::{debug, warn};
use serde::{Deserialize, Serialize};
use serde_json::Deserializer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::bytes::{Buf, BufMut as _};

use crate::error::{self, Result};

use super::model;

pub(super) trait Sink:
    futures_util::Sink<model::Request, Error = error::Error> + Send + Sync + Unpin
{
}

impl<T: futures_util::Sink<model::Request, Error = error::Error> + Send + Sync + Unpin> Sink for T {}

pub(super) trait Stream:
    Sink + futures_util::Stream<Item = Result<model::Response>>
{
}

impl<T: Sink + futures_util::Stream<Item = Result<model::Response>>> Stream for T {}

/// A codec for encoding and decoding JSON messages that are undelimited and
/// unframed.
pub(super) struct JsonCodec<I, O> {
    _input_marker: PhantomData<I>,
    _output_marker: PhantomData<O>,
}

impl<I, O> JsonCodec<I, O> {
    pub(super) fn new() -> Self {
        Self {
            _input_marker: PhantomData,
            _output_marker: PhantomData,
        }
    }
}

impl<I, O: for<'de> Deserialize<'de>> tokio_util::codec::Decoder for JsonCodec<I, O> {
    type Item = O;
    type Error = error::Error;

    fn decode(
        &mut self,
        buf: &mut tokio_util::bytes::BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        let mut iter = Deserializer::from_slice(buf).into_iter();
        let value: Result<Option<Self::Item>> = iter.next().unwrap_or(Ok(None)).or_else(|err| {
            if err.is_eof() {
                Ok(None)
            } else {
                warn!(
                    "Failed to decode message from stream with contents {:?}: {:?}",
                    std::str::from_utf8(buf).map_err(Into::<error::Conversion>::into)?,
                    err
                );
                Err(err)?
            }
        });
        if let &Ok(Some(_)) = &value {
            debug!(
                "Received raw message: {:?}",
                std::str::from_utf8(&buf[..iter.byte_offset()])
                    .map_err(Into::<error::Conversion>::into)?
            );
        }
        buf.advance(iter.byte_offset());
        value
    }
}

impl<I: Serialize + Debug, O> tokio_util::codec::Encoder<I> for JsonCodec<I, O> {
    type Error = error::Error;

    fn encode(
        &mut self,
        item: I,
        buf: &mut tokio_util::bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        debug!("Sending message: {:?}", item);
        Ok(serde_json::to_writer(&mut buf.writer(), &item)?)
    }
}

pub(super) struct JsonMessageStream<T>(
    tokio_util::codec::Framed<T, JsonCodec<model::Request, model::Response>>,
);

impl<T> AsMut<tokio_util::codec::Framed<T, JsonCodec<model::Request, model::Response>>>
    for JsonMessageStream<T>
{
    fn as_mut(
        &mut self,
    ) -> &mut tokio_util::codec::Framed<T, JsonCodec<model::Request, model::Response>> {
        &mut self.0
    }
}

impl<T: AsyncRead + AsyncWrite> From<T> for JsonMessageStream<T> {
    fn from(stream: T) -> Self {
        Self(tokio_util::codec::Framed::new(stream, JsonCodec::new()))
    }
}
