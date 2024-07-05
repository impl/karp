// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::Encoding as _;
use log::debug;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::{base64::Base64, json::JsonString, serde_as, DisplayFromStr};

use rand::Rng as _;

use crate::{error::Result, rng};

use super::error as keepassxc_error;

pub(super) mod encrypted_json;
pub(super) mod key_material;

pub(super) trait HasAction {
    fn action(&self) -> &str;
}

pub(super) trait HasNonce {
    fn nonce(&self) -> &key_material::Nonce;
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct Key {
    pub(super) id: String,
    #[serde_as(as = "Base64")]
    pub(super) key: [u8; key_material::KEY_SIZE],
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct KeyedPayload<T> {
    action: String,
    keys: Vec<Key>,
    #[serde(flatten)]
    payload: T,
}

#[serde_as]
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct Request {
    action: String,
    #[serde(flatten)]
    payload: serde_json::Value,
    #[serde_as(as = "Base64")]
    #[serde(rename = "clientID")]
    client_id: [u8; key_material::KEY_SIZE],
    #[serde(rename = "requestID")]
    id: String,
    #[serde_as(as = "DisplayFromStr")]
    trigger_unlock: bool,
}

impl Request {
    fn new<T: Serialize>(
        action: String,
        client_id: &[u8; key_material::KEY_SIZE],
        payload: T,
        trigger_unlock: bool,
    ) -> Result<Self> {
        Ok(Request {
            action,
            payload: serde_json::to_value(payload)?,
            client_id: *client_id,
            id: rng::map(|rng| {
                rng.sample_iter(&rand::distributions::Alphanumeric)
                    .take(8)
                    .map(char::from)
                    .collect()
            }),
            trigger_unlock,
        })
    }

    fn new_encrypted<T: Serialize>(
        action: String,
        client_id: &[u8; key_material::KEY_SIZE],
        keys: &dyn AsRef<[Key]>,
        secret: &key_material::SharedKey,
        payload: T,
        trigger_unlock: bool,
    ) -> Result<(Self, key_material::Nonce)> {
        let encrypted_payload = encrypted_json::EncryptedJson::encrypt(
            secret,
            KeyedPayload {
                action: action.clone(),
                keys: keys.as_ref().to_vec(),
                payload,
            },
        )?;
        let nonce = *encrypted_payload.nonce();
        Ok((
            Self::new(action, client_id, encrypted_payload, trigger_unlock)?,
            nonce,
        ))
    }
}

impl HasAction for Request {
    fn action(&self) -> &str {
        &self.action
    }
}

#[derive(Clone, Copy, Debug, Deserialize_repr, Serialize_repr, PartialEq)]
#[repr(u8)]
pub(super) enum ErrorCode {
    UnknownError = 0,
    DatabaseNotOpened = 1,
    DatabaseHashNotReceived = 2,
    ClientPublicKeyNotReceived = 3,
    CannotDecryptMessage = 4,
    TimeoutOrNotConnected = 5,
    ActionCancelledOrDenied = 6,
    PublicKeyNotFound = 7,
    AssociationFailed = 8,
    KeyChangeFailed = 9,
    EncryptionKeyUnrecognized = 10,
    NoSavedDatabasesFound = 11,
    IncorrectAction = 12,
    EmptyMessageReceived = 13,
    NoUrlProvided = 14,
    NoLoginsFound = 15,
    NoGroupsFound = 16,
    CannotCreateNewGroup = 17,
    NoValidUuidProvided = 18,
    AccessToAllEntriesDenied = 19,
    PasskeysAttestationNotSupported = 20,
    PasskeysCredentialIsExcluded = 21,
    PasskeysRequestCanceled = 22,
    PasskeysInvalidUserVerification = 23,
    PasskeysEmptyPublicKey = 24,
    PasskeysInvalidUrlProvided = 25,
    PasskeysOriginNotAllowed = 26,
    PasskeysDomainIsNotValid = 27,
    PasskeysDomainRpidMismatch = 28,
    PasskeysNoSupportedAlgorithms = 29,
    PasskeysWaitForLifetimer = 30,
    PasskeysUnknownError = 31,
    PasskeysInvalidChallenge = 32,
    PasskeysInvalidUserId = 33,
    #[serde(other)]
    Other,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Error {
    error: String,
    #[serde_as(as = "JsonString")]
    error_code: ErrorCode,
}

impl Error {
    pub(in crate::keepassxc) fn error(&self) -> &str {
        &self.error
    }

    pub(in crate::keepassxc) fn error_code(&self) -> ErrorCode {
        self.error_code
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct Response {
    action: String,
    #[serde(flatten)]
    error: Option<Error>,
    #[serde(flatten)]
    payload: serde_json::Value,
}

impl HasAction for Response {
    fn action(&self) -> &str {
        &self.action
    }
}

fn increment_nonce(nonce: &key_material::Nonce) -> key_material::Nonce {
    *key_material::Nonce::from_slice(
        &crypto_bigint::U192::from_le_slice(nonce)
            .wrapping_add(&crypto_bigint::Uint::ONE)
            .to_le_bytes(),
    )
}

pub(super) struct MessageBuilder {
    client_id: [u8; key_material::KEY_SIZE],
    client_secret: key_material::SecretKey,
}

impl MessageBuilder {
    pub(super) fn new() -> Self {
        let mut client_id = [0; key_material::KEY_SIZE];
        rng::map(|rng| rng.fill(&mut client_id));

        let client_secret = key_material::SecretKey::generate();

        Self {
            client_id,
            client_secret,
        }
    }

    pub(super) fn encrypt(self, host_key: &key_material::PublicKey) -> EncryptedMessageBuilder {
        EncryptedMessageBuilder {
            client_id: self.client_id,
            client_key: self.client_key(),
            secret: key_material::SharedKey::new(key_material::SharedKeyMaterial::new(
                host_key,
                &self.client_secret,
            )),
        }
    }

    pub(super) fn client_key(&self) -> key_material::PublicKey {
        self.client_secret.expose_secret().as_ref().public_key()
    }

    pub(super) fn encode_request<T: HasAction + HasNonce + Serialize>(
        &self,
        msg: &T,
        trigger_unlock: bool,
    ) -> Result<(Request, key_material::Nonce)> {
        Ok((
            Request::new(
                msg.action().to_owned(),
                &self.client_id,
                msg,
                trigger_unlock,
            )?,
            increment_nonce(msg.nonce()),
        ))
    }

    pub(super) fn decode_response<T: for<'de> Deserialize<'de> + HasNonce>(
        resp: Response,
        nonce: &key_material::Nonce,
    ) -> Result<T> {
        debug!("Deserializing unencrypted response: {:?}", resp);
        match resp.error {
            None => {
                let value: T = serde_json::from_value(resp.payload)?;
                if value.nonce() != nonce {
                    return Err(keepassxc_error::Api::InvalidNonce.into());
                }

                Ok(value)
            }
            Some(error) => Err(keepassxc_error::Api::ServerError(error).into()),
        }
    }
}

pub(super) struct EncryptedMessageBuilder {
    client_id: [u8; key_material::KEY_SIZE],
    client_key: key_material::PublicKey,
    secret: key_material::SharedKey,
}

impl EncryptedMessageBuilder {
    pub(super) fn client_key(&self) -> &key_material::PublicKey {
        &self.client_key
    }

    pub(super) fn encode_request<T: HasAction + Serialize>(
        &self,
        keys: &dyn AsRef<[Key]>,
        msg: &T,
        trigger_unlock: bool,
    ) -> Result<(Request, key_material::Nonce)> {
        let (req, nonce) = Request::new_encrypted(
            msg.action().to_owned(),
            &self.client_id,
            keys,
            &self.secret,
            msg,
            trigger_unlock,
        )?;
        Ok((req, increment_nonce(&nonce)))
    }

    pub(super) fn decode_response_with<T: for<'de> Deserialize<'de>, A, F>(
        &self,
        resp: Response,
        f: F,
    ) -> Result<(T, A)>
    where
        F: FnOnce(&encrypted_json::EncryptedJson<T>) -> Result<A>,
    {
        debug!("Deserializing encrypted response: {:?}", resp);
        match resp.error {
            None => {
                let encrypted_value: encrypted_json::EncryptedJson<T> =
                    serde_json::from_value(resp.payload)?;
                let associated = f(&encrypted_value)?;

                Ok((encrypted_value.decrypt(&self.secret)?, associated))
            }
            Some(error) => Err(keepassxc_error::Api::ServerError(error).into()),
        }
    }

    pub(super) fn decode_response<T: for<'de> Deserialize<'de>>(
        &self,
        encrypted_resp: Response,
        nonce: &key_material::Nonce,
    ) -> Result<T> {
        let (resp, ()) = self.decode_response_with(encrypted_resp, |encrypted_value| {
            if encrypted_value.nonce() != nonce {
                return Err(keepassxc_error::Api::InvalidNonce.into());
            }

            Ok(())
        })?;
        Ok(resp)
    }
}
