// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{fmt::Debug, marker::PhantomData};

use crypto_box::aead::Aead;
use secrecy::{ExposeSecret as _, Secret};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::error::Result;

use super::{super::error as keepassxc_error, key_material, HasNonce};

#[serde_as]
#[derive(Deserialize, Serialize, PartialEq)]
pub(in crate::keepassxc) struct EncryptedJson<T> {
    #[serde_as(as = "Base64")]
    message: Vec<u8>,
    #[serde_as(as = "Base64")]
    nonce: [u8; key_material::NONCE_SIZE],
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> EncryptedJson<T> {
    pub(super) fn encrypt(secret: &key_material::SharedKey, msg: T) -> Result<Self>
    where
        T: Serialize,
    {
        let nonce = key_material::generate_nonce();
        let plaintext = Secret::new(serde_json::to_string(&msg)?);

        Ok(Self {
            message: secret
                .expose_secret()
                .as_ref()
                .encrypt(&nonce, plaintext.expose_secret().as_bytes())
                .map_err(Into::<keepassxc_error::Error>::into)?,
            nonce: nonce.into(),
            _marker: PhantomData,
        })
    }

    pub(super) fn decrypt(&self, secret: &key_material::SharedKey) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let plaintext = Secret::new(
            secret
                .expose_secret()
                .as_ref()
                .decrypt(&self.nonce.into(), &*self.message)
                .map_err(Into::<keepassxc_error::Error>::into)?,
        );

        Ok(serde_json::from_slice(plaintext.expose_secret())?)
    }
}

impl<T> Debug for EncryptedJson<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedJson").finish()
    }
}

impl<T> HasNonce for EncryptedJson<T> {
    fn nonce(&self) -> &key_material::Nonce {
        key_material::Nonce::from_slice(&self.nonce)
    }
}
