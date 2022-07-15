// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{fmt::Debug, marker::PhantomData};

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, Iv, IvSizeUser, Key, KeyIvInit, Unsigned};
use rand::Rng;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;

use crate::{
    error::{self, Result},
    rng,
};

use super::hash;

fn compute_mac<KeyT, PayloadT, IvT>(key: KeyT, payload: PayloadT, iv: IvT) -> [u8; 20]
where
    KeyT: AsRef<[u8]>,
    PayloadT: AsRef<[u8]>,
    IvT: AsRef<[u8]>,
{
    Sha1::new_with_prefix(sha1::Sha1::digest(key))
        .chain_update(payload)
        .chain_update(iv)
        .finalize()
        .into()
}

#[serde_as]
#[derive(Deserialize, Serialize, PartialEq)]
pub(crate) struct EncryptedJson<T> {
    #[serde_as(as = "Base64")]
    message: Vec<u8>,
    #[serde_as(as = "Base64")]
    iv: [u8; <cbc::Encryptor<aes::Aes256> as IvSizeUser>::IvSize::USIZE],
    #[serde_as(as = "Base64")]
    hmac: [u8; 20],
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> EncryptedJson<T> {
    pub(super) fn encrypt(session_key: &hash::Secret, msg: &T) -> Result<Self>
    where
        T: Serialize,
    {
        let key: Secret<[u8; 32]> = session_key.into();

        let mut iv = Iv::<cbc::Encryptor<aes::Aes256>>::default();
        rng::map(|rng| rng.fill(&mut *iv));

        let plaintext = Secret::new(serde_json::to_string(&msg)?);

        let encryptor = cbc::Encryptor::<aes::Aes256>::new(
            Key::<cbc::Encryptor<aes::Aes256>>::from_slice(key.expose_secret()),
            &iv,
        );
        let message = encryptor
            .encrypt_padded_vec_mut::<block_padding::Pkcs7>(plaintext.expose_secret().as_bytes());

        let mac = compute_mac(key.expose_secret(), &message, &iv);

        Ok(Self {
            message,
            iv: iv.into(),
            hmac: mac,
            _marker: PhantomData::default(),
        })
    }

    pub(super) fn decrypt(&self, session_key: &hash::Secret) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let key: Secret<[u8; 32]> = session_key.into();

        let mac = compute_mac(key.expose_secret(), &self.message, &self.iv);
        if mac.ct_eq(&self.hmac).unwrap_u8() != 1 {
            return Err(error::Api::MessageAuthenticationFailure.into());
        }

        let decryptor = cbc::Decryptor::<aes::Aes256>::new(
            Key::<cbc::Decryptor<aes::Aes256>>::from_slice(key.expose_secret()),
            Iv::<cbc::Decryptor<aes::Aes256>>::from_slice(&self.iv),
        );
        let plaintext = Secret::new(
            decryptor
                .decrypt_padded_vec_mut::<block_padding::Pkcs7>(&self.message)
                .map_err(error::Conversion::from)?,
        );

        Ok(serde_json::from_slice::<T>(plaintext.expose_secret())?)
    }
}

impl<T> Debug for EncryptedJson<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedJson").finish()
    }
}
