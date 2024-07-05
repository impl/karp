// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use crypto_box::{aead::AeadCore, SalsaBox};
pub(in crate::keepassxc) use crypto_box::{Nonce, PublicKey, KEY_SIZE};
use digest::typenum::Unsigned;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::rng;

pub(in crate::keepassxc) const NONCE_SIZE: usize = <SalsaBox as AeadCore>::NonceSize::USIZE;

pub(in crate::keepassxc) fn generate_nonce() -> Nonce {
    rng::map(|rng| SalsaBox::generate_nonce(rng))
}

#[derive(Deserialize, Serialize, Clone)]
pub(in crate::keepassxc) struct SecretKeyMaterial(crypto_box::SecretKey);

impl AsRef<crypto_box::SecretKey> for SecretKeyMaterial {
    fn as_ref(&self) -> &crypto_box::SecretKey {
        &self.0
    }
}

impl secrecy::Zeroize for SecretKeyMaterial {
    fn zeroize(&mut self) {
        self.0 = crypto_box::SecretKey::from_bytes([0; KEY_SIZE]);
    }
}

impl secrecy::CloneableSecret for SecretKeyMaterial {}

impl secrecy::SerializableSecret for SecretKeyMaterial {}

#[derive(Deserialize, Serialize, Clone)]
pub(in crate::keepassxc) struct SecretKey(secrecy::Secret<SecretKeyMaterial>);

impl SecretKey {
    pub(in crate::keepassxc) fn generate() -> Self {
        Self(secrecy::Secret::new(SecretKeyMaterial(rng::map(
            crypto_box::SecretKey::generate,
        ))))
    }
}

impl ExposeSecret<SecretKeyMaterial> for SecretKey {
    fn expose_secret(&self) -> &SecretKeyMaterial {
        self.0.expose_secret()
    }
}

pub(in crate::keepassxc) struct SharedKeyMaterial(SalsaBox);

impl SharedKeyMaterial {
    pub(super) fn new(host_key: &PublicKey, client_key: &SecretKey) -> Self {
        Self(SalsaBox::new(host_key, client_key.expose_secret().as_ref()))
    }
}

impl AsRef<SalsaBox> for SharedKeyMaterial {
    fn as_ref(&self) -> &SalsaBox {
        &self.0
    }
}

impl secrecy::Zeroize for SharedKeyMaterial {
    fn zeroize(&mut self) {
        self.0 = SalsaBox::new(
            &PublicKey::from_bytes([0; KEY_SIZE]),
            &crypto_box::SecretKey::from_bytes([0; KEY_SIZE]),
        );
    }
}

pub(in crate::keepassxc) type SharedKey = secrecy::Secret<SharedKeyMaterial>;
