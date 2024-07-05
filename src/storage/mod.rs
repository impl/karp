// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

mod file;
#[cfg(feature = "keychain")]
mod keychain;
mod memory;
#[cfg(feature = "secret-service")]
mod secret_service;

use async_trait::async_trait;

use crate::error::Result;

pub(crate) use file::File;
#[cfg(feature = "keychain")]
pub(crate) use keychain::Keychain;
pub(crate) use memory::Memory;
#[cfg(feature = "secret-service")]
pub(crate) use secret_service::SecretService;

pub(crate) trait IsPersistent {
    fn is_persistent(&self) -> bool;
}

impl<T: IsPersistent + ?Sized> IsPersistent for Box<T> {
    fn is_persistent(&self) -> bool {
        (**self).is_persistent()
    }
}

#[async_trait]
pub(crate) trait Storage<T>: Send + Sync + IsPersistent {
    async fn get(&mut self) -> Result<Option<T>>;
    async fn update(&mut self, data: &T) -> Result<()>;
    #[allow(dead_code)]
    async fn clear(&mut self) -> Result<()>;
}

#[async_trait]
impl<Tn: Sync, T: Storage<Tn> + ?Sized> Storage<Tn> for Box<T> {
    async fn get(&mut self) -> Result<Option<Tn>> {
        (**self).get().await
    }

    async fn update(&mut self, data: &Tn) -> Result<()> {
        (**self).update(data).await
    }

    async fn clear(&mut self) -> Result<()> {
        (**self).clear().await
    }
}
