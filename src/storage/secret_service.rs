// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};

use crate::{
    error::{self, Result},
    metadata,
};

use super::{IsPersistent, Storage};

pub(crate) struct SecretService {
    keyring: oo7::Keyring,
    attributes: HashMap<String, String>,
}

impl SecretService {
    async fn item(&self) -> Result<Option<oo7::Item>> {
        Ok(self
            .keyring
            .search_items(
                self.attributes
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str()))
                    .collect(),
            )
            .await
            .map_err(error::Storage::from)?
            .into_iter()
            .next())
    }

    pub(crate) async fn new(url: &url::Url) -> Result<Self> {
        Ok(Self {
            keyring: oo7::Keyring::new().await.map_err(error::Storage::from)?,
            attributes: HashMap::from([
                ("karp.kind".to_owned(), "storage".to_owned()),
                ("karp.url".to_owned(), url.as_str().to_owned()),
            ]),
        })
    }
}

impl IsPersistent for SecretService {
    fn is_persistent(&self) -> bool {
        true
    }
}

#[async_trait]
impl<T: for<'de> Deserialize<'de> + Send + Serialize + Sync> Storage<T> for SecretService {
    async fn get(&mut self) -> Result<Option<T>> {
        let data = match self.item().await? {
            Some(item) => {
                let secret = item.secret().await.map_err(error::Storage::from)?;
                serde_json::from_slice(&secret)?
            }
            None => None,
        };
        Ok(data)
    }

    async fn update(&mut self, data: &T) -> Result<()> {
        self.keyring
            .create_item(
                &metadata::CLIENT_DISPLAY_NAME,
                self.attributes
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str()))
                    .collect(),
                SecretVec::new(serde_json::to_vec(data)?).expose_secret(),
                true,
            )
            .await
            .map_err(error::Storage::from)?;
        Ok(())
    }

    async fn clear(&mut self) -> Result<()> {
        if let Some(item) = self.item().await? {
            item.delete().await.map_err(error::Storage::from)?;
        }
        Ok(())
    }
}
