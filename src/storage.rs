// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    error::{self, Result},
    metadata, model,
};

pub(crate) trait IsPersistent {
    fn is_persistent(&self) -> bool;

    fn security_level(&self) -> model::setup::SecurityLevel {
        if self.is_persistent() {
            model::setup::SecurityLevel::Medium
        } else {
            model::setup::SecurityLevel::High
        }
    }
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

pub(crate) struct Memory<T> {
    data: Arc<RwLock<Option<T>>>,
}

impl<T> Memory<T> {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl<T> IsPersistent for Memory<T> {
    fn is_persistent(&self) -> bool {
        false
    }
}

#[async_trait]
impl<T: Send + Sync + Clone> Storage<T> for Memory<T> {
    async fn get(&mut self) -> Result<Option<T>> {
        let data = Arc::clone(&self.data);
        let guard = data.read().await;
        Ok(guard.clone())
    }

    async fn update(&mut self, data: &T) -> Result<()> {
        let target_data = Arc::clone(&self.data);
        let mut guard = target_data.write_owned().await;
        *guard = Some(data.clone());
        Ok(())
    }

    async fn clear(&mut self) -> Result<()> {
        let target_data = Arc::clone(&self.data);
        let mut guard = target_data.write_owned().await;
        *guard = None;
        Ok(())
    }
}

impl<T> Default for Memory<T> {
    fn default() -> Self {
        Self {
            data: Arc::new(RwLock::new(None)),
        }
    }
}

pub(crate) struct File {
    path: PathBuf,
}

impl File {
    pub(crate) fn new<P: AsRef<Path>>(file: P) -> Option<Self> {
        metadata::PROJECT_DIRS.as_ref().map(|dirs| Self {
            path: dirs.data_dir().to_owned().join(file),
        })
    }
}

impl IsPersistent for File {
    fn is_persistent(&self) -> bool {
        true
    }
}

#[async_trait]
impl<T: Send + Serialize + Sync + for<'de> Deserialize<'de>> Storage<T> for File {
    async fn get(&mut self) -> Result<Option<T>> {
        match fs::File::open(&self.path) {
            Ok(fp) => Ok(Some(serde_json::from_reader::<fs::File, T>(fp)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn update(&mut self, data: &T) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = fs::File::create(&self.path)?;
        serde_json::to_writer(file, data)?;
        Ok(())
    }

    async fn clear(&mut self) -> Result<()> {
        fs::remove_file(&self.path)?;
        Ok(())
    }
}

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
                &*metadata::CLIENT_DISPLAY_NAME,
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
