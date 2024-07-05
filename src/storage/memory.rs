// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::error::Result;

use super::{IsPersistent, Storage};

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
