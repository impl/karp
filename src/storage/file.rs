// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{error::Result, metadata};

use super::{IsPersistent, Storage};

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
