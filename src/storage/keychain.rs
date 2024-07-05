// SPDX-FileCopyrightText: 2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use secrecy::{ExposeSecret as _, SecretVec};
use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
use serde::{Deserialize, Serialize};

use crate::{
    error::{self, Result},
    metadata,
};

use super::{IsPersistent, Storage};

pub(crate) struct Keychain {
    delegate: SecKeychain,
    service: String,
    account: String,
}

impl Keychain {
    pub(crate) fn new(url: &url::Url) -> Result<Self> {
        Ok(Self {
            delegate: SecKeychain::default_for_domain(SecPreferencesDomain::User)
                .map_err(Into::<error::Storage>::into)?,
            service: metadata::PROJECT_DIRS
                .as_ref()
                .map(|dirs| dirs.project_path().as_os_str())
                .ok_or(error::Storage::NoProjectDirs)?
                .to_string_lossy()
                .to_string(),
            account: url.to_string(),
        })
    }
}

impl IsPersistent for Keychain {
    fn is_persistent(&self) -> bool {
        true
    }
}

#[async_trait]
impl<T: for<'de> Deserialize<'de> + Send + Serialize + Sync> Storage<T> for Keychain {
    async fn get(&mut self) -> Result<Option<T>> {
        let result = self
            .delegate
            .find_generic_password(&self.service, &self.account);
        match result {
            Ok((password, _)) => Ok(Some(serde_json::from_slice(&password)?)),
            Err(err) if err.code() == -25300_i32 => Ok(None),
            Err(err) => Err(Into::<error::Storage>::into(err).into()),
        }
    }

    async fn update(&mut self, data: &T) -> Result<()> {
        self.delegate
            .set_generic_password(
                &self.service,
                &self.account,
                SecretVec::new(serde_json::to_vec(data)?).expose_secret(),
            )
            .map_err(Into::<error::Storage>::into)?;
        Ok(())
    }

    async fn clear(&mut self) -> Result<()> {
        let result = self
            .delegate
            .find_generic_password(&self.service, &self.account);
        match result {
            Ok((_, item)) => item.delete(),
            Err(err) if err.code() == -25300_i32 => {}
            Err(err) => return Err(Into::<error::Storage>::into(err).into()),
        };
        Ok(())
    }
}
