// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::{ffi::OsString, path::Path};

use async_trait::async_trait;
use secrecy::SecretString;
use tokio::task;

use crate::{error::Result, metadata};

#[derive(Debug, Default, Clone)]
pub(crate) struct Request {
    error: Option<String>,
}

pub(crate) struct RequestBuilder {
    error: Option<String>,
}

impl RequestBuilder {
    pub(crate) const fn new() -> Self {
        Self { error: None }
    }

    pub(crate) fn with_error(mut self, error: &str) -> Self {
        self.error = Some(error.to_owned());
        self
    }

    pub(crate) fn into_request(self) -> Request {
        Request { error: self.error }
    }
}

#[async_trait]
pub(crate) trait Prompt: Send + Sync {
    async fn prompt(&self, req: Request) -> Result<Option<SecretString>>;
}

#[async_trait]
impl<T: Prompt + ?Sized> Prompt for Box<T> {
    async fn prompt(&self, req: Request) -> Result<Option<SecretString>> {
        (**self).prompt(req).await
    }
}

#[async_trait]
impl<T: Prompt> Prompt for Vec<T> {
    async fn prompt(&self, req: Request) -> Result<Option<SecretString>> {
        for candidate in self {
            if let r @ (Ok(Some(_)) | Err(_)) = candidate.prompt(req.clone()).await {
                return r;
            }
        }

        Ok(None)
    }
}

pub(crate) struct PinentryPrompt {
    executable: Option<OsString>,
}

impl PinentryPrompt {
    pub(crate) const fn new() -> Self {
        Self { executable: None }
    }

    pub(crate) fn new_with_executable<P: AsRef<Path>>(executable: P) -> Self {
        Self {
            executable: Some(executable.as_ref().as_os_str().into()),
        }
    }
}

#[async_trait]
impl Prompt for PinentryPrompt {
    async fn prompt(&self, req: Request) -> Result<Option<SecretString>> {
        fn interact<'input>(
            mut input: pinentry::PassphraseInput<'input>,
            title: &'input str,
            error: Option<&'input String>,
        ) -> Result<SecretString> {
            _ = input.required("You must enter the password presented by KeePassRPC to continue.");
            _ = input.with_title(title);
            _ = input.with_prompt("Password");
            if let Some(e) = error {
                _ = input.with_error(e);
            }

            Ok(input.interact()?)
        }

        let title = format!("Password - {}", *metadata::CLIENT_DISPLAY_NAME);

        let input = self
            .executable
            .as_ref()
            .and_then(pinentry::PassphraseInput::with_binary)
            .or_else(pinentry::PassphraseInput::with_default_binary)
            .map(|input| task::spawn_blocking(move || interact(input, &title, req.error.as_ref())));

        Ok(match input {
            Some(fut) => Some(fut.await??),
            None => None,
        })
    }
}

pub(crate) struct RpasswordPrompt;

#[async_trait]
impl Prompt for RpasswordPrompt {
    async fn prompt(&self, req: Request) -> Result<Option<SecretString>> {
        if let Some(error) = req.error {
            eprintln!("Error: {error}");
        }

        Ok(Some(
            task::spawn_blocking(|| {
                rpassword::prompt_password("Password: ").map(SecretString::new)
            })
            .await??,
        ))
    }
}
