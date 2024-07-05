// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use directories::ProjectDirs;
use inflector::Inflector;
use once_cell::sync::Lazy;

pub(crate) const CLIENT_VERSION: u32 = u32::from_be_bytes([0, 2, 0, 0]);
pub(crate) static CLIENT_TYPE_ID: Lazy<String> =
    Lazy::new(|| option_env!("CARGO_PKG_NAME").unwrap_or("karp").to_owned());
pub(crate) static CLIENT_DISPLAY_NAME: Lazy<String> = Lazy::new(|| CLIENT_TYPE_ID.to_title_case());
pub(crate) static CLIENT_DISPLAY_DESCRIPTION: Lazy<Option<String>> =
    Lazy::new(|| option_env!("CARGO_PKG_DESCRIPTION").map(str::to_owned));

pub(crate) static PROJECT_DIRS: Lazy<Option<ProjectDirs>> =
    Lazy::new(|| ProjectDirs::from("com", "NoahFontes", &CLIENT_DISPLAY_NAME));
