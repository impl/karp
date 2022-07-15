// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use uuid::Uuid;

use crate::{metadata, srp};

use super::{hash::Hash, key_material::KeyMaterial};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum ErrorCode {
    AuthFailed,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Error {
    code: ErrorCode,
    message_params: Vec<String>,
}

impl Error {
    #[cfg(any())]
    pub(crate) fn code(&self) -> ErrorCode {
        self.code
    }
}

impl PartialEq<ErrorCode> for Error {
    fn eq(&self, other: &ErrorCode) -> bool {
        &self.code == other
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.code)?;
        for param in &self.message_params {
            write!(f, ": {}", param)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[non_exhaustive]
pub(crate) enum ClientFeature {
    #[serde(rename = "KPRPC_FEATURE_VERSION_1_6")]
    FeatureVersion1_6,
    #[serde(rename = "KPRPC_FEATURE_WARN_USER_WHEN_FEATURE_MISSING")]
    FeatureWarnUserWhenFeatureMissing,
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[non_exhaustive]
pub(crate) enum ServerFeature {
    #[serde(rename = "KPRPC_FEATURE_VERSION_1_6")]
    FeatureVersion1_6,
    #[serde(rename = "KPRPC_GENERAL_CLIENTS")]
    GeneralClients,
    #[serde(rename = "KPRPC_FEATURE_KEE_BRAND")]
    FeatureKeeBrand,
    #[serde(rename = "KPRPC_ENTRIES_WITH_NO_URL")]
    EntriesWithNoUrl,
    #[serde(rename = "KPRPC_FIELD_DEFAULT_NAME_AND_ID_EMPTY")]
    FieldDefaultNameAndIdEmpty,
    #[serde(rename = "KPRPC_OPEN_AND_FOCUS_DATABASE")]
    OpenAndFocusDatabase,
    #[serde(rename = "KPRPC_FEATURE_ENTRY_URL_REPLACEMENT")]
    FeatureEntryUrlReplacement,
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize_repr, Serialize_repr, PartialEq, PartialOrd, Clone, Copy)]
#[repr(i32)]
pub(crate) enum SecurityLevel {
    Low = 1_i32,
    Medium = 2_i32,
    High = 3_i32,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ClientInitVariant {
    Srp(SrpIdentifyToServer),
    #[serde(rename_all = "camelCase")]
    Key {
        username: String,
        security_level: SecurityLevel,
    },
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyServerChallenge {
    #[serde(rename = "sc")]
    server_challenge: String,
    security_level: SecurityLevel,
}

impl KeyServerChallenge {
    pub(crate) fn server_challenge(&self) -> &str {
        &self.server_challenge
    }

    pub(crate) const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyClientNegotiation {
    #[serde(rename = "cc")]
    client_challenge: String,
    #[serde(rename = "cr")]
    client_response: Hash,
    security_level: SecurityLevel,
}

impl KeyClientNegotiation {
    pub(crate) fn new(client_challenge: &str, client_response: &Hash) -> Self {
        Self {
            client_challenge: client_challenge.to_owned(),
            client_response: client_response.clone(),
            security_level: SecurityLevel::Medium,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyServerResponse {
    #[serde(rename = "sr")]
    server_response: Hash,
    security_level: SecurityLevel,
}

impl KeyServerResponse {
    pub(crate) const fn server_response(&self) -> &Hash {
        &self.server_response
    }

    pub(crate) const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SrpIdentifyToServerStage {
    IdentifyToServer,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SrpIdentifyToServer {
    stage: SrpIdentifyToServerStage,
    #[serde(rename = "I")]
    identifier: Uuid,
    #[serde(rename = "A")]
    public_key: KeyMaterial<64>,
    security_level: SecurityLevel,
}

impl SrpIdentifyToServer {
    pub(crate) fn new(srp: &srp::Protocol<srp::Init>, security_level: SecurityLevel) -> Self {
        Self {
            stage: SrpIdentifyToServerStage::IdentifyToServer,
            identifier: srp.identifier(),
            public_key: srp.my_public_key().clone(),
            security_level,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SrpIdentifyToClientStage {
    IdentifyToClient,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SrpIdentifyToClient {
    stage: SrpIdentifyToClientStage,
    #[serde(rename = "B")]
    public_key: KeyMaterial<84>,
    #[serde(rename = "s")]
    salt: String,
    security_level: SecurityLevel,
}

impl SrpIdentifyToClient {
    pub(crate) const fn public_key(&self) -> &KeyMaterial<84> {
        &self.public_key
    }

    pub(crate) fn salt(&self) -> &str {
        &self.salt
    }

    pub(crate) const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SrpProofToServerStage {
    ProofToServer,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SrpProofToServer {
    stage: SrpProofToServerStage,
    #[serde(rename = "M")]
    evidence: Hash,
    security_level: SecurityLevel,
}

impl SrpProofToServer {
    pub(crate) fn new(srp: &srp::Protocol<srp::Computed>, security_level: SecurityLevel) -> Self {
        Self {
            stage: SrpProofToServerStage::ProofToServer,
            evidence: srp.my_evidence().clone(),
            security_level,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SrpProofToClientStage {
    ProofToClient,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SrpProofToClient {
    stage: SrpProofToClientStage,
    #[serde(rename = "M2")]
    evidence: Hash,
    security_level: SecurityLevel,
}

impl SrpProofToClient {
    pub(crate) const fn evidence(&self) -> &Hash {
        &self.evidence
    }

    pub(crate) const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClientInit {
    features: Vec<ClientFeature>,
    client_type_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_display_description: Option<String>,
    #[serde(flatten)]
    variant: ClientInitVariant,
}

impl ClientInit {
    pub(crate) fn new(variant: ClientInitVariant) -> Self {
        Self {
            features: vec![
                ClientFeature::FeatureVersion1_6,
                ClientFeature::FeatureWarnUserWhenFeatureMissing,
            ],
            client_type_id: metadata::CLIENT_TYPE_ID.to_owned(),
            client_display_name: Some(metadata::CLIENT_DISPLAY_NAME.to_owned()),
            client_display_description: metadata::CLIENT_DISPLAY_DESCRIPTION.to_owned(),
            variant,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub(crate) enum Variant {
    #[serde(rename_all = "camelCase")]
    Error {
        error: Error,
    },
    ClientInit(ClientInit),
    SrpIdentifyToClient {
        features: Vec<ServerFeature>,
        srp: SrpIdentifyToClient,
    },
    SrpProofToServer {
        srp: SrpProofToServer,
    },
    SrpProofToClient {
        srp: SrpProofToClient,
    },
    KeyServerChallenge {
        features: Vec<ServerFeature>,
        key: KeyServerChallenge,
    },
    KeyClientNegotiation {
        key: KeyClientNegotiation,
    },
    KeyServerResponse {
        key: KeyServerResponse,
    },
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct Setup {
    version: u32,
    #[serde(flatten)]
    variant: Variant,
}

impl Setup {
    pub(crate) const fn new(variant: Variant) -> Self {
        Self {
            version: metadata::CLIENT_VERSION,
            variant,
        }
    }

    pub(crate) const fn variant(&self) -> &Variant {
        &self.variant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::mock;
    use serde_test::{assert_tokens, Configure, Token};
    use uuid::uuid;

    #[test]
    fn setup_client_init_key() {
        let msg = Setup::new(Variant::ClientInit(ClientInit::new(
            ClientInitVariant::Key {
                username: "test".to_owned(),
                security_level: SecurityLevel::Medium,
            },
        )));

        assert_tokens(
            &msg,
            &[
                &[
                    Token::Map { len: None },
                    Token::Str("version"),
                    Token::U32(metadata::CLIENT_VERSION),
                    Token::Str("features"),
                    Token::Seq { len: Some(2) },
                    Token::UnitVariant {
                        name: "ClientFeature",
                        variant: "KPRPC_FEATURE_VERSION_1_6",
                    },
                    Token::UnitVariant {
                        name: "ClientFeature",
                        variant: "KPRPC_FEATURE_WARN_USER_WHEN_FEATURE_MISSING",
                    },
                    Token::SeqEnd,
                    Token::Str("clientTypeId"),
                    Token::Str(&metadata::CLIENT_TYPE_ID),
                    Token::Str("clientDisplayName"),
                    Token::Some,
                    Token::Str(&metadata::CLIENT_DISPLAY_NAME),
                ][..],
                metadata::CLIENT_DISPLAY_DESCRIPTION
                    .as_ref()
                    .map(|desc| {
                        vec![
                            Token::Str("clientDisplayDescription"),
                            Token::Some,
                            Token::Str(desc),
                        ]
                    })
                    .unwrap_or_default()
                    .as_slice(),
                &[
                    Token::Str("key"),
                    Token::Struct {
                        name: "key",
                        len: 2,
                    },
                    Token::Str("username"),
                    Token::Str("test"),
                    Token::Str("securityLevel"),
                    Token::I32(2),
                    Token::StructEnd,
                    Token::MapEnd,
                ][..],
            ]
            .concat(),
        );
    }

    #[test]
    fn setup_client_init_srp() {
        static IDENTIFIER: Uuid = uuid!("46640aca-1245-44d2-8ca9-d19750597d6c");
        let srp = srp::ProtocolBuilder::new()
            .with_identifier(IDENTIFIER)
            .with_rng(&mut mock::StepRng::new(0, 1))
            .into_protocol();
        let msg = Setup::new(Variant::ClientInit(ClientInit::new(
            ClientInitVariant::Srp(SrpIdentifyToServer::new(&srp, SecurityLevel::Medium)),
        )));

        assert_tokens(
            &msg.compact(),
            &[
                &[
                    Token::Map { len: None },
                    Token::Str("version"),
                    Token::U32(metadata::CLIENT_VERSION),
                    Token::Str("features"),
                    Token::Seq { len: Some(2) },
                    Token::UnitVariant {
                        name: "ClientFeature",
                        variant: "KPRPC_FEATURE_VERSION_1_6",
                    },
                    Token::UnitVariant {
                        name: "ClientFeature",
                        variant: "KPRPC_FEATURE_WARN_USER_WHEN_FEATURE_MISSING",
                    },
                    Token::SeqEnd,
                    Token::Str("clientTypeId"),
                    Token::Str(&metadata::CLIENT_TYPE_ID),
                    Token::Str("clientDisplayName"),
                    Token::Some,
                    Token::Str(&metadata::CLIENT_DISPLAY_NAME),
                ][..],
                metadata::CLIENT_DISPLAY_DESCRIPTION
                    .as_ref()
                    .map(|desc| {
                        vec![
                            Token::Str("clientDisplayDescription"),
                            Token::Some,
                            Token::Str(desc),
                        ]
                    })
                    .unwrap_or_default()
                    .as_slice(),
                &[
                    Token::Str("srp"),
                    Token::Struct {
                        name: "SrpIdentifyToServer",
                        len: 4,
                    },
                    Token::Str("stage"),
                    Token::UnitVariant { name: "SrpIdentifyToServerStage", variant: "identifyToServer" },
                    Token::Str("I"),
                    Token::Bytes(IDENTIFIER.as_bytes()),
                    Token::Str("A"),
                    Token::Str("C14AEFD8F95D6E76736EC937D99E9A45DCBF456CA7D4CF257BAE54640C90AFC1BC537D2F4719483EEC28231776F226BE933D8E418C28AD31CC52651BB9E10ECD"),
                    Token::Str("securityLevel"),
                    Token::I32(2),
                    Token::StructEnd,
                    Token::MapEnd,
                ][..],
            ].concat(),
        );
    }
}
