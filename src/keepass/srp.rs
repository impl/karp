// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use digest::Digest;
use num_bigint::{BigInt, Sign};
use num_traits::Zero;
use once_cell::sync::Lazy;
use rand::{Rng as _, RngCore};
use secrecy::{ExposeSecret, SecretString};
use sha1::Sha1;
use sha2::Sha256;
use uuid::Uuid;

use crate::{error::Result, rng};

use super::{error as keepass_error, model};

static PARAM_N: Lazy<BigInt> = Lazy::new(|| {
    BigInt::from_bytes_be(
        Sign::Plus,
        &[
            212, 199, 248, 162, 179, 44, 17, 184, 251, 169, 88, 30, 196, 186, 79, 27, 4, 33, 86,
            66, 239, 115, 85, 227, 124, 15, 192, 68, 62, 247, 86, 234, 44, 107, 142, 235, 117, 90,
            28, 114, 48, 39, 102, 60, 170, 38, 94, 247, 133, 184, 255, 106, 155, 53, 34, 122, 82,
            216, 102, 51, 219, 223, 202, 67,
        ],
    )
});

static PARAM_GENERATOR: Lazy<BigInt> = Lazy::new(|| BigInt::from(2_u32));

static PARAM_K: Lazy<BigInt> = Lazy::new(|| {
    let (_, n_bytes) = PARAM_N.to_bytes_be();

    let (_, mut generator_bytes) = PARAM_GENERATOR.to_bytes_le();
    generator_bytes.resize(n_bytes.len(), 0);
    generator_bytes.reverse();

    let hash = Sha1::new_with_prefix(n_bytes)
        .chain_update(generator_bytes)
        .finalize();

    BigInt::from_bytes_be(Sign::Plus, hash.as_ref())
});

pub(crate) trait State: private::Sealed {}

pub(crate) struct Init {
    my_private_key: model::key_material::Secret<32>,
    my_public_key: model::key_material::KeyMaterial<64>,
}

impl State for Init {}

pub(crate) struct Computed {
    my_evidence: model::hash::Hash,
    their_evidence: model::hash::Hash,
    session_key: model::key_material::Secret<64>,
}

impl State for Computed {}

pub(crate) struct Authenticated {
    session_key_hash: model::hash::Secret,
}

impl State for Authenticated {}

pub(crate) struct Protocol<S: State> {
    state: S,
    identifier: Uuid,
}

impl<S: State> Protocol<S> {
    pub(crate) const fn identifier(&self) -> Uuid {
        self.identifier
    }
}

impl Protocol<Init> {
    pub(crate) fn new() -> Self {
        ProtocolBuilder::new().into_protocol()
    }

    pub(crate) const fn my_public_key(&self) -> &model::key_material::KeyMaterial<64> {
        &self.state.my_public_key
    }

    pub(crate) fn compute(
        self,
        their_public_key: &model::key_material::KeyMaterial<84>,
        salt: &str,
        password: &str,
    ) -> Protocol<Computed> {
        let my_private_key_num: model::key_material::SecretBigInt =
            self.state.my_private_key.into();
        let my_public_key_str: String = self.state.my_public_key.into();
        let their_public_key_str: String = their_public_key.into();

        let u: BigInt = {
            let hash: model::hash::Hash = Sha256::new_with_prefix(&my_public_key_str)
                .chain_update(&their_public_key_str)
                .into();
            hash.into()
        };

        let x: BigInt = {
            let hash: model::hash::Hash =
                Sha256::new_with_prefix(salt).chain_update(password).into();
            hash.into()
        };

        let session_key: model::key_material::Secret<64> = {
            let base = BigInt::from(their_public_key)
                - (&(*PARAM_K) * PARAM_GENERATOR.modpow(&x, &PARAM_N));
            let exponent = my_private_key_num.expose_secret() + (u * x);

            // LINT: Limited by the size of N.
            #[allow(clippy::unwrap_used)]
            base.modpow(&exponent, &PARAM_N).try_into().unwrap()
        };
        let session_key_str = SecretString::from(&session_key);

        let my_evidence = Sha256::new_with_prefix(&my_public_key_str)
            .chain_update(&their_public_key_str)
            .chain_update(session_key_str.expose_secret())
            .into();

        let their_evidence = Sha256::new_with_prefix(&my_public_key_str)
            .chain_update(String::from(&my_evidence))
            .chain_update(session_key_str.expose_secret())
            .into();

        Protocol {
            state: Computed {
                my_evidence,
                their_evidence,
                session_key,
            },
            identifier: self.identifier,
        }
    }
}

impl Default for Protocol<Init> {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol<Computed> {
    pub(crate) const fn my_evidence(&self) -> &model::hash::Hash {
        &self.state.my_evidence
    }

    pub(crate) fn authenticate(
        self,
        their_evidence: &model::hash::Hash,
    ) -> Result<Protocol<Authenticated>> {
        if &self.state.their_evidence != their_evidence {
            return Err(keepass_error::Srp::ServerProofMismatch.into());
        }

        let session_key_hash =
            Sha256::new_with_prefix(SecretString::from(self.state.session_key).expose_secret())
                .into();

        Ok(Protocol {
            state: Authenticated { session_key_hash },
            identifier: self.identifier,
        })
    }
}

impl Protocol<Authenticated> {
    pub(crate) const fn session_key(&self) -> &model::hash::Secret {
        &self.state.session_key_hash
    }
}

pub(crate) struct ProtocolBuilder<'rng> {
    rng: Option<&'rng mut (dyn RngCore + Send)>,
    identifier: Option<Uuid>,
}

impl<'rng> ProtocolBuilder<'rng> {
    pub(crate) fn new() -> Self {
        Self {
            rng: None,
            identifier: None,
        }
    }

    pub(crate) const fn with_identifier(mut self, identifier: Uuid) -> Self {
        self.identifier = Some(identifier);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_rng(mut self, rng: &'rng mut (dyn RngCore + Send)) -> Self {
        self.rng = Some(rng);
        self
    }

    pub(crate) fn into_protocol(mut self) -> Protocol<Init> {
        rng::map_option(&mut self.rng, |rng| {
            let (my_private_key, my_public_key) = loop {
                let private = model::key_material::Secret::random(rng);
                let public = PARAM_GENERATOR.modpow(
                    model::key_material::SecretBigInt::from(&private).expose_secret(),
                    &PARAM_N,
                );
                if !(&public % &(*PARAM_N)).is_zero() {
                    break (private, public);
                }
            };

            // LINT: Limited by the size of N.
            #[allow(clippy::unwrap_used)]
            let init = Init {
                my_private_key,
                my_public_key: my_public_key.try_into().unwrap(),
            };
            let identifier = self
                .identifier
                .unwrap_or_else(|| uuid::Builder::from_random_bytes(rng.gen()).into_uuid());

            Protocol {
                state: init,
                identifier,
            }
        })
    }
}

mod private {
    pub(crate) trait Sealed {}
    impl Sealed for super::Init {}
    impl Sealed for super::Computed {}
    impl Sealed for super::Authenticated {}
}
