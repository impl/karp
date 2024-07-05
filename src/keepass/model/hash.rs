// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use generic_array::{typenum::U32, GenericArray};
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error;

const HASH_BYTES: usize = 32;

/// A representation of hashed (SHA-256) data commonly used by the KeePassRPC
/// plugin. May or may not also represent secret data.
#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq)]
#[serde(try_from = "String", into = "String")]
pub(in crate::keepass) struct Hash([u8; HASH_BYTES]);

impl From<GenericArray<u8, U32>> for Hash {
    fn from(mut value: GenericArray<u8, U32>) -> Self {
        value.reverse();
        Self(value.into())
    }
}

impl From<&Hash> for BigUint {
    fn from(value: &Hash) -> Self {
        Self::from_bytes_le(&value.0)
    }
}

impl From<Hash> for BigUint {
    fn from(value: Hash) -> Self {
        (&value).into()
    }
}

impl From<&Hash> for BigInt {
    fn from(value: &Hash) -> Self {
        BigUint::from(value).into()
    }
}

impl From<Hash> for BigInt {
    fn from(value: Hash) -> Self {
        (&value).into()
    }
}

impl From<Sha256> for Hash {
    fn from(value: Sha256) -> Self {
        value.finalize().into()
    }
}

impl From<&Hash> for String {
    fn from(value: &Hash) -> Self {
        format!("{:064x}", BigInt::from(value))
    }
}

impl From<Hash> for String {
    fn from(value: Hash) -> Self {
        (&value).into()
    }
}

impl TryFrom<String> for Hash {
    type Error = error::Conversion;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let num = BigUint::from_str_radix(&value, 16)?;
        let mut bytes = num.to_bytes_le();
        if bytes.len() < HASH_BYTES {
            bytes.resize(HASH_BYTES, 0);
        }
        Ok(Self(bytes.try_into().map_err(|rejected: Vec<u8>| {
            error::Conversion::HashLength(HASH_BYTES, rejected.len())
        })?))
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }
}

impl secrecy::CloneableSecret for Hash {}

impl secrecy::SerializableSecret for Hash {}

impl secrecy::Zeroize for Hash {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub(in crate::keepass) struct Secret(secrecy::Secret<Hash>);

impl From<&Secret> for secrecy::Secret<[u8; HASH_BYTES]> {
    fn from(value: &Secret) -> Self {
        let mut bytes = value.0.expose_secret().0;
        bytes.reverse();

        Self::new(bytes)
    }
}

impl From<Secret> for secrecy::Secret<[u8; HASH_BYTES]> {
    fn from(value: Secret) -> Self {
        (&value).into()
    }
}

impl From<&Secret> for secrecy::SecretString {
    fn from(value: &Secret) -> Self {
        Self::new(value.0.expose_secret().into())
    }
}

impl From<Secret> for secrecy::SecretString {
    fn from(value: Secret) -> Self {
        (&value).into()
    }
}

impl From<Sha256> for Secret {
    fn from(value: Sha256) -> Self {
        Self(secrecy::Secret::new(value.into()))
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Result;

    use super::*;

    #[test]
    fn from_zero_padded_string() -> Result<()> {
        let hash = Hash::try_from(
            "00670e90136bc908d24502fc582e4e3069b9d23b91de72efa1266e39ca1ac0e1".to_owned(),
        )?;

        assert_eq!(
            hash.0,
            [
                225, 192, 26, 202, 57, 110, 38, 161, 239, 114, 222, 145, 59, 210, 185, 105, 48, 78,
                46, 88, 252, 2, 69, 210, 8, 201, 107, 19, 144, 14, 103, 0,
            ],
        );
        Ok(())
    }
}
