// SPDX-FileCopyrightText: 2022 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use rand::{Rng, RngCore};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::error;

/// Integer-derived key data commonly used by the KeePassRPC plugin, stored as a
/// byte array in little-endian order (so we don't have to worry about
/// unnecessary zeroes) and represented as an uppercase hex-encoded string.
#[derive(Debug, Deserialize, Serialize, Clone, Eq)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct KeyMaterial<const BYTES: usize>([u8; BYTES]);

impl<const BYTES: usize> From<&KeyMaterial<BYTES>> for BigInt {
    fn from(value: &KeyMaterial<BYTES>) -> Self {
        BigUint::from_bytes_le(&value.0).into()
    }
}

impl<const BYTES: usize> From<KeyMaterial<BYTES>> for BigInt {
    fn from(value: KeyMaterial<BYTES>) -> Self {
        (&value).into()
    }
}

impl<const BYTES: usize> TryFrom<BigUint> for KeyMaterial<BYTES> {
    type Error = error::Conversion;

    fn try_from(value: BigUint) -> Result<Self, Self::Error> {
        let mut bytes = value.to_bytes_le();
        if bytes.len() < BYTES {
            bytes.resize(BYTES, 0);
        }
        Ok(Self(bytes.try_into().map_err(|rejected: Vec<u8>| {
            error::Conversion::KeyMaterialLength(BYTES, rejected.len())
        })?))
    }
}

impl<const BYTES: usize> TryFrom<BigInt> for KeyMaterial<BYTES> {
    type Error = error::Conversion;

    fn try_from(value: BigInt) -> Result<Self, Self::Error> {
        let num: BigUint = value.try_into()?;
        num.try_into()
    }
}

impl<const BYTES: usize> From<&KeyMaterial<BYTES>> for String {
    fn from(value: &KeyMaterial<BYTES>) -> Self {
        let mut s = BigInt::from(value).to_str_radix(16);
        s.make_ascii_uppercase();
        s
    }
}

impl<const BYTES: usize> From<KeyMaterial<BYTES>> for String {
    fn from(value: KeyMaterial<BYTES>) -> Self {
        (&value).into()
    }
}

impl<const BYTES: usize> TryFrom<String> for KeyMaterial<BYTES> {
    type Error = error::Conversion;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let num: BigInt = BigUint::from_str_radix(&value, 16)?.into();
        num.try_into()
    }
}

impl<const BYTES: usize> PartialEq for KeyMaterial<BYTES> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }
}

impl<const BYTES: usize> secrecy::Zeroize for KeyMaterial<BYTES> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

struct ZeroizableBigInt(BigInt);

impl secrecy::Zeroize for ZeroizableBigInt {
    fn zeroize(&mut self) {
        for bit in 0..=self.0.bits() {
            self.0.set_bit(bit, false);
        }
    }
}

pub(crate) struct SecretBigInt(secrecy::Secret<ZeroizableBigInt>);

impl ExposeSecret<BigInt> for SecretBigInt {
    fn expose_secret(&self) -> &BigInt {
        &self.0.expose_secret().0
    }
}

pub(crate) struct Secret<const BYTES: usize>(secrecy::Secret<KeyMaterial<BYTES>>);

impl<const BYTES: usize> Secret<BYTES>
where
    [u8; BYTES]: rand::Fill,
{
    pub(crate) fn random<T: RngCore + ?Sized>(rng: &mut T) -> Self {
        let mut data = [0; BYTES];
        rng.fill(&mut data);
        Self(secrecy::Secret::new(KeyMaterial(data)))
    }
}

impl<const BYTES: usize> From<&Secret<BYTES>> for SecretBigInt {
    fn from(value: &Secret<BYTES>) -> Self {
        Self(secrecy::Secret::new(ZeroizableBigInt(
            value.0.expose_secret().into(),
        )))
    }
}

impl<const BYTES: usize> From<Secret<BYTES>> for SecretBigInt {
    fn from(value: Secret<BYTES>) -> Self {
        (&value).into()
    }
}

impl<const BYTES: usize> From<&Secret<BYTES>> for secrecy::SecretString {
    fn from(value: &Secret<BYTES>) -> Self {
        Self::new(value.0.expose_secret().into())
    }
}

impl<const BYTES: usize> From<Secret<BYTES>> for secrecy::SecretString {
    fn from(value: Secret<BYTES>) -> Self {
        (&value).into()
    }
}

impl<const BYTES: usize> TryFrom<BigInt> for Secret<BYTES> {
    type Error = error::Conversion;

    fn try_from(value: BigInt) -> Result<Self, Self::Error> {
        Ok(Self(secrecy::Secret::new(value.try_into()?)))
    }
}
