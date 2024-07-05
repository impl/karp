// SPDX-FileCopyrightText: 2022-2024 Noah Fontes
//
// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;

use rand::{thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

thread_local! {
    // LINT: We need a working random number generator for the program to
    // function.
    #[allow(clippy::expect_used)]
    static RNG: RefCell<ChaCha20Rng> = RefCell::new(ChaCha20Rng::from_rng(thread_rng()).expect("random number generator failed to initialize"));
}

pub(crate) fn map<F, R>(mut f: F) -> R
where
    F: FnMut(&mut ChaCha20Rng) -> R,
{
    RNG.with(|rng| f(&mut rng.borrow_mut()))
}

pub(crate) fn map_option<F, R>(rng: &mut Option<&mut (dyn RngCore + Send)>, mut f: F) -> R
where
    F: FnMut(&mut dyn RngCore) -> R,
{
    match rng.as_deref_mut() {
        Some(chosen) => f(chosen),
        None => map(|rng| f(rng)),
    }
}
