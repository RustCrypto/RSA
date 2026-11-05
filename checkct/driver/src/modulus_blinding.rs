//! CRT modulus blinding with secret primes and random factors.

use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use crypto_bigint::{BoxedUint, Odd, U64};

#[checkct]
pub fn blind_modulus_64() {
    // SAFETY: This independent, single-threaded analysis has no live allocations.
    unsafe { crate::allocator::reset() };
    black_box(PublicRng.next_u32());

    let prime = Odd::new(BoxedUint::from(secret_modulus())).unwrap();
    let blinded = crate::blinding::blind_modulus(&mut PrivateRng, &prime).unwrap();
    black_box(blinded.as_limbs());
    drop(blinded);
}

fn secret_modulus() -> U64 {
    let mut bytes = [0u8; 8];
    PrivateRng.fill_bytes(&mut bytes);
    bytes[0] |= 1;
    U64::from_le_slice(&bytes)
}
