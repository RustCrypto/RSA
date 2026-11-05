//! Exponent blinding arithmetic, including secret factors and zeroization on drop.

use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use crypto_bigint::{BoxedUint, Odd};

#[checkct]
pub fn blind_exponent_64() {
    // SAFETY: This independent, single-threaded analysis has no live allocations.
    unsafe { crate::allocator::reset() };
    black_box(PublicRng.next_u32());

    // Overapproximate valid inputs: no constraints on the exponent or totient's value.
    let exponent = secret_64();
    let totient = secret_64();
    let blinded = crate::blinding::blind_exponent(&mut PrivateRng, &exponent, &totient).unwrap();
    black_box(blinded.as_limbs());
    drop(blinded);
}

#[checkct]
pub fn exponent_blinding_totient_128() {
    // SAFETY: This independent, single-threaded analysis has no live allocations.
    unsafe { crate::allocator::reset() };
    black_box(PublicRng.next_u32());

    let primes = [secret_prime(), secret_prime()];
    let totient = crate::blinding::totient(&primes, 128).unwrap();
    black_box(totient.as_limbs());
    drop(totient);
}

fn secret_64() -> BoxedUint {
    let mut bytes = [0u8; 8];
    PrivateRng.fill_bytes(&mut bytes);
    BoxedUint::from_le_slice(&bytes, 64).unwrap()
}

fn secret_prime() -> Odd<BoxedUint> {
    let mut bytes = [0u8; 8];
    PrivateRng.fill_bytes(&mut bytes);
    bytes[0] |= 1;
    Odd::new(BoxedUint::from_le_slice(&bytes, 64).unwrap()).unwrap()
}
