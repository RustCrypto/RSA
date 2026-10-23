//! Small fixed-width checks for I2OSP, including zeroization on drop.

use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use crypto_bigint::BoxedUint;

fn i2osp<const INPUT_LEN: usize, const OUTPUT_LEN: usize>() {
    // SAFETY: This is the start of an independent, single-threaded analysis;
    // no allocations are live yet.
    unsafe { crate::allocator::reset() };

    // The generated BINSEC script requires both RNG symbols.
    black_box(PublicRng.next_u32());
    let mut bytes = [0u8; INPUT_LEN];
    PrivateRng.fill_bytes(&mut bytes);

    // Storage precision and both byte lengths are public and fixed. Leading
    // zero bytes in the secret input remain unconstrained.
    let input = black_box(BoxedUint::from_be_slice(&bytes, 64).unwrap());
    let output = crate::pad::i2osp_zeroizing(input, OUTPUT_LEN);
    black_box(output.as_slice());
    drop(output);
}

#[checkct]
pub fn i2osp_zeroizing_equal_width() {
    i2osp::<8, 8>();
}

#[checkct]
pub fn i2osp_zeroizing_left_pad() {
    i2osp::<8, 16>();
}

#[checkct]
pub fn i2osp_zeroizing_truncate_storage() {
    // Seven secret bytes fit in seven output bytes, while the input occupies
    // eight storage bytes on every target. Only a known-zero byte is removed.
    i2osp::<7, 7>();
}
