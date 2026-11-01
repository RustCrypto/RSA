//! Verify the actual §7.2 decoding and selection helpers up to the output boundary.
//!
//! EM, AM, CL, and the intermediate lengths are secret. We deliberately do not slice at the final
//! returned length: §7.2 step 5 permits exposing that length, but BINSEC has no declassification
//! annotation here. The fixed-size selection itself must have no secret-dependent control flow or
//! memory accesses.

use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;

#[checkct]
pub fn pkcs1v15_al() {
    black_box(PublicRng.next_u32());
    let mut cl = [0u8; 256];
    PrivateRng.fill_bytes(&mut cl);
    // `k=32` gives a non-power-of-two bound and exercises candidate rejection.
    black_box(crate::selection::select_al(&cl, 21));
}

#[checkct]
pub fn pkcs1v15_decode_and_select() {
    black_box(PublicRng.next_u32());
    let mut em = [0u8; 32];
    let mut am = [0u8; 32];
    PrivateRng.fill_bytes(&mut em);
    PrivateRng.fill_bytes(&mut am);
    // An independent secret AL covering every valid length `(0..=21)` for `k=32`.
    // Masking also admits `22..=31`, still within the selector's buffer bound.
    let al = (PrivateRng.next_u32() & 31) as u16;
    let (check, l) = crate::selection::eme_pkcs1v15_decode(&em, em.len());
    black_box(crate::selection::select_message(&mut em, &am, al, l, check));
    black_box(em);
}
