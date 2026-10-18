//! Special handling for converting the BigUint to u8 vectors

use alloc::vec::Vec;
use crypto_bigint::{BoxedUint, Choice, CtEq};
use zeroize::Zeroizing;

/// Writes the big-endian encoding of `bytes` into `out`.
///
/// The value must fit in `out`: any bytes truncated from the front must be zero.
/// In release builds, the amount of data copied depends only on the slice lengths.
#[inline]
fn be_pad_into(bytes: &[u8], out: &mut [u8]) {
    let excess = bytes.len().saturating_sub(out.len());
    debug_assert!(
        !bytes[..excess]
            .iter()
            .fold(Choice::FALSE, |overflow, byte| overflow | !byte.ct_eq(&0u8))
            .to_bool(),
        "integer exceeds output width"
    );

    out.fill(0);
    let tail = &bytes[excess..];
    let start = out.len() - tail.len();
    out[start..].copy_from_slice(tail);
}

/// Integer-to-Octet-String Primitive (I2OSP) from [RFC8017 §4.1].
///
/// Converts `input` to exactly `padded_len` big-endian bytes, left-padded with zeros.
/// `input` must fit in `padded_len` bytes. This is a caller-established precondition, checked by a
/// debug assertion.
///
/// Use [`i2osp_zeroizing`] when encoding secret values.
///
/// [RFC8017 §4.1]: https://www.rfc-editor.org/rfc/rfc8017.html#section-4.1
#[inline]
pub(crate) fn i2osp(input: BoxedUint, padded_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; padded_len];
    be_pad_into(&input.to_be_bytes(), &mut out);
    out
}

/// Computes [`i2osp`] (Integer-to-Octet-String Primitive) with zeroization of the input and output
/// buffers.
///
/// The input integer, temporary byte buffer, and returned vector are each zeroized on drop.
/// The same input-width precondition as [`i2osp`] applies.
///
/// For RSA decryption, this computes `EM = I2OSP(m, k)`, where `padded_len` is `k`, the public
/// modulus length in octets.
///
/// [draft-irtf-cfrg-rsa-guidance-10 §7.2] requires this conversion to be constant-time with respect
/// to `m`. Serialization and copying in this function depend only on `padded_len` and the input's
/// storage precision. To satisfy that requirement, callers must ensure that both widths are
/// independent of `m`'s value.
///
/// [draft-irtf-cfrg-rsa-guidance-10 §7.2]: https://www.ietf.org/archive/id/draft-irtf-cfrg-rsa-guidance-10.html#section-7.2
#[inline]
pub(crate) fn i2osp_zeroizing(input: BoxedUint, padded_len: usize) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    let bytes = Zeroizing::new(input.to_be_bytes());
    let mut out = Zeroizing::new(vec![0u8; padded_len]);
    be_pad_into(&bytes, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn be_pad() {
        let x = BoxedUint::from(0x0102u64);
        let p = i2osp(x.clone(), 16);
        assert_eq!(&p[..14], &[0u8; 14]);
        assert_eq!(&p[14..], &[1, 2]);

        let p = i2osp_zeroizing(x.clone(), 3);
        assert_eq!(&p[..], &[0, 1, 2]);

        let p = i2osp(x.clone(), 8);
        assert_eq!(&p[..], &[0, 0, 0, 0, 0, 0, 1, 2]);

        let p = i2osp(BoxedUint::zero_with_precision(128), 4);
        assert_eq!(&p[..], &[0u8; 4]);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "integer exceeds output width")]
    fn be_pad_rejects_broken_precondition() {
        i2osp_zeroizing(BoxedUint::from(0x0102u64), 1);
    }
}
