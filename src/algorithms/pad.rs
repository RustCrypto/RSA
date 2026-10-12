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

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
///
/// `input` must fit in `padded_len` bytes.
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; padded_len];
    be_pad_into(&input.to_be_bytes(), &mut out);
    out
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
///
/// `input` must fit in `padded_len` bytes.
///
/// For secret values: every intermediate buffer, including the returned one, is zeroized on drop.
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad(input: BoxedUint, padded_len: usize) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    let bytes = Zeroizing::new(input.to_be_bytes());
    let mut out = Zeroizing::new(vec![0u8; padded_len]);
    be_pad_into(&bytes, &mut out);
    out
}

/// Encode a private RSA representative using the modulus width in octets.
///
/// The caller has established that `input` fits in `k` octets. Offsets depend only on the public
/// storage and modulus widths, not on `input`'s value.
///
/// From draft-irtf-cfrg-rsa-guidance-10 §7.2:
/// > I2OSP MUST be constant-time with respect of m.
#[inline]
pub(crate) fn i2osp_modulus_width(input: BoxedUint, k: usize) -> Zeroizing<Vec<u8>> {
    debug_assert!(k >= 11);

    let input = Zeroizing::new(input);
    let bytes = Zeroizing::new(input.to_be_bytes());
    let copy_len = bytes.len().min(k);
    let mut out = Zeroizing::new(vec![0u8; k]);
    out[k - copy_len..].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn be_pad() {
        let x = BoxedUint::from(0x0102u64);
        let p = uint_to_be_pad(x.clone(), 16);
        assert_eq!(&p[..14], &[0u8; 14]);
        assert_eq!(&p[14..], &[1, 2]);

        let p = uint_to_zeroizing_be_pad(x.clone(), 3);
        assert_eq!(&p[..], &[0, 1, 2]);

        let p = uint_to_be_pad(x.clone(), 8);
        assert_eq!(&p[..], &[0, 0, 0, 0, 0, 0, 1, 2]);

        let p = uint_to_be_pad(BoxedUint::zero_with_precision(128), 4);
        assert_eq!(&p[..], &[0u8; 4]);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "integer exceeds output width")]
    fn be_pad_rejects_broken_precondition() {
        uint_to_zeroizing_be_pad(BoxedUint::from(0x0102u64), 1);
    }

    #[test]
    fn i2osp_modulus_width_uses_octet_width_not_storage_precision() {
        // From draft-irtf-cfrg-rsa-guidance-10 §7.2:
        // > EM = I2OSP (m, k).
        //
        // A 2049-bit modulus has `k = 257`, even when BoxedUint stores more bytes.
        let k = 257;
        let mut expected = vec![0u8; k];
        expected[k - 2..].copy_from_slice(&[0x12, 0x34]);

        for bits_precision in [2048, 2049] {
            let m = BoxedUint::from_be_slice(&[0x12, 0x34], bits_precision).unwrap();
            let em = i2osp_modulus_width(m, k);
            assert_eq!(em.as_slice(), expected.as_slice());
        }

        // The most significant octet of a 2049-bit value must also be retained.
        expected[0] = 1;
        let m = BoxedUint::from_be_slice(&expected, 2049).unwrap();
        let em = i2osp_modulus_width(m, k);
        assert_eq!(em.as_slice(), expected.as_slice());
    }
}
