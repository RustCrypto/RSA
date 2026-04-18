//! Special handling for converting the BigUint to u8 vectors

use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// Returns a new vector of the given length, with 0s left padded.
#[inline]
fn left_pad(input: &[u8], padded_len: usize) -> Result<Vec<u8>> {
    if input.len() > padded_len {
        return Err(Error::InvalidPadLen);
    }

    let mut out = vec![0u8; padded_len];
    out[padded_len - input.len()..].copy_from_slice(input);
    Ok(out)
}

/// Converts input to an exact modulus-width big-endian encoding.
///
/// This normalizes only by the public storage width of the integer: if the
/// backing representation is wider than `k`, only the public over-width prefix
/// is dropped. The returned buffer is always exactly `k` octets long.
#[inline]
pub(crate) fn i2osp_modulus_width(input: &BoxedUint, k: usize) -> Zeroizing<Vec<u8>> {
    let bytes = Zeroizing::new(input.to_be_bytes());
    let copy_len = bytes.len().min(k);
    let src_start = bytes.len().saturating_sub(k);

    debug_assert!(bytes[..src_start].iter().all(|&byte| byte == 0));

    let mut out = Zeroizing::new(vec![0u8; k]);
    out[k - copy_len..].copy_from_slice(&bytes[src_start..]);
    out
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// In some cases BoxedUint might already have leading zeroes, this function removes them
/// before padding again.
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let leading_zeros = input.leading_zeros() as usize / 8;
    left_pad(&input.to_be_bytes()[leading_zeros..], padded_len)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// In some cases BoxedUint might already have leading zeroes, this function removes them
/// before padding again.
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let leading_zeros = input.leading_zeros() as usize / 8;

    let m = Zeroizing::new(input);
    let m = Zeroizing::new(m.to_be_bytes());

    left_pad(&m[leading_zeros..], padded_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_left_pad() {
        const INPUT_LEN: usize = 3;
        let input = vec![0u8; INPUT_LEN];

        // input len < padded len
        let padded = left_pad(&input, INPUT_LEN + 1).unwrap();
        assert_eq!(padded.len(), INPUT_LEN + 1);

        // input len == padded len
        let padded = left_pad(&input, INPUT_LEN).unwrap();
        assert_eq!(padded.len(), INPUT_LEN);

        // input len > padded len
        let padded = left_pad(&input, INPUT_LEN - 1);
        assert!(padded.is_err());
    }

    #[test]
    fn test_i2osp_modulus_width_exact_width() {
        let input = BoxedUint::from_be_slice(&[0x12, 0x34], 128).unwrap();
        let padded = i2osp_modulus_width(&input, 2);

        assert_eq!(padded.as_slice(), &[0x12, 0x34]);
    }

    #[test]
    fn test_i2osp_modulus_width_left_pads_to_modulus_width() {
        let input = BoxedUint::from_be_slice(&[0x12, 0x34], 128).unwrap();
        let padded = i2osp_modulus_width(&input, 4);

        assert_eq!(padded.as_slice(), &[0x00, 0x00, 0x12, 0x34]);
    }

    #[test]
    fn test_i2osp_modulus_width_odd_modulus_width() {
        let input = BoxedUint::from_be_slice(&[0x01], 2049).unwrap();
        let padded = i2osp_modulus_width(&input, 257);

        assert_eq!(padded.len(), 257);
        assert_eq!(padded[256], 0x01);
    }
}
