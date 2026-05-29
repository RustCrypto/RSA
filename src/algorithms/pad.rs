//! Special handling for converting the BigUint to u8 vectors

use alloc::vec::Vec;
use crypto_bigint::{ctutils::CtGt, BoxedUint};
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// Returns a new vector of the given length, with 0s left padded.
#[inline]
fn left_pad(input: &[u8], padded_len: usize) -> Vec<u8> {
    let mut out = vec![0_u8; padded_len];
    for (output_byte, data_byte) in out
        .iter_mut()
        .rev()
        .zip(input.iter().rev().chain(core::iter::repeat(&0_u8)))
    {
        *output_byte |= *data_byte;
    }
    out
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// In some cases BoxedUint might already have leading zeroes, this function removes them
/// before padding again.
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let leading_zeros = input.leading_zeros() as usize >> 3;
    let input_be_bytes = input.to_be_bytes();
    if ((input_be_bytes.len() - leading_zeros) as u64)
        .ct_gt(&(padded_len as u64))
        .into()
    {
        return Err(Error::InvalidPadLen);
    }
    Ok(left_pad(&input_be_bytes, padded_len))
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// In some cases BoxedUint might already have leading zeroes, this function removes them
/// before padding again.
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let leading_zero_bytes = input.leading_zeros() as usize >> 3;
    let input = Zeroizing::new(input);
    let input_be_bytes = Zeroizing::new(input.to_be_bytes());
    if ((input_be_bytes.len() - leading_zero_bytes) as u64)
        .ct_gt(&(padded_len as u64))
        .into()
    {
        return Err(Error::InvalidPadLen);
    }
    Ok(left_pad(&input_be_bytes, padded_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_left_pad() {
        let input = vec![1u8, 2, 3];

        // input len < padded len: left padded with leading zeros
        let padded = left_pad(&input, input.len() + 1);
        assert_eq!(padded, vec![0, 1, 2, 3]);

        // input len == padded len: returned unchanged
        let padded = left_pad(&input, input.len());
        assert_eq!(padded, vec![1, 2, 3]);

        // input len > padded len: truncated, keeping the low-order bytes
        let padded = left_pad(&input, input.len() - 1);
        assert_eq!(padded, vec![2, 3]);
    }

    #[test]
    fn test_uint_to_be_pad() {
        let input = BoxedUint::from(0x1234u32);

        // padded_len larger than the value: left padded with zeros
        let padded = uint_to_be_pad(input.clone(), 4).unwrap();
        assert_eq!(padded, vec![0, 0, 0x12, 0x34]);

        // padded_len matches the value's byte length
        let padded = uint_to_be_pad(input.clone(), 2).unwrap();
        assert_eq!(padded, vec![0x12, 0x34]);

        // padded_len smaller than the value's byte length: error
        assert_eq!(uint_to_be_pad(input, 1), Err(Error::InvalidPadLen));
    }

    #[test]
    fn test_uint_to_zeroizing_be_pad() {
        let input = BoxedUint::from(0x1234u32);

        // padded_len larger than the value: left padded with zeros
        let padded = uint_to_zeroizing_be_pad(input.clone(), 4).unwrap();
        assert_eq!(padded, vec![0, 0, 0x12, 0x34]);

        // padded_len matches the value's byte length
        let padded = uint_to_zeroizing_be_pad(input.clone(), 2).unwrap();
        assert_eq!(padded, vec![0x12, 0x34]);

        // padded_len smaller than the value's byte length: error
        assert_eq!(
            uint_to_zeroizing_be_pad(input, 1),
            Err(Error::InvalidPadLen)
        );
    }
}
