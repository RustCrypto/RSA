//! Special handling for converting the BigUint to u8 vectors

use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Error, Result};

/// Writes the big-endian encoding of `bytes` into a buffer of exactly `padded_len` bytes
///
/// Constant-time with respect to the *value*: the only branches depend on the public lengths
/// The previous implementation sliced at `leading_zeros() / 8`, so the amount of data copied (and
/// whether an error was returned) depended on how many leading zero bytes the secret plaintext
/// had, which is exactly the signal the Marvin attack measures
#[inline]
fn be_pad_into(bytes: &[u8], out: &mut [u8]) -> Result<()> {
    let padded_len = out.len();
    if bytes.len() >= padded_len {
        let (hi, lo) = bytes.split_at(bytes.len() - padded_len);
        let overflow = hi.iter().fold(0u8, |acc, b| acc | b);
        out.copy_from_slice(lo);
        if core::hint::black_box(overflow) != 0 {
            out.zeroize();
            return Err(Error::InvalidPadLen);
        }
    } else {
        let (zero, tail) = out.split_at_mut(padded_len - bytes.len());
        zero.fill(0);
        tail.copy_from_slice(bytes);
    }
    Ok(())
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; padded_len];
    be_pad_into(&input.to_be_bytes(), &mut out)?;
    Ok(out)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
///
/// For secret values: every intermediate buffer, including the returned one, is zeroized on drop.
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad(
    input: BoxedUint,
    padded_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let input = Zeroizing::new(input);
    let bytes = Zeroizing::new(input.to_be_bytes());
    let mut out = Zeroizing::new(vec![0u8; padded_len]);
    be_pad_into(&bytes, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn be_pad() {
        let x = BoxedUint::from(0x0102u64);
        let p = uint_to_be_pad(x.clone(), 16).unwrap();
        assert_eq!(&p[..14], &[0u8; 14]);
        assert_eq!(&p[14..], &[1, 2]);

        let p = uint_to_zeroizing_be_pad(x.clone(), 3).unwrap();
        assert_eq!(&p[..], &[0, 1, 2]);

        let p = uint_to_be_pad(x.clone(), 8).unwrap();
        assert_eq!(&p[..], &[0, 0, 0, 0, 0, 0, 1, 2]);

        assert!(uint_to_be_pad(x.clone(), 1).is_err());
        assert!(uint_to_zeroizing_be_pad(x, 1).is_err());

        let p = uint_to_be_pad(BoxedUint::zero_with_precision(128), 4).unwrap();
        assert_eq!(&p[..], &[0u8; 4]);
    }
}
