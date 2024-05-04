//! Base32 encoding trait.

use crate::{alphabet::Alphabet, Error, Result};
use core::str;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Core encoder/decoder functions for a particular Base32 alphabet
pub trait Encoding: Alphabet {
    /// Decode a Base32-encoded string into the provided output buffer,
    /// returning a slice containing the decoded data.
    fn decode(src: impl AsRef<[u8]>, dst: &mut [u8]) -> Result<&[u8]>;

    /// Decode a Base32 string into a byte vector.
    #[cfg(feature = "alloc")]
    fn decode_vec(input: &str) -> Result<Vec<u8>>;

    /// Encode the input byte slice as Base32.
    ///
    /// Writes the result into the provided destination slice, returning an
    /// ASCII-encoded Base32 string value.
    fn encode<'a>(src: &[u8], dst: &'a mut [u8]) -> Result<&'a str>;

    /// Encode input byte slice into a [`String`] containing Base32.
    #[cfg(feature = "alloc")]
    fn encode_string(input: &[u8]) -> String;

    /// Get the length of Base32 produced by encoding the given bytes.
    fn encoded_len(bytes: &[u8]) -> usize;
}

impl<T: Alphabet> Encoding for T {
    fn decode(src: impl AsRef<[u8]>, dst: &mut [u8]) -> Result<&[u8]> {
        let src = if Self::PADDED {
            remove_padding(src.as_ref())?
        } else {
            src.as_ref()
        };

        if src.is_empty() {
            return Ok(&[]);
        }

        let dlen = decoded_len(src.len());
        let dst = dst.get_mut(..dlen).ok_or(Error::InvalidLength)?;

        let mut src_chunks = src.chunks_exact(8);
        let mut dst_chunks = dst.chunks_exact_mut(5);
        let mut err = 0u8;

        for (s, d) in (&mut src_chunks).zip(&mut dst_chunks) {
            let c0 = Self::decode_5bits(s[0]);
            let c1 = Self::decode_5bits(s[1]);
            let c2 = Self::decode_5bits(s[2]);
            let c3 = Self::decode_5bits(s[3]);
            let c4 = Self::decode_5bits(s[4]);
            let c5 = Self::decode_5bits(s[5]);
            let c6 = Self::decode_5bits(s[6]);
            let c7 = Self::decode_5bits(s[7]);

            d[0] = (((c0 << 3) | (c1 >> 2)) & 0xff) as u8;
            d[1] = (((c1 << 6) | (c2 << 1) | (c3 >> 4)) & 0xff) as u8;
            d[2] = (((c3 << 4) | (c4 >> 1)) & 0xff) as u8;
            d[3] = (((c4 << 7) | (c5 << 2) | (c6 >> 3)) & 0xff) as u8;
            d[4] = (((c6 << 5) | (c7)) & 0xff) as u8;

            err |= ((c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7) >> 8) as u8;
        }

        // Handle last chunk if it's non-empty
        let src_rem = src_chunks.remainder();
        let dst_rem = dst_chunks.into_remainder();
        let mut c = [0i16; 7];

        if !src_rem.is_empty() {
            c[0] = Self::decode_5bits(src_rem[0]);
        }

        if src_rem.len() >= 2 {
            c[1] = Self::decode_5bits(src_rem[1]);
        };

        if src_rem.len() >= 3 {
            c[2] = Self::decode_5bits(src_rem[2]);
        }

        if src_rem.len() >= 4 {
            c[3] = Self::decode_5bits(src_rem[3]);
        }

        if src_rem.len() >= 5 {
            c[4] = Self::decode_5bits(src_rem[4]);
        }

        if src_rem.len() >= 6 {
            c[5] = Self::decode_5bits(src_rem[5]);
        }

        if src_rem.len() >= 7 {
            c[6] = Self::decode_5bits(src_rem[6]);
        };

        if !src_rem.is_empty() {
            dst_rem[0] = (((c[0] << 3) | (c[1] >> 2)) & 0xff) as u8;
        }

        if src_rem.len() >= 3 {
            dst_rem[1] = (((c[1] << 6) | (c[2] << 1) | (c[3] >> 4)) & 0xff) as u8;
        }

        if src_rem.len() >= 5 {
            dst_rem[2] = (((c[3] << 4) | (c[4] >> 1)) & 0xff) as u8;
        }

        if src_rem.len() >= 6 {
            dst_rem[3] = (((c[4] << 7) | (c[5] << 2) | (c[6] >> 3)) & 0xff) as u8;
        }

        err |= ((c[0] | c[1] | c[2] | c[3] | c[4] | c[5] | c[6]) >> 8) as u8;

        if err == 0 {
            Ok(dst)
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    #[cfg(feature = "alloc")]
    fn decode_vec(input: &str) -> Result<Vec<u8>> {
        let mut output = vec![0u8; decoded_len(input.len())];
        let len = Self::decode(input, &mut output)?.len();

        if len <= output.len() {
            output.truncate(len);
            Ok(output)
        } else {
            Err(Error::InvalidLength)
        }
    }

    fn encode<'a>(src: &[u8], dst: &'a mut [u8]) -> Result<&'a str> {
        let elen = Self::encoded_len(src);
        let dst = dst.get_mut(..elen).ok_or(Error::InvalidLength)?;

        let mut src_chunks = src.chunks_exact(5);
        let mut dst_chunks = dst.chunks_exact_mut(8);

        for (s, d) in (&mut src_chunks).zip(&mut dst_chunks) {
            d[0] = Self::encode_5bits((s[0] >> 3) & 31);
            d[1] = Self::encode_5bits(((s[0] << 2) | (s[1] >> 6)) & 31);
            d[2] = Self::encode_5bits((s[1] >> 1) & 31);
            d[3] = Self::encode_5bits(((s[1] << 4) | (s[2] >> 4)) & 31);
            d[4] = Self::encode_5bits(((s[2] << 1) | (s[3] >> 7)) & 31);
            d[5] = Self::encode_5bits((s[3] >> 2) & 31);
            d[6] = Self::encode_5bits(((s[3] << 3) | (s[4] >> 5)) & 31);
            d[7] = Self::encode_5bits(s[4] & 31);
        }

        // The last chunk, which may have padding
        let src_rem = src_chunks.remainder();
        let dst_rem = match dst_chunks.next() {
            Some(d) => d,
            None => dst_chunks.into_remainder(),
        };

        if Self::PADDED {
            for byte in dst_rem.iter_mut() {
                *byte = b'=';
            }
        }

        let mut b = [0u8; 4];
        b[..src_rem.len()].copy_from_slice(src_rem);

        if !src_rem.is_empty() {
            dst_rem[0] = Self::encode_5bits((b[0] >> 3) & 31);
            dst_rem[1] = Self::encode_5bits(((b[0] << 2) | (b[1] >> 6)) & 31);
        }

        if src_rem.len() >= 2 {
            dst_rem[2] = Self::encode_5bits((b[1] >> 1) & 31);
            dst_rem[3] = Self::encode_5bits(((b[1] << 4) | (b[2] >> 4)) & 31);
        }

        if src_rem.len() >= 3 {
            dst_rem[4] = Self::encode_5bits(((b[2] << 1) | (b[3] >> 7)) & 31);
        }

        if src_rem.len() == 4 {
            dst_rem[5] = Self::encode_5bits((b[3] >> 2) & 31);
            dst_rem[6] = Self::encode_5bits((b[3] << 3) & 31);
        }

        debug_assert!(src_rem.len() <= 4);
        debug_assert!(str::from_utf8(dst).is_ok());

        Ok(
            // SAFETY: `dst` is fully written and contains only valid one-byte UTF-8 chars
            #[allow(unsafe_code)]
            unsafe {
                str::from_utf8_unchecked(dst)
            },
        )
    }

    #[cfg(feature = "alloc")]
    fn encode_string(input: &[u8]) -> String {
        let elen = Self::encoded_len(input);
        let mut dst = vec![0u8; elen];
        let res = Self::encode(input, &mut dst).expect("encoding error");

        debug_assert_eq!(elen, res.len());
        debug_assert!(str::from_utf8(&dst).is_ok());

        // SAFETY: `dst` is fully written and contains only valid one-byte UTF-8 chars
        #[allow(unsafe_code)]
        unsafe {
            String::from_utf8_unchecked(dst)
        }
    }

    fn encoded_len(bytes: &[u8]) -> usize {
        if bytes.is_empty() {
            0
        } else if Self::PADDED {
            ((bytes.len() - 1) / 5 + 1) * 8
        } else {
            (bytes.len() * 8) / 5 + 1
        }
    }
}

/// Get the length of the output from decoding the provided *unpadded*
/// Base32-encoded input.
///
/// Note that this function does not fully validate the Base32 is well-formed
/// and may return incorrect results for malformed Base32.
// TODO(tarcieri): checked/overflow-proof arithmetic
#[inline(always)]
fn decoded_len(input_len: usize) -> usize {
    (input_len * 5) / 8
}

/// Remove padding from the provided input.
fn remove_padding(mut input: &[u8]) -> Result<&[u8]> {
    // TODO(tarcieri): properly validate padding
    if input.len() % 8 != 0 {
        return Err(Error::InvalidEncoding);
    }

    for _ in 0..6 {
        match input.split_last() {
            Some((b'=', rest)) => input = rest,
            _ => break,
        }
    }

    Ok(input)
}
