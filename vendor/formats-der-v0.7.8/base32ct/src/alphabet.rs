//! Base32 alphabets.

pub(crate) mod rfc4648;

use core::{fmt::Debug, ops::RangeInclusive};

/// Core encoder/decoder functions for a particular Base64 alphabet
pub trait Alphabet: 'static + Copy + Debug + Eq + Send + Sized + Sync {
    /// First character in this Base64 alphabet
    const BASE: u8;

    /// Decoder passes
    const DECODER: &'static [DecodeStep];

    /// Encoder passes
    const ENCODER: &'static [EncodeStep];

    /// Is this encoding padded?
    const PADDED: bool;

    /// Use bitwise operators instead of table-lookups to turn 5-bit integers
    /// into 8-bit integers.
    fn decode_5bits(byte: u8) -> i16 {
        let src = byte as i16;
        let mut ret: i16 = -1;

        for DecodeStep(range, offset) in Self::DECODER {
            // Compute exclusive range from inclusive one
            let start = *range.start() as i16 - 1;
            let end = *range.end() as i16 + 1;
            ret += (((start - src) & (src - end)) >> 8) & (src + *offset);
        }

        ret
    }

    /// Use bitwise operators instead of table-lookups to turn 8-bit integers
    /// into 5-bit integers.
    fn encode_5bits(byte: u8) -> u8 {
        let src = byte as i16;
        let mut diff = src + Self::BASE as i16;

        for &EncodeStep(threshold, offset) in Self::ENCODER {
            diff -= ((threshold as i16 - src) >> 8) & offset;
        }

        diff as u8
    }
}

/// Constant-time decoder step.
#[derive(Debug)]
pub struct DecodeStep(RangeInclusive<u8>, i16);

/// Compute a difference using the given offset on match.
#[derive(Copy, Clone, Debug)]
pub struct EncodeStep(u8, i16);
