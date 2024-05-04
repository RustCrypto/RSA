//! RFC4648 Base32 alphabet.

use super::{Alphabet, DecodeStep, EncodeStep};

/// RFC4648 lower case Base32 encoding with `=` padding.
///
/// ```text
/// [a-z]      [2-7]
/// 0x61-0x7a, 0x32-0x37
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base32;

impl Alphabet for Base32 {
    const BASE: u8 = b'a';
    const DECODER: &'static [DecodeStep] = DECODE_LOWER;
    const ENCODER: &'static [EncodeStep] = ENCODE_LOWER;
    const PADDED: bool = true;
}

/// RFC4648 lower case Base32 encoding *without* padding.
///
/// ```text
/// [a-z]      [2-7]
/// 0x61-0x7a, 0x32-0x37
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base32Unpadded;

impl Alphabet for Base32Unpadded {
    const BASE: u8 = b'a';
    const DECODER: &'static [DecodeStep] = DECODE_LOWER;
    const ENCODER: &'static [EncodeStep] = ENCODE_LOWER;
    const PADDED: bool = false;
}

/// Lower-case Base32 decoder.
const DECODE_LOWER: &[DecodeStep] = &[DecodeStep(b'a'..=b'z', -96), DecodeStep(b'2'..=b'7', -23)];

/// Standard Base64 encoder
const ENCODE_LOWER: &[EncodeStep] = &[EncodeStep(25, 73)];

/// RFC4648 upper case Base32 encoding with `=` padding.
///
/// ```text
/// [A-Z]      [2-7]
/// 0x41-0x5a, 0x32-0x37
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base32Upper;

impl Alphabet for Base32Upper {
    const BASE: u8 = b'A';
    const DECODER: &'static [DecodeStep] =
        &[DecodeStep(b'A'..=b'Z', -64), DecodeStep(b'2'..=b'7', -23)];
    const ENCODER: &'static [EncodeStep] = &[EncodeStep(25, 41)];
    const PADDED: bool = true;
}
