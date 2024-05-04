//! Test vectors.

#![cfg(feature = "alloc")]

use base32ct::{Base32, Base32Unpadded, Base32Upper, Encoding, Error};

#[derive(Debug)]
struct TestVector {
    decoded: &'static [u8],
    encoded: &'static str,
}

const LOWER_PADDED_VECTORS: &[TestVector] = &[
    TestVector {
        decoded: &[0],
        encoded: "aa======",
    },
    TestVector {
        decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
        encoded: "aebagbijcequdai=",
    },
    TestVector {
        decoded: &[32, 7],
        encoded: "eadq====",
    },
];

const LOWER_UNPADDED_VECTORS: &[TestVector] = &[
    TestVector {
        decoded: &[0],
        encoded: "aa",
    },
    TestVector {
        decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
        encoded: "aebagbijcequdai",
    },
    TestVector {
        decoded: &[32, 7],
        encoded: "eadq",
    },
];

const UPPER_PADDED_VECTORS: &[TestVector] = &[
    TestVector {
        decoded: &[0],
        encoded: "AA======",
    },
    TestVector {
        decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
        encoded: "AEBAGBIJCEQUDAI=",
    },
    TestVector {
        decoded: &[32, 7],
        encoded: "EADQ====",
    },
];

#[test]
fn decode_valid_base32() {
    for vector in LOWER_PADDED_VECTORS {
        assert_eq!(&Base32::decode_vec(vector.encoded).unwrap(), vector.decoded);
    }

    for vector in LOWER_UNPADDED_VECTORS {
        assert_eq!(
            &Base32Unpadded::decode_vec(vector.encoded).unwrap(),
            vector.decoded
        );
    }

    for vector in UPPER_PADDED_VECTORS {
        assert_eq!(
            &Base32Upper::decode_vec(vector.encoded).unwrap(),
            vector.decoded
        );
    }
}

#[test]
fn decode_padding_error() {
    let truncated =
        &LOWER_PADDED_VECTORS[0].encoded[..(&LOWER_PADDED_VECTORS[0].encoded.len() - 1)];
    assert_eq!(Base32::decode_vec(truncated), Err(Error::InvalidEncoding));
}

#[test]
fn decode_range_error() {
    assert_eq!(
        Base32::decode_vec(core::str::from_utf8(&[0, 0, 0]).unwrap()),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn encode_base32() {
    for vector in LOWER_PADDED_VECTORS {
        assert_eq!(&Base32::encode_string(vector.decoded), vector.encoded);
    }

    for vector in LOWER_UNPADDED_VECTORS {
        assert_eq!(
            &Base32Unpadded::encode_string(vector.decoded),
            vector.encoded
        );
    }

    for vector in UPPER_PADDED_VECTORS {
        assert_eq!(&Base32Upper::encode_string(vector.decoded), vector.encoded);
    }
}
