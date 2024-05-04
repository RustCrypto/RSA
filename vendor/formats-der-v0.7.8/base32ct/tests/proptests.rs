//! Equivalence tests between `base32` crate and `base32ct`.

#![cfg(feature = "alloc")]

use base32::Alphabet;
use base32ct::{Base32 as Base32Ct, Base32Unpadded as Base32UnpaddedCt, Encoding};
use proptest::{prelude::*, string::*};

const RFC4648_PADDED: Alphabet = Alphabet::RFC4648 { padding: true };
const RFC4648_UNPADDED: Alphabet = Alphabet::RFC4648 { padding: false };

proptest! {
    /// Ensure `base32ct` decodes padded data encoded by `base32` ref crate.
    #[test]
    fn decode_equiv_padded(bytes in bytes_regex(".{0,256}").unwrap()) {
        let encoded = base32::encode(RFC4648_PADDED, &bytes).to_lowercase();
        let decoded = Base32Ct::decode_vec(&encoded);
        prop_assert_eq!(Ok(bytes), decoded);
    }

    /// Ensure `base32ct` decodes unpadded data encoded by `base32` ref crate.
    #[test]
    fn decode_equiv_unpadded(bytes in bytes_regex(".{0,256}").unwrap()) {
        let encoded = base32::encode(RFC4648_UNPADDED, &bytes).to_lowercase();
        let decoded = Base32UnpaddedCt::decode_vec(&encoded);
        prop_assert_eq!(Ok(bytes), decoded);
    }

    /// Ensure `base32ct` and the `base32` ref crate encode randomly generated
    /// inputs equivalently (with padding).
    #[test]
    fn encode_equiv_padded(bytes in bytes_regex(".{0,256}").unwrap()) {
        let actual = Base32Ct::encode_string(&bytes);
        let expected = base32::encode(RFC4648_PADDED, &bytes).to_lowercase();
        prop_assert_eq!(actual, expected);
    }
}
