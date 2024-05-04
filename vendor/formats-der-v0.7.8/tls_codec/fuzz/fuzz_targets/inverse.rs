#![no_main]

use libfuzzer_sys::fuzz_target;
use tls_codec::{Deserialize, Serialize, Size, VLBytes};

fuzz_target!(|expected: VLBytes| {
    let serialized = expected.tls_serialize_detached().unwrap();
    let slice = &mut serialized.as_slice();

    let got = VLBytes::tls_deserialize(slice).unwrap();

    // Assert that serialized length matches predicted length.
    assert_eq!(expected.tls_serialized_len(), serialized.len());

    // Assert that all bytes were consumed.
    assert!(slice.is_empty());

    // Assert that ...
    //     expected == deserialize(serialize(expected))
    assert_eq!(expected, got);
});
