//! Test CRT coefficients for primes with different storage precisions.

use rsa::{traits::PrivateKeyParts, BoxedUint, RsaPrivateKey};

fn key_and_coefficient(reverse: bool) -> (RsaPrivateKey, BoxedUint) {
    let (p, q, expected) = if reverse {
        // (2^127 - 1) mod 3 = 1.
        (3u128, u128::MAX >> 1, 1u128)
    } else {
        // 3 * ((2^128 - 1) / 3) = 2p + 1.
        (u128::MAX >> 1, 3u128, u128::MAX / 3)
    };
    let key = RsaPrivateKey::from_p_q(
        BoxedUint::from(p),
        BoxedUint::from(q),
        BoxedUint::from(65537u64),
    )
    .unwrap();

    assert_ne!(
        key.primes()[0].bits_precision(),
        key.primes()[1].bits_precision()
    );
    (key, BoxedUint::from(expected))
}

fn check_coefficient(reverse: bool) {
    let (mut key, expected) = key_and_coefficient(reverse);
    assert_eq!(key.crt_coefficient().unwrap(), expected);
    key.clear_precomputed();
    assert_eq!(key.crt_coefficient().unwrap(), expected);
}

#[test]
fn crt_coefficient_wider_p() {
    check_coefficient(false);
}

#[test]
fn crt_coefficient_wider_q() {
    check_coefficient(true);
}

#[cfg(feature = "encoding")]
fn check_encoded_coefficient(reverse: bool) {
    use pkcs1::{EncodeRsaPrivateKey, RsaPrivateKeyRef};
    use pkcs8::der::Decode;

    let (mut key, expected) = key_and_coefficient(reverse);
    for clear_precomputed in [false, true] {
        if clear_precomputed {
            key.clear_precomputed();
        }
        let der = key.to_pkcs1_der().unwrap();
        let encoded = RsaPrivateKeyRef::from_der(der.as_bytes()).unwrap();
        let coefficient = BoxedUint::from_be_slice(encoded.coefficient.as_bytes(), 128).unwrap();
        assert_eq!(coefficient, expected);
    }
}

#[test]
#[cfg(feature = "encoding")]
fn pkcs1_coefficient_wider_p() {
    check_encoded_coefficient(false);
}

#[test]
#[cfg(feature = "encoding")]
fn pkcs1_coefficient_wider_q() {
    check_encoded_coefficient(true);
}
