//! Test explicit wide storage for unbalanced primes in both orders.

use rsa::{
    BoxedUint, RsaPrivateKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};

fn key_and_coefficient(reverse: bool) -> (RsaPrivateKey, BoxedUint) {
    let (p, q, expected) = if reverse {
        // (2^127 - 1) mod 3 = 1.
        (3u128, u128::MAX >> 1, 1u128)
    } else {
        // 3 * ((2^128 - 1) / 3) = 2p + 1.
        (u128::MAX >> 1, 3u128, u128::MAX / 3)
    };
    let n = BoxedUint::from_be_hex("00000000000000017ffffffffffffffffffffffffffffffd", 192)
        .expect("modulus");
    let e = BoxedUint::from(65537u64);
    let d = BoxedUint::from(113429186379523348228037317453566814889u128);
    let primes = vec![BoxedUint::from(p), BoxedUint::from(q)];
    // The default policy rejects unbalanced keys consistently on 32- and 64-bit machines.
    assert!(
        RsaPrivateKey::from_components(n.clone(), e.clone(), d.clone(), primes.clone()).is_err()
    );
    let key = RsaPrivateKey::from_components_with_wide_primes(n, e, d, primes)
        .expect("explicit wide key");
    for prime in key.primes() {
        assert_eq!(prime.bits_precision(), key.n().bits_precision());
    }
    assert_eq!(
        key.dp().expect("dp").bits_precision(),
        key.n().bits_precision()
    );
    assert_eq!(
        key.dq().expect("dq").bits_precision(),
        key.n().bits_precision()
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

#[test]
#[cfg(feature = "hazmat")]
fn wide_crt_matches_non_crt() {
    for reverse in [false, true] {
        let (key, _) = key_and_coefficient(reverse);
        let mut non_crt = key.clone();
        non_crt.clear_precomputed();
        let bits = key.n().bits_precision();
        for c in [
            BoxedUint::zero_with_precision(bits),
            BoxedUint::one_with_precision(bits),
            key.n().as_ref() - &BoxedUint::one(),
        ] {
            let crt = rsa::hazmat::rsa_decrypt_and_check::<rand::rngs::ChaCha8Rng>(&key, None, &c)
                .expect("CRT");
            let reference =
                rsa::hazmat::rsa_decrypt_and_check::<rand::rngs::ChaCha8Rng>(&non_crt, None, &c)
                    .expect("non-CRT");
            assert_eq!(crt, reference);
        }
    }
}

#[test]
fn half_width_bit_bound_is_independent_of_limb_size() {
    // n has 64 bits but p has 33. A 32-bit bound rounds up to 64 on 64-bit platforms,
    // so checking storage precision alone would accept this key only on those platforms.
    let n = BoxedUint::from(18446744065119616769u64);
    let e = BoxedUint::from(65537u64);
    let d = BoxedUint::from(9187203045686083073u64);
    let primes = vec![
        BoxedUint::from(4294967311u64),
        BoxedUint::from(4294967279u64),
    ];
    assert_eq!(
        RsaPrivateKey::from_components(n.clone(), e.clone(), d.clone(), primes.clone()),
        Err(rsa::Error::InvalidPrime)
    );
    RsaPrivateKey::from_components_with_wide_primes(n, e, d, primes).expect("wide key");
}
