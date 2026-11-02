//! Public-key modulus size policy and explicit overrides.

use crypto_bigint::Resize;
use rand::rngs::ChaCha8Rng;
use rand_core::SeedableRng;
use rsa::{BoxedUint, Error, Oaep, Pkcs1v15Encrypt, RsaPublicKey};

// Public-key construction checks the modulus size and parity, not its factorization.
fn modulus(bits: u32) -> BoxedUint {
    let one = BoxedUint::one_with_precision(bits);
    (&one << (bits - 1)) | one
}

#[test]
#[allow(deprecated)]
fn default_public_key_size_limits() {
    for (bits, error) in [
        (1023, Some(Error::ModulusTooSmall)),
        (1024, None),
        (8192, None),
        (8193, Some(Error::ModulusTooLarge)),
    ] {
        let n = modulus(bits);
        let e = BoxedUint::from(65537u64);
        assert_eq!(RsaPublicKey::new(n.clone(), e.clone()).err(), error);
        assert_eq!(
            RsaPublicKey::new_with_max_size(n, e, RsaPublicKey::MAX_SIZE).err(),
            error
        );
    }

    // Storage precision must not allow a short modulus to evade the minimum.
    assert_eq!(
        RsaPublicKey::new(
            BoxedUint::from(3233u64).resize_unchecked(1024),
            17u64.into()
        ),
        Err(Error::ModulusTooSmall)
    );
}

#[test]
fn explicit_public_key_size_limits() {
    for bits in [512, 1024, 8193] {
        let key = RsaPublicKey::new_with_size_limits(
            modulus(bits),
            65537u64.into(),
            bits as usize..=bits as usize,
        )
        .unwrap();

        // Operation-time checks must respect the constructor's explicit size override.
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        key.encrypt(&mut rng, Pkcs1v15Encrypt, b"test").unwrap();
        key.encrypt(&mut rng, Oaep::<sha1::Sha1>::new(), b"test")
            .unwrap();
    }

    for (limits, error) in [
        (1025..=8192, Error::ModulusTooSmall),
        (0..=1023, Error::ModulusTooLarge),
        (1025..=1024, Error::InvalidArguments),
    ] {
        assert_eq!(
            RsaPublicKey::new_with_size_limits(modulus(1024), 65537u64.into(), limits),
            Err(error)
        );
    }
}

#[test]
fn size_override_preserves_public_key_validation() {
    for (n, e, error) in [
        (0u64, 3u64, Error::InvalidModulus),
        (3234, 17, Error::InvalidModulus),
        (3233, 3233, Error::InvalidModulus),
        (3233, 2, Error::InvalidExponent),
        (3233, 1, Error::PublicExponentTooSmall),
        (1 << 40 | 1, 1 << 34 | 1, Error::PublicExponentTooLarge),
    ] {
        assert_eq!(
            RsaPublicKey::new_with_size_limits(n.into(), e.into(), 0..=8192),
            Err(error)
        );
    }
}

#[test]
#[cfg(feature = "encoding")]
fn public_key_decoding_enforces_default_size_limits() {
    use rsa::{
        pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
        pkcs8::{DecodePublicKey, EncodePublicKey},
    };

    for bits in [512, 1023, 1024] {
        let key =
            RsaPublicKey::new_with_size_limits(modulus(bits), 65537u64.into(), 0..=8192).unwrap();
        let pkcs1 = key.to_pkcs1_der().unwrap();
        let spki = key.to_public_key_der().unwrap();
        if bits < 1024 {
            assert!(matches!(
                RsaPublicKey::from_pkcs1_der(pkcs1.as_bytes()),
                Err(pkcs1::Error::KeyMalformed)
            ));
            assert!(matches!(
                RsaPublicKey::from_public_key_der(spki.as_bytes()),
                Err(spki::Error::KeyMalformed)
            ));
        } else {
            assert_eq!(RsaPublicKey::from_pkcs1_der(pkcs1.as_bytes()).unwrap(), key);
            assert_eq!(
                RsaPublicKey::from_public_key_der(spki.as_bytes()).unwrap(),
                key
            );
        }

        // A legacy key can be decoded into components and explicitly allowed.
        use rsa::pkcs8::der::Decode;
        let components = pkcs1::RsaPublicKeyRef::from_der(pkcs1.as_bytes()).unwrap();
        let imported = RsaPublicKey::new_with_size_limits(
            BoxedUint::from_be_slice_vartime(components.modulus.as_bytes()),
            BoxedUint::from_be_slice_vartime(components.public_exponent.as_bytes()),
            0..=8192,
        )
        .unwrap();
        assert_eq!(imported, key);

        #[cfg(feature = "serde")]
        {
            let json = serde_json::to_string(&key).unwrap();
            let decoded = serde_json::from_str::<RsaPublicKey>(&json);
            if bits < 1024 {
                assert!(decoded.is_err());
            } else {
                assert_eq!(decoded.unwrap(), key);
            }
        }
    }
}
