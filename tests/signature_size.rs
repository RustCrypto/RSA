//! Signature decoding limits and support for larger RSA keys.

macro_rules! signature_tests {
    ($scheme:ident) => {
        mod $scheme {
            use rsa::{signature::SignatureEncoding, $scheme::Signature};

            #[test]
            fn decoding_limits() {
                assert_eq!(Signature::MAX_LEN, 1024);
                let bytes = [0u8; 2049];

                for len in [0, 1, 1023, 1024, 1025, 2048, 2049] {
                    let input = &bytes[..len];
                    let signature = Signature::try_from(input);
                    assert_eq!(signature.is_ok(), len <= 1024);
                    if let Ok(signature) = signature {
                        assert_eq!(signature.to_bytes().as_ref(), input);
                    }

                    for max_len in [0, 512, 2048] {
                        let signature = Signature::from_bytes_with_max_len(input, max_len);
                        assert_eq!(signature.is_ok(), len <= max_len);
                        if let Ok(signature) = signature {
                            assert_eq!(signature.to_bytes().as_ref(), input);
                        }
                    }
                }
            }

            #[test]
            #[cfg(feature = "encoding")]
            fn bitstring_decoding_limits() {
                use rsa::pkcs8::der::asn1::BitStringRef;

                let bytes = [0u8; 1025];
                for len in [1024, 1025] {
                    let bitstring = BitStringRef::new(0, &bytes[..len]).unwrap();
                    assert_eq!(Signature::try_from(bitstring).is_ok(), len <= 1024);
                }
            }

            #[test]
            #[cfg(feature = "serde")]
            fn serde_decoding_limits() {
                use serde_test::{
                    Compact, Configure, Token, assert_de_tokens_error, assert_tokens,
                };

                let bytes = [42u8; 1024];
                let signature = Signature::try_from(bytes.as_slice()).unwrap();
                assert_tokens(&signature.compact(), &[Token::Bytes(&[42u8; 1024])]);
                assert_de_tokens_error::<Compact<Signature>>(
                    &[Token::Bytes(&[0u8; 1025])],
                    "invalid length 1025, expected an array with a maximum length of 1024",
                );

                for len in [0, 1, 1024, 1025] {
                    let encoded = format!("\"{}\"", "2a".repeat(len));
                    let signature = serde_json::from_str::<Signature>(&encoded);
                    assert_eq!(signature.is_ok(), len <= 1024);
                    if let Ok(signature) = signature {
                        assert_eq!(signature.to_bytes().as_ref(), vec![42u8; len]);
                    }
                }
            }
        }
    };
}

signature_tests!(pss);

#[cfg(feature = "pkcs1v15")]
signature_tests!(pkcs1v15);

#[test]
#[cfg(feature = "pkcs1v15")]
fn sign_with_large_key() {
    use crypto_bigint::{BoxedUint, ConcatenatingMul, NonZero, Resize};
    use rand::{SeedableRng, rngs::ChaCha8Rng};
    use rsa::{
        RsaPrivateKey, RsaPublicKey, pkcs1v15, pss,
        signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier},
        traits::PublicKeyParts,
    };
    use sha2::Sha256;

    // Public, known Mersenne primes give an 8676-bit test key without prime generation.
    // These factors have different widths, so explicitly use the wide-prime constructor.
    let one = BoxedUint::one_with_precision(4424);
    let p = one.shl_vartime(4253).expect("p fits in 4424 bits") - &one;
    let q = one.shl_vartime(4423).expect("q fits in 4424 bits") - &one;
    let n = p.concatenating_mul(&q);
    let phi = NonZero::new((&p - &one).concatenating_mul(&(&q - &one))).unwrap();
    let e = BoxedUint::from(65537u32);
    let d = e
        .clone()
        .resize_unchecked(phi.bits_precision())
        .invert_mod(&phi)
        .unwrap();
    let key = RsaPrivateKey::from_components_with_wide_primes(n, e, d, vec![p, q])
        .expect("valid test key");
    assert!(key.size() > RsaPublicKey::MAX_SIZE.div_ceil(8));

    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let message = b"signatures larger than the default decoding limit";

    macro_rules! check_signing {
        ($scheme:ident) => {{
            let signing_key = $scheme::SigningKey::<Sha256>::new(key.clone());
            let signature = signing_key.try_sign_with_rng(&mut rng, message).unwrap();
            let bytes = signature.to_bytes();
            assert_eq!(bytes.len(), key.size());
            assert!($scheme::Signature::try_from(bytes.as_ref()).is_err());
            let decoded = $scheme::Signature::from_bytes_with_max_len(&bytes, key.size()).unwrap();
            assert_eq!(decoded, signature);
            signing_key
                .verifying_key()
                .verify(message, &decoded)
                .unwrap();
        }};
    }

    check_signing!(pss);

    #[cfg(feature = "pkcs1v15")]
    check_signing!(pkcs1v15);
}
