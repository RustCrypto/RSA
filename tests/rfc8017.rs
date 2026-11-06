//! Regression tests for RFC8017 signature representation and verification boundaries.

use rand::{SeedableRng, rngs::ChaCha8Rng};
use rsa::{
    BoxedUint, PrivateKey, Pss, PublicKey, pss,
    signature::{
        DigestVerifier, RandomizedSigner, SignatureEncoding, Verifier, hazmat::PrehashVerifier,
    },
    traits::PublicKeyParts,
};
use sha2::{Digest, Sha256};

#[cfg(feature = "pkcs1v15")]
use rsa::{Pkcs1v15Sign, pkcs1v15};

fn private_key() -> PrivateKey {
    // 1025 bits makes both k != storage width and PSS emLen != k.
    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    PrivateKey::new(&mut rng, 1025).unwrap()
}

#[cfg(feature = "pkcs1v15")]
fn check_pkcs1v15(key: &PublicKey, message: &[u8], bytes: &[u8], valid: bool) {
    let digest = Sha256::digest(message);
    let signature = pkcs1v15::Signature::try_from(bytes).unwrap();
    let verifier = pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
    assert_eq!(
        key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, bytes)
            .is_ok(),
        valid
    );
    assert_eq!(verifier.verify(message, &signature).is_ok(), valid);
    assert_eq!(verifier.verify_prehash(&digest, &signature).is_ok(), valid);
    assert_eq!(
        verifier
            .verify_digest(
                |d| {
                    d.update(message);
                    Ok(())
                },
                &signature
            )
            .is_ok(),
        valid
    );
}

fn check_pss(key: &PublicKey, message: &[u8], bytes: &[u8], valid: bool) {
    let digest = Sha256::digest(message);
    let signature = pss::Signature::try_from(bytes).unwrap();
    let verifier = pss::VerifyingKey::<Sha256>::new(key.clone());
    assert_eq!(
        key.verify(Pss::<Sha256>::new(), &digest, bytes).is_ok(),
        valid
    );
    assert_eq!(verifier.verify(message, &signature).is_ok(), valid);
    assert_eq!(verifier.verify_prehash(&digest, &signature).is_ok(), valid);
    assert_eq!(
        verifier
            .verify_digest(
                |d| {
                    d.update(message);
                    Ok(())
                },
                &signature
            )
            .is_ok(),
        valid
    );
    assert_eq!(
        pss::VerifyingKey::<Sha256>::new_with_auto_salt_len(key.clone())
            .verify(message, &signature)
            .is_ok(),
        valid
    );
}

#[test]
#[cfg(feature = "pkcs1v15")]
fn signature_octet_strings_round_trip_pkcs1v15() {
    for bytes in [&[][..], &[0][..], &[0, 0, 42][..], &[0u8; 129][..]] {
        let pkcs = pkcs1v15::Signature::try_from(bytes).unwrap();
        assert_eq!(pkcs.to_bytes().as_ref(), bytes);
        assert_eq!(format!("{pkcs:x}"), hex::encode(bytes));
        assert_eq!(format!("{pkcs:X}"), hex::encode_upper(bytes));
    }
}

#[test]
fn signature_octet_strings_round_trip_pss() {
    for bytes in [&[][..], &[0][..], &[0, 0, 42][..], &[0u8; 129][..]] {
        let pss = pss::Signature::try_from(bytes).unwrap();
        assert_eq!(pss.to_bytes().as_ref(), bytes);
        assert_eq!(format!("{pss:x}"), hex::encode(bytes));
        assert_eq!(format!("{pss:X}"), hex::encode_upper(bytes));
    }
}

#[test]
#[cfg(feature = "pkcs1v15")]
fn signatures_require_exact_modulus_length_pkcs1v15() {
    let key = private_key();
    let public = key.to_public_key();
    let message = b"RFC8017 octet-string lengths";
    let mut rng = ChaCha8Rng::from_seed([7; 32]);
    let pkcs = pkcs1v15::SigningKey::<Sha256>::new(key.clone())
        .sign_with_rng(&mut rng, message)
        .to_bytes();

    assert_eq!(pkcs.len(), public.size());
    check_pkcs1v15(&public, message, &pkcs, true);

    // Adding zero octets changes S's length without changing OS2IP(S).
    for extra in [1, 7, 8] {
        let mut padded = vec![0; extra];
        padded.extend_from_slice(&pkcs);
        check_pkcs1v15(&public, message, &padded, false);
    }
    check_pkcs1v15(&public, message, &pkcs[1..], false);
    check_pkcs1v15(&public, message, &[], false);
}

#[test]
fn signatures_require_exact_modulus_length_pss() {
    let key = private_key();
    let public = key.to_public_key();
    let message = b"RFC8017 octet-string lengths";
    let mut rng = ChaCha8Rng::from_seed([7; 32]);
    let pss = pss::SigningKey::<Sha256>::new(key)
        .sign_with_rng(&mut rng, message)
        .to_bytes();

    assert_eq!(pss.len(), public.size());
    check_pss(&public, message, &pss, true);

    // Adding zero octets changes S's length without changing OS2IP(S).
    for extra in [1, 7, 8] {
        let mut padded = vec![0; extra];
        padded.extend_from_slice(&pss);
        check_pss(&public, message, &padded, false);
    }
    check_pss(&public, message, &pss[1..], false);
    check_pss(&public, message, &[], false);
}

#[test]
fn pss_rejects_out_of_range_signature_alias() {
    const OUT_OF_RANGE: &[u8] = b"out-of-range signature representative";

    let key = private_key();
    let public = key.to_public_key();
    let digest = Sha256::digest(OUT_OF_RANGE);
    let mut rng = ChaCha8Rng::from_seed([7; 32]);
    let bytes = key
        .sign_with_rng(&mut rng, Pss::<Sha256>::new(), &digest)
        .unwrap();

    let s = BoxedUint::from_be_slice(&bytes, public.n_bits_precision()).unwrap();
    let alias = s.wrapping_add(public.n().as_ref());
    assert!(alias >= *public.n().as_ref());

    // The 1025-bit modulus leaves enough space for s+n in the 129-octet signature.
    let bytes = alias.to_be_bytes();
    let bytes = &bytes[bytes.len() - public.size()..];
    check_pss(&public, OUT_OF_RANGE, bytes, false);
}
