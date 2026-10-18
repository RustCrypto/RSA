//! Regression tests for RFC8017 signature representation and verification boundaries.

use rand::{rngs::ChaCha8Rng, SeedableRng};
use rsa::{
    pkcs1v15, pss,
    signature::{
        hazmat::PrehashVerifier, DigestVerifier, RandomizedSigner, SignatureEncoding, Verifier,
    },
    traits::PublicKeyParts,
    Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};

fn private_key() -> RsaPrivateKey {
    // 1025 bits makes both k != storage width and PSS emLen != k.
    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    RsaPrivateKey::new(&mut rng, 1025).unwrap()
}

fn check_pkcs1v15(key: &RsaPublicKey, message: &[u8], bytes: &[u8], valid: bool) {
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

fn check_pss(key: &RsaPublicKey, message: &[u8], bytes: &[u8], valid: bool) {
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
fn signature_octet_strings_round_trip() {
    for bytes in [&[][..], &[0][..], &[0, 0, 42][..], &[0u8; 129][..]] {
        let pkcs = pkcs1v15::Signature::try_from(bytes).unwrap();
        let pss = pss::Signature::try_from(bytes).unwrap();
        assert_eq!(pkcs.to_bytes().as_ref(), bytes);
        assert_eq!(pss.to_bytes().as_ref(), bytes);
        assert_eq!(format!("{pkcs:x}"), hex::encode(bytes));
        assert_eq!(format!("{pss:x}"), hex::encode(bytes));
        assert_eq!(format!("{pkcs:X}"), hex::encode_upper(bytes));
        assert_eq!(format!("{pss:X}"), hex::encode_upper(bytes));
    }
}

#[test]
fn signatures_require_exact_modulus_length() {
    let key = private_key();
    let public = key.to_public_key();
    let message = b"RFC8017 octet-string lengths";
    let mut rng = ChaCha8Rng::from_seed([7; 32]);
    let pkcs = pkcs1v15::SigningKey::<Sha256>::new(key.clone())
        .sign_with_rng(&mut rng, message)
        .to_bytes();
    let pss = pss::SigningKey::<Sha256>::new(key)
        .sign_with_rng(&mut rng, message)
        .to_bytes();

    assert_eq!(pkcs.len(), public.size());
    assert_eq!(pss.len(), public.size());
    check_pkcs1v15(&public, message, &pkcs, true);
    check_pss(&public, message, &pss, true);

    // Adding zero octets changes S's length without changing OS2IP(S).
    for extra in [1, 7, 8] {
        let mut padded = vec![0; extra];
        padded.extend_from_slice(&pkcs);
        check_pkcs1v15(&public, message, &padded, false);
        let mut padded = vec![0; extra];
        padded.extend_from_slice(&pss);
        check_pss(&public, message, &padded, false);
    }
    check_pkcs1v15(&public, message, &pkcs[1..], false);
    check_pss(&public, message, &pss[1..], false);
    check_pkcs1v15(&public, message, &[], false);
    check_pss(&public, message, &[], false);
}
