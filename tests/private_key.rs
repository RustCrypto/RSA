//! Integration tests for `rsa::PrivateKey`.

use rand::{SeedableRng, rngs::ChaCha8Rng};
use rsa::{Error, Oaep, PrivateKey, Pss, traits::PublicKeyParts};
#[cfg(feature = "pkcs1v15")]
use rsa::{Pkcs1v15Encrypt, Pkcs1v15Sign};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

fn example_private_key() -> &'static PrivateKey {
    static KEY: OnceLock<PrivateKey> = OnceLock::new();

    // Exercise non-byte-aligned moduli without depending on the encoding feature.
    KEY.get_or_init(|| PrivateKey::new(&mut example_rng(), 1025).unwrap())
}

fn example_rng() -> ChaCha8Rng {
    ChaCha8Rng::from_seed([42; 32])
}

#[test]
fn encryption_interoperability() {
    let key = example_private_key();
    let public = key.to_public_key();

    // Empty messages and the exact maximum message lengths are supported.
    #[cfg(feature = "pkcs1v15")]
    for len in [0, public.size() - 11] {
        let msg = vec![42; len];
        let ct = public
            .pkcs1v15_encrypt_with_rng(&mut example_rng(), &msg)
            .unwrap();
        assert_eq!(ct.len(), public.size());
        assert_eq!(
            ct,
            public
                .encrypt(&mut example_rng(), Pkcs1v15Encrypt, &msg)
                .unwrap()
        );
        assert_eq!(key.decrypt(Pkcs1v15Encrypt, &ct).unwrap(), msg);
        assert_eq!(key.pkcs1v15_decrypt(&ct).unwrap(), msg);
        assert_eq!(
            key.pkcs1v15_decrypt_with_rng(&mut example_rng(), &ct)
                .unwrap(),
            msg
        );
    }

    for len in [0, public.size() - 2 * 32 - 2] {
        let msg = vec![42; len];
        let ct = public
            .oaep_encrypt_with_rng::<Sha256, _>(&mut example_rng(), &msg)
            .unwrap();

        assert_eq!(ct.len(), public.size());
        assert_eq!(
            ct,
            public
                .encrypt(&mut example_rng(), Oaep::<Sha256>::new(), &msg)
                .unwrap()
        );
        assert_eq!(key.decrypt(Oaep::<Sha256>::new(), &ct).unwrap(), msg);
        assert_eq!(key.oaep_decrypt::<Sha256>(&ct).unwrap(), msg);
        assert_eq!(
            key.oaep_decrypt_with_rng::<Sha256, _>(&mut example_rng(), &ct)
                .unwrap(),
            msg
        );
    }
}

#[test]
fn signing_interoperability() {
    let key = example_private_key();
    let public = key.to_public_key();

    for msg in [b"".as_slice(), b"inherent signing methods"] {
        let hash = Sha256::digest(msg);
        let pss = key
            .pss_sign_with_rng::<Sha256, _>(&mut example_rng(), msg)
            .unwrap();
        assert_eq!(pss.len(), public.size());
        assert_eq!(
            pss,
            key.sign_with_rng(&mut example_rng(), Pss::<Sha256>::new(), &hash)
                .unwrap()
        );
        assert_eq!(
            pss,
            key.pss_sign_prehash_with_rng::<Sha256, _>(&mut example_rng(), &hash)
                .unwrap()
        );
        public.verify(Pss::<Sha256>::new(), &hash, &pss).unwrap();
        public.pss_verify::<Sha256>(msg, &pss).unwrap();
        public.pss_verify_prehash::<Sha256>(&hash, &pss).unwrap();
        assert!(public.pss_verify::<Sha256>(b"wrong message", &pss).is_err());

        #[cfg(feature = "pkcs1v15")]
        let pkcs = {
            let pkcs = key
                .pkcs1v15_sign_with_rng::<Sha256, _>(&mut example_rng(), msg)
                .unwrap();

            assert_eq!(pkcs.len(), public.size());
            assert_eq!(
                pkcs,
                key.sign(Pkcs1v15Sign::new::<Sha256>(), &hash).unwrap()
            );
            assert_eq!(pkcs, key.pkcs1v15_sign::<Sha256>(msg).unwrap());
            assert_eq!(pkcs, key.pkcs1v15_sign_prehash::<Sha256>(&hash).unwrap());
            assert_eq!(
                pkcs,
                key.pkcs1v15_sign_prehash_with_rng::<Sha256, _>(&mut example_rng(), &hash)
                    .unwrap()
            );

            public
                .verify(Pkcs1v15Sign::new::<Sha256>(), &hash, &pkcs)
                .unwrap();
            public.pkcs1v15_verify::<Sha256>(msg, &pkcs).unwrap();
            public
                .pkcs1v15_verify_prehash::<Sha256>(&hash, &pkcs)
                .unwrap();

            assert!(
                public
                    .pkcs1v15_verify::<Sha256>(b"wrong message", &pkcs)
                    .is_err()
            );

            pkcs
        };

        for sig in [
            #[cfg(feature = "pkcs1v15")]
            &pkcs,
            &pss,
        ] {
            let mut padded = vec![0];
            padded.extend_from_slice(sig);
            for invalid in [&sig[..sig.len() - 1], padded.as_slice(), &[]] {
                assert_eq!(
                    public.pss_verify::<Sha256>(msg, invalid),
                    Err(Error::Verification)
                );

                #[cfg(feature = "pkcs1v15")]
                assert_eq!(
                    public.pkcs1v15_verify::<Sha256>(msg, invalid),
                    Err(Error::Verification)
                );
            }
        }
    }
}

#[test]
fn pss_requires_digest_sized_salt() {
    let key = example_private_key();
    let public = key.to_public_key();
    let msg = b"salt length policy";
    let hash = Sha256::digest(msg);
    for salt_len in [0, 20, 32] {
        let sig = key
            .sign_with_rng(
                &mut example_rng(),
                Pss::<Sha256>::new_with_salt(salt_len),
                &hash,
            )
            .unwrap();
        assert_eq!(
            public.pss_verify::<Sha256>(msg, &sig).is_ok(),
            salt_len == 32
        );
        assert_eq!(
            public.pss_verify_prehash::<Sha256>(&hash, &sig).is_ok(),
            salt_len == 32
        );
    }
}

#[test]
fn invalid_inputs() {
    let key = example_private_key();
    let public = key.to_public_key();

    assert_eq!(
        public.oaep_encrypt_with_rng::<Sha256, _>(&mut example_rng(), &vec![0; public.size() - 65]),
        Err(Error::MessageTooLong)
    );
    #[cfg(feature = "pkcs1v15")]
    assert_eq!(
        public.pkcs1v15_encrypt_with_rng(&mut example_rng(), &vec![0; public.size() - 10]),
        Err(Error::MessageTooLong)
    );

    let outside_modulus = public.n().to_be_bytes();
    let outside_modulus = &outside_modulus[outside_modulus.len() - public.size()..];
    for ct in [&[][..], outside_modulus] {
        #[cfg(feature = "pkcs1v15")]
        {
            assert!(key.pkcs1v15_decrypt(ct).is_err());
            assert!(
                key.pkcs1v15_decrypt_with_rng(&mut example_rng(), ct)
                    .is_err()
            );
            assert!(public.pkcs1v15_verify::<Sha256>(b"message", ct).is_err());
        }
        assert!(key.oaep_decrypt::<Sha256>(ct).is_err());
        assert!(
            key.oaep_decrypt_with_rng::<Sha256, _>(&mut example_rng(), ct)
                .is_err()
        );
        assert!(public.pss_verify::<Sha256>(b"message", ct).is_err());
    }

    // An all-zero ciphertext has invalid padding, but is a valid representative.
    let ct = vec![0; public.size()];

    #[cfg(feature = "pkcs1v15")]
    {
        let synthetic = key.decrypt(Pkcs1v15Encrypt, &ct).unwrap();
        assert_eq!(key.pkcs1v15_decrypt(&ct).unwrap(), synthetic);
        assert_eq!(
            key.pkcs1v15_decrypt_with_rng(&mut example_rng(), &ct)
                .unwrap(),
            synthetic
        );
    }

    assert_eq!(key.oaep_decrypt::<Sha256>(&ct), Err(Error::Decryption));
    assert_eq!(
        key.oaep_decrypt_with_rng::<Sha256, _>(&mut example_rng(), &ct),
        Err(Error::Decryption)
    );

    let sig = key
        .pss_sign_with_rng::<Sha256, _>(&mut example_rng(), b"message")
        .unwrap();

    for len in [0, 31, 33] {
        let hash = vec![0; len];
        assert_eq!(
            public.pss_verify_prehash::<Sha256>(&hash, &sig),
            Err(Error::Verification)
        );

        #[cfg(feature = "pkcs1v15")]
        {
            assert_eq!(
                key.pkcs1v15_sign_prehash::<Sha256>(&hash),
                Err(Error::InputNotHashed)
            );
            assert_eq!(
                public.pkcs1v15_verify_prehash::<Sha256>(&hash, &sig),
                Err(Error::InputNotHashed)
            );
        }
    }
}

#[test]
#[cfg(feature = "getrandom")]
fn system_rng_methods() {
    let key = example_private_key();
    let public = key.to_public_key();
    let msg = b"system randomness";

    #[cfg(feature = "pkcs1v15")]
    {
        let pkcs = public.pkcs1v15_encrypt(msg).unwrap();
        assert_eq!(key.pkcs1v15_decrypt(&pkcs).unwrap(), msg);
    }

    let oaep = public.oaep_encrypt::<Sha256>(msg).unwrap();
    assert_eq!(key.oaep_decrypt::<Sha256>(&oaep).unwrap(), msg);

    let pss = key.pss_sign::<Sha256>(msg).unwrap();
    public.pss_verify::<Sha256>(msg, &pss).unwrap();

    let hash = Sha256::digest(msg);
    let pss = key.pss_sign_prehash::<Sha256>(&hash).unwrap();
    public.pss_verify::<Sha256>(msg, &pss).unwrap();
    assert_eq!(
        key.pss_sign_prehash::<Sha256>(&hash[..31]),
        Err(Error::InputNotHashed)
    );
}
