//! Deterministic fallback derivation from [draft-irtf-cfrg-rsa-guidance-10 §7.1–7.2].
//!
//! These helpers implement step 3 of §7.2. The caller is then expected to perform decoding and
//! message selection without exposing padding validity or the alternative length.
//!
//! [draft-irtf-cfrg-rsa-guidance-10 §7.1–7.2]: https://www.ietf.org/archive/id/draft-irtf-cfrg-rsa-guidance-10.html#section-7.1

use super::selection::select_al;
use crate::{
    algorithms::pad::i2osp_zeroizing,
    errors::{Error, Result},
};
use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use digest::Digest;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Key derivation key for one private key and ciphertext.
pub(crate) struct KeyDerivationKey(Zeroizing<[u8; 32]>);

impl KeyDerivationKey {
    /// Computes `HMAC-SHA256(SHA256(I2OSP(d, k)), ciphertext)`.
    ///
    /// The caller must establish that d fits in k octets and that its storage precision is public.
    ///
    /// Use the supplied private exponent, not a reconstructed equivalent exponent. The ciphertext
    /// must have passed the public length check.
    pub(crate) fn derive(d: &BoxedUint, k: usize, ciphertext: &[u8]) -> Result<Self> {
        if k < 11 || ciphertext.len() != k {
            return Err(Error::Decryption);
        }

        // Step 3.1.1: D = I2OSP(d, k).
        let d = i2osp_zeroizing(d.clone(), k);

        // Step 3.1.2: DH = SHA256(D).
        let dh: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(&*d).into());

        // Step 3.1.3: KDK = HMAC(DH, C, SHA256).
        let mut mac = Hmac::<Sha256>::new_from_slice(dh.as_ref()).map_err(|_| Error::Internal)?;
        mac.update(ciphertext);
        Ok(Self(Zeroizing::new(mac.finalize().into_bytes().into())))
    }

    /// Derives the full alternative message and its candidate suffix length.
    ///
    /// Both the length and message remain secret until the caller selects the final result together
    /// with the real plaintext. Do not slice at this candidate length  or expose it separately
    /// before that selection.
    pub(crate) fn alternative_message(&self, k: usize) -> Result<(Zeroizing<Vec<u8>>, u16)> {
        let max_message_len = k
            .checked_sub(11)
            .and_then(|len| u16::try_from(len).ok())
            .ok_or(Error::Decryption)?;

        // Step 3.2.1: CL = IRPRF(KDK, "length", 256).
        let cl = self.irprf(b"length", 256)?;

        // Step 3.2.2: AM = IRPRF(KDK, "message", k).
        let am = self.irprf(b"message", k)?;

        // Step 3.3: AL is the last admissible candidate, or zero.
        let al = select_al(&cl, max_message_len);
        Ok((am, al))
    }

    /// Computes the `IRPRF` from `draft-irtf-cfrg-rsa-guidance-10` §7.1, returning a zeroizing
    /// output buffer.
    fn irprf(&self, label: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>> {
        let bit_length = length
            .checked_mul(8)
            .and_then(|bits| u16::try_from(bits).ok())
            .ok_or(Error::Decryption)?
            .to_be_bytes();

        let mut output = Zeroizing::new(vec![0u8; length]);
        for (i, chunk) in (0u16..).zip(output.chunks_mut(32)) {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(self.0.as_ref()).map_err(|_| Error::Internal)?;
            mac.update(&i.to_be_bytes());
            mac.update(label);
            mac.update(&bit_length);
            let block: Zeroizing<[u8; 32]> = Zeroizing::new(mac.finalize().into_bytes().into());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_mask_boundary() {
        // Reproduces the k - 10 mask bug from #702 using real IRPRF output.
        let mut key = [0u8; 32];
        key[31] = 2;
        let kdk = KeyDerivationKey(Zeroizing::new(key));
        assert_eq!(kdk.alternative_message(138).unwrap().1, 105);
        assert_eq!(kdk.alternative_message(266).unwrap().1, 233);
    }

    #[test]
    fn public_length_errors() {
        let d = BoxedUint::from(1u64);
        assert!(KeyDerivationKey::derive(&d, 10, &[0; 10]).is_err());
        assert!(KeyDerivationKey::derive(&d, 11, &[0; 10]).is_err());
        assert!(KeyDerivationKey::derive(&d, 11, &[0; 12]).is_err());
        let kdk = KeyDerivationKey::derive(&d, 11, &[0; 11]).unwrap();
        assert!(kdk.alternative_message(10).is_err());
        assert_eq!(kdk.alternative_message(11).unwrap().1, 0);
        assert!(kdk.irprf(b"message", 0).unwrap().is_empty());
        assert_eq!(kdk.irprf(b"message", 8191).unwrap().len(), 8191);
        assert!(kdk.irprf(b"message", 8192).is_err());
        assert!(kdk.irprf(b"message", usize::MAX).is_err());
    }

    #[cfg(feature = "encoding")]
    mod vectors {
        use super::*;
        use crate::{
            PrivateKey,
            algorithms::{pad::os2ip, pkcs1v15::eme_pkcs1v15_decode, rsa::rsa_decrypt_and_check},
            pkcs1v15::{DecryptingKey, Pkcs1v15Encrypt},
            traits::{Decryptor, PaddingScheme, PublicKeyParts, RandomizedDecryptor},
        };
        use alloc::{collections::BTreeMap, string::String};
        use pkcs8::DecodePrivateKey;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Section {
            key_pem: String,
            cases: Vec<Case>,
        }

        #[derive(Deserialize)]
        struct Case {
            id: String,
            valid: bool,
            ciphertext_hex: String,
            expect: Expected,
        }

        #[derive(Deserialize)]
        struct Expected {
            #[serde(default)]
            empty: bool,
            ascii: Option<String>,
            hex: Option<String>,
        }

        macro_rules! fixture {
            ($name:literal) => {
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/examples/pkcs1v15_cfrg_rsa_guidance/",
                    $name
                ))
            };
        }

        #[rstest::rstest]
        #[case("B.1")]
        #[case("B.2")]
        #[case("B.3")]
        #[case("B.4")]
        fn draft_10_vectors(#[case] section: &str) {
            let data: BTreeMap<String, Section> =
                serde_json::from_str(fixture!("test_cases.json")).unwrap();
            let section = &data[section];
            let pem = match section.key_pem.as_str() {
                "k2048.pem" => fixture!("k2048.pem"),
                "k2049.pem" => fixture!("k2049.pem"),
                "k3072.pem" => fixture!("k3072.pem"),
                "k4096.pem" => fixture!("k4096.pem"),
                _ => panic!("unknown key fixture"),
            };
            let key = PrivateKey::from_pkcs8_pem(pem).unwrap();
            let k = key.size();
            let typed_key = DecryptingKey::new(key.clone());
            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            assert_eq!(section.cases.len(), 12);

            for case in &section.cases {
                let ciphertext = hex::decode(&case.ciphertext_hex).unwrap();
                assert_eq!(ciphertext.len(), k, "{}", case.id);
                let c = os2ip(&ciphertext, key.n_bits_precision()).unwrap();
                let m = rsa_decrypt_and_check::<ChaCha8Rng>(&key, None, &c).unwrap();
                let em = i2osp_zeroizing(m, k);
                let (check, _) = eme_pkcs1v15_decode(&em, k);
                assert_eq!(!check.to_bool(), case.valid, "{}", case.id);

                let expected = if case.expect.empty {
                    Vec::new()
                } else if let Some(ascii) = &case.expect.ascii {
                    ascii.as_bytes().to_vec()
                } else {
                    hex::decode(case.expect.hex.as_ref().unwrap()).unwrap()
                };

                // Exercise the actual scheme and both public APIs. Different blinding randomness
                // and repeated calls must not change synthetic plaintext.
                let outputs = [
                    Pkcs1v15Encrypt
                        .decrypt::<ChaCha8Rng>(None, &key, &ciphertext)
                        .unwrap(),
                    key.decrypt(Pkcs1v15Encrypt, &ciphertext).unwrap(),
                    key.decrypt_blinded(&mut rng, Pkcs1v15Encrypt, &ciphertext)
                        .unwrap(),
                    typed_key.decrypt(&ciphertext).unwrap(),
                    typed_key.decrypt_with_rng(&mut rng, &ciphertext).unwrap(),
                ];
                for got in outputs {
                    assert_eq!(got, expected, "{}", case.id);
                }
            }
        }
    }
}
