use rand::Rng;

use num_bigint::BigUint;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::errors::{Error, Result};
use crate::hash::{Hash, Hashes};
use crate::internals;
use crate::key::{self, PublicKey, RSAPrivateKey};

/// Represents oaep cipering/deciphering options.
#[derive(Debug, Clone)]
pub struct OaepOptions {
    pub hash: Hashes,
    pub label: Option<String>,
}

impl OaepOptions {
    pub fn new() -> OaepOptions {
        OaepOptions {
            hash: Hashes::SHA1,
            label: None,
        }
    }

    pub fn set_hash(mut self, h: Hashes) -> Self {
        self.hash = h;
        self
    }

    pub fn set_label(mut self, l: Option<String>) -> Self {
        self.label = l;
        self
    }
}

fn inc_counter(counter: &mut [u8]) {
    if counter[3] == u8::max_value() {
        counter[3] = 0;
    } else {
        counter[3] += 1;
        return;
    }

    if counter[2] == u8::max_value() {
        counter[2] = 0;
    } else {
        counter[2] += 1;
        return;
    }

    if counter[1] == u8::max_value() {
        counter[1] = 0;
    } else {
        counter[1] += 1;
        return;
    }

    if counter[0] == u8::max_value() {
        counter[0] = 0u8;
        counter[1] = 0u8;
        counter[2] = 0u8;
        counter[3] = 0u8;
    } else {
        counter[0] += 1;
    }
}

/// Mask generation function
fn mgf1_xor<H: Hash>(out: &mut [u8], h: &H, seed: &[u8]) {
    let mut counter = vec![0u8; 4];
    let mut i = 0;

    while i < out.len() {
        let mut digest_data = vec![0u8; seed.len() + 4];
        digest_data[0..seed.len()].copy_from_slice(seed);
        digest_data[seed.len()..].copy_from_slice(&counter);

        let digest = h.digest(digest_data.as_slice());
        let mut j = 0;
        loop {
            if j >= digest.len() || i >= out.len() {
                break;
            }

            out[i] ^= digest[j];
            j += 1;
            i += 1;
        }
        inc_counter(counter.as_mut_slice());
    }
}

// Encrypts the given message with RSA and the padding
// scheme from PKCS#1 OAEP.  The message must be no longer than the
// length of the public modulus minus (2+ 2*hash.size()).
#[inline]
pub fn encrypt<R: Rng, K: PublicKey>(
    rng: &mut R,
    pub_key: &K,
    msg: &[u8],
    oaep_options: OaepOptions,
) -> Result<Vec<u8>> {
    key::check_public(pub_key)?;

    let h = oaep_options.hash;
    let k = pub_key.size();

    if msg.len() > k - 2 * h.size() - 2 {
        return Err(Error::MessageTooLong);
    }

    let label = match oaep_options.label {
        Some(l) => l,
        None => "".to_owned(),
    };

    let mut em = vec![0u8; k];

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h.size());
    rng.fill(seed);

    // Data block DB =  pHash || PS || 01 || M
    let db_len = k - h.size() - 1;

    let p_hash = h.digest(label.as_bytes());
    db[0..h.size()].copy_from_slice(p_hash.as_slice());
    db[db_len - msg.len() - 1] = 1;
    db[db_len - msg.len()..].copy_from_slice(msg);

    mgf1_xor(db, &h, seed);
    mgf1_xor(seed, &h, db);

    {
        let mut m = BigUint::from_bytes_be(&em);
        let mut c = internals::encrypt(pub_key, &m).to_bytes_be();
        internals::copy_with_left_pad(&mut em, &c);

        // clear out tmp values
        m.zeroize();
        c.zeroize();
    }

    Ok(em)
}

/// Decrypts a plaintext using RSA and the padding scheme from pkcs1# OAEP
// If an `rng` is passed, it uses RSA blinding to avoid timing side-channel attacks.
//
// Note that whether this function returns an error or not discloses secret
// information. If an attacker can cause this function to run repeatedly and
// learn whether each instance returned an error then they can decrypt and
// forge signatures as if they had the private key. See
// `decrypt_session_key` for a way of solving this problem.
#[inline]
pub fn decrypt<R: Rng>(
    rng: Option<&mut R>,
    priv_key: &RSAPrivateKey,
    ciphertext: &[u8],
    oaep_options: OaepOptions,
) -> Result<Vec<u8>> {
    key::check_public(priv_key)?;

    let (valid, out, index) = decrypt_inner(rng, priv_key, ciphertext, oaep_options)?;
    if valid == 0 {
        return Err(Error::Decryption);
    }

    Ok(out[index as usize..].to_vec())
}

/// Decrypts ciphertext using `priv_key` and blinds the operation if
/// `rng` is given. It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured. In either case, the plaintext is
/// returned in em so that it may be read independently of whether it was valid
/// in order to maintain constant memory access patterns. If the plaintext was
/// valid then index contains the index of the original message in em.
#[inline]
fn decrypt_inner<R: Rng>(
    rng: Option<&mut R>,
    priv_key: &RSAPrivateKey,
    ciphertext: &[u8],
    oaep_options: OaepOptions,
) -> Result<(u8, Vec<u8>, u32)> {
    let k = priv_key.size();
    if k < 11 {
        return Err(Error::Decryption);
    }

    let h = oaep_options.hash;

    if ciphertext.len() > k || k < h.size() * 2 + 2 {
        return Err(Error::Decryption);
    }

    let mut em = {
        let mut c = BigUint::from_bytes_be(ciphertext);
        let mut m = internals::decrypt(rng, priv_key, &c)?;
        let em = internals::left_pad(&m.to_bytes_be(), k);

        c.zeroize();
        m.zeroize();

        em
    };

    let label = match oaep_options.label {
        Some(l) => l,
        None => "".to_owned(),
    };

    let expected_p_hash = h.digest(label.as_bytes());

    let first_byte_is_zero = em[0].ct_eq(&0u8);

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h.size());

    mgf1_xor(seed, &h, db);
    mgf1_xor(db, &h, seed);

    let hash_are_equal = db[0..h.size()].ct_eq(expected_p_hash.as_slice());

    // The remainder of the plaintext must be zero or more 0x00, followed
    // by 0x01, followed by the message.
    //   looking_for_index: 1 if we are still looking for the 0x01
    //   index: the offset of the first 0x01 byte
    //   zero_before_one: 1 if we saw a non-zero byte before the 1
    let mut looking_for_index = 1u8;
    let mut index = 0u32;
    let mut zero_before_one = 0u8;

    for (i, el) in db.iter().skip(h.size()).enumerate() {
        let equals0 = el.ct_eq(&0u8);
        let equals1 = el.ct_eq(&1u8);
        index.conditional_assign(&(i as u32), Choice::from(looking_for_index) & equals1);
        looking_for_index.conditional_assign(&0u8, equals1);
        zero_before_one.conditional_assign(&1u8, Choice::from(looking_for_index) & !equals0);
    }

    let valid = first_byte_is_zero
        & hash_are_equal
        & !Choice::from(zero_before_one)
        & !Choice::from(looking_for_index);
    index = u32::conditional_select(&0, &(index + 2 + (h.size() * 2) as u32), valid);

    Ok((valid.unwrap_u8(), em, index))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::hash::Hashes;
    use crate::key::RSAPublicKey;
    use num_traits::FromPrimitive;
    use rand::distributions::Alphanumeric;
    use rand::thread_rng;

    fn get_private_key() -> RSAPrivateKey {
        // -----BEGIN RSA PRIVATE KEY-----
        // MIIEpAIBAAKCAQEA05e4TZikwmE47RtpWoEG6tkdVTvwYEG2LT/cUKBB4iK49FKW
        // icG4LF5xVU9d1p+i9LYVjPDb61eBGg/DJ+HyjnT+dNO8Fmweq9wbi1e5NMqL5bAL
        // TymXW8yZrK9BW1m7KKZ4K7QaLDwpdrPBjbre9i8AxrsiZkAJUJbAzGDSL+fvmH11
        // xqgbENlr8pICivEQ3HzBu8Q9Iq2rN5oM1dgHjMeA/1zWIJ3qNMkiz3hPdxfkKNdb
        // WuyP8w5fAUFRB2bi4KuNRzyE6HELK5gifD2wlTN600UvGeK5v7zN2BSKv2d2+lUn
        // debnWVbkUimuWpxGlJurHmIvDkj1ZSSoTtNIOwIDAQABAoIBAQDE5wxokWLJTGYI
        // KBkbUrTYOSEV30hqmtvoMeRY1zlYMg3Bt1VFbpNwHpcC12+wuS+Q4B0f4kgVMoH+
        // eaqXY6kvrmnY1+zRRN4p+hNb0U+Vc+NJ5FAx47dpgvWDADgmxVLomjl8Gga9IWNI
        // hjDZLowrtkPXq+9wDaldaFyUFImkb1S1MW9itdLDp/G70TTLNzU6RGg/3J2V02RY
        // 3iL2xEBX/nSgpDbEMI9z9NpC81xHrBanE41IOvyR5B3DoRJzguDA9RGbAiG0/GOd
        // a5w4F3pt6bUm69iMONeYLAf5ig79h31Qiq4nW5RpFcAuLhEG0XXXTsZ3f16A0SwF
        // PZx74eNBAoGBAPgnu/OkGHfHzFmuv0LtSynDLe/LjtloY9WwkKBaiTDdYkohydz5
        // g4Vo/foN9luEYqXyrJE9bFb5dVMr2OePsHvUBcqZpIS89Z8Bm73cs5M/K85wYwC0
        // 97EQEgxd+QGBWQZ8NdowYaVshjWlK1QnOzEnG0MR8Hld9gIeY1XhpC5hAoGBANpI
        // F84Aid028q3mo/9BDHPsNL8bT2vaOEMb/t4RzvH39u+nDl+AY6Ox9uFylv+xX+76
        // CRKgMluNH9ZaVZ5xe1uWHsNFBy4OxSA9A0QdKa9NZAVKBFB0EM8dp457YRnZCexm
        // 5q1iW/mVsnmks8W+fYlc18W5xMSX/ecwkW/NtOQbAoGAHabpz4AhKFbodSLrWbzv
        // CUt4NroVFKdjnoodjfujfwJFF2SYMV5jN9LG3lVCxca43ulzc1tqka33Nfv8TBcg
        // WHuKQZ5ASVgm5VwU1wgDMSoQOve07MWy/yZTccTc1zA0ihDXgn3bfR/NnaVh2wlh
        // CkuI92eyW1494hztc7qlmqECgYEA1zenyOQ9ChDIW/ABGIahaZamNxsNRrDFMl3j
        // AD+cxHSRU59qC32CQH8ShRy/huHzTaPX2DZ9EEln76fnrS4Ey7uLH0rrFl1XvT6K
        // /timJgLvMEvXTx/xBtUdRN2fUqXtI9odbSyCtOYFL+zVl44HJq2UzY4pVRDrNcxs
        // SUkQJqsCgYBSaNfPBzR5rrstLtTdZrjImRW1LRQeDEky9WsMDtCTYUGJTsTSfVO8
        // hkU82MpbRVBFIYx+GWIJwcZRcC7OCQoV48vMJllxMAAjqG/p00rVJ+nvA7et/nNu
        // BoB0er/UmDm4Ly/97EO9A0PKMOE5YbMq9s3t3RlWcsdrU7dvw+p2+A==
        // -----END RSA PRIVATE KEY-----

        RSAPrivateKey::from_components(
            BigUint::parse_bytes(b"00d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078cc780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf6776fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b", 16).unwrap(),
            BigUint::from_u64(65537).unwrap(),
            BigUint::parse_bytes(b"00c4e70c689162c94c660828191b52b4d8392115df486a9adbe831e458d73958320dc1b755456e93701e9702d76fb0b92f90e01d1fe248153281fe79aa9763a92fae69d8d7ecd144de29fa135bd14f9573e349e45031e3b76982f583003826c552e89a397c1a06bd2163488630d92e8c2bb643d7abef700da95d685c941489a46f54b5316f62b5d2c3a7f1bbd134cb37353a44683fdc9d95d36458de22f6c44057fe74a0a436c4308f73f4da42f35c47ac16a7138d483afc91e41dc3a1127382e0c0f5119b0221b4fc639d6b9c38177a6de9b526ebd88c38d7982c07f98a0efd877d508aae275b946915c02e2e1106d175d74ec6777f5e80d12c053d9c7be1e341", 16).unwrap(),
            vec![
                BigUint::parse_bytes(b"00f827bbf3a41877c7cc59aebf42ed4b29c32defcb8ed96863d5b090a05a8930dd624a21c9dcf9838568fdfa0df65b8462a5f2ac913d6c56f975532bd8e78fb07bd405ca99a484bcf59f019bbddcb3933f2bce706300b4f7b110120c5df9018159067c35da3061a56c8635a52b54273b31271b4311f0795df6021e6355e1a42e61",16).unwrap(),
                BigUint::parse_bytes(b"00da4817ce0089dd36f2ade6a3ff410c73ec34bf1b4f6bda38431bfede11cef1f7f6efa70e5f8063a3b1f6e17296ffb15feefa0912a0325b8d1fd65a559e717b5b961ec345072e0ec5203d03441d29af4d64054a04507410cf1da78e7b6119d909ec66e6ad625bf995b279a4b3c5be7d895cd7c5b9c4c497fde730916fcdb4e41b", 16).unwrap()
            ],
        )
    }

    #[test]
    fn test_encrypt_decrypt_oaep() {
        let mut rng = thread_rng();
        let priv_key = get_private_key();
        let k = priv_key.size();

        let mut oaep_options = OaepOptions::new();

        let hashers = [
            Hashes::SHA1,
            Hashes::SHA2_224,
            Hashes::SHA2_256,
            Hashes::SHA2_384,
            Hashes::SHA2_512,
            Hashes::SHA3_256,
            Hashes::SHA3_384,
            Hashes::SHA3_512,
        ];

        for i in 1..16 {
            let mut input: Vec<u8> = (0..i * 8).map(|_| rng.gen()).collect();
            if input.len() > k - 11 {
                input = input[0..k - 11].to_vec();
            }
            let hasher_idx: u32 = rng.gen();
            let has_label: bool = rng.gen();
            let label = if has_label {
                Some(rng.sample_iter(&Alphanumeric).take(30).collect())
            } else {
                None
            };

            oaep_options = oaep_options
                .set_hash(hashers[(hasher_idx as usize % hashers.len())])
                .set_label(label);

            let pub_key: RSAPublicKey = priv_key.clone().into();
            let ciphertext = encrypt(&mut rng, &pub_key, &input, oaep_options.clone()).unwrap();
            assert_ne!(input, ciphertext);
            let blind: bool = rng.gen();
            let blinder = if blind { Some(&mut rng) } else { None };
            let plaintext = decrypt(blinder, &priv_key, &ciphertext, oaep_options.clone()).unwrap();
            assert_eq!(input, plaintext);
        }
    }

    #[test]
    fn test_decrypt_oaep_invalid_hash() {
        let mut rng = thread_rng();
        let priv_key = get_private_key();
        let pub_key: RSAPublicKey = priv_key.clone().into();
        let mut oaep_options = OaepOptions::new();
        let ciphertext = encrypt(
            &mut rng,
            &pub_key,
            "a_plain_text".as_bytes(),
            oaep_options.clone(),
        )
        .unwrap();
        oaep_options = oaep_options.set_label(Some("a_label".to_owned()));
        assert!(
            decrypt(Some(&mut rng), &priv_key, &ciphertext, oaep_options.clone()).is_err(),
            "decrypt should have failed on hash verification"
        );
    }

}
