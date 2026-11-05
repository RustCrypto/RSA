//! Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
//!
use alloc::boxed::Box;
use alloc::vec::Vec;

use crypto_bigint::{Choice, CtAssign, CtEq, CtOption};
use digest::{Digest, FixedOutputReset};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use super::mgf::{mgf1_xor, mgf1_xor_digest};
use crate::errors::{Error, Result};

/// Maximum label size (2^64 bits) for SHA-1 and SHA-256 hash functions.
///
/// In theory, other hash functions (e.g. SHA-512 and SHA-3) can process longer labels,
/// but such huge inputs are practically impossible on one machine, so we use this limit
/// for all hash functions.
const MAX_LABEL_LEN: u64 = 1 << 61;

#[inline]
fn encrypt_internal<R: TryCryptoRng + ?Sized, MGF: FnMut(&mut [u8], &mut [u8])>(
    rng: &mut R,
    msg: &[u8],
    p_hash: &[u8],
    h_size: usize,
    k: usize,
    mut mgf: MGF,
) -> Result<Zeroizing<Vec<u8>>> {
    if msg.len() + 2 * h_size + 2 > k {
        return Err(Error::MessageTooLong);
    }

    let mut em = Zeroizing::new(vec![0u8; k]);

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h_size);
    rng.try_fill_bytes(seed).map_err(|_| Error::Rng)?;

    // Data block DB =  pHash || PS || 01 || M
    let db_len = k - h_size - 1;

    db[0..h_size].copy_from_slice(p_hash);
    db[db_len - msg.len() - 1] = 1;
    db[db_len - msg.len()..].copy_from_slice(msg);

    mgf(seed, db);

    Ok(em)
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
pub(crate) fn oaep_encrypt<R, D, MGD>(
    rng: &mut R,
    msg: &[u8],
    digest: &mut D,
    mgf_digest: &mut MGD,
    label: Option<Box<[u8]>>,
    k: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    R: TryCryptoRng + ?Sized,
    D: Digest + FixedOutputReset,
    MGD: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    Digest::update(digest, &label);
    let p_hash = digest.finalize_reset();

    encrypt_internal(rng, msg, &p_hash, h_size, k, |seed, db| {
        mgf1_xor(db, mgf_digest, seed);
        mgf1_xor(seed, mgf_digest, db);
    })
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
pub(crate) fn oaep_encrypt_digest<R, D, MGD>(
    rng: &mut R,
    msg: &[u8],
    label: Option<Box<[u8]>>,
    k: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    R: TryCryptoRng + ?Sized,
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    let p_hash = D::digest(&label);

    encrypt_internal(rng, msg, &p_hash, h_size, k, |seed, db| {
        let mut mgf_digest = MGD::new();
        mgf1_xor_digest(db, &mut mgf_digest, seed);
        mgf1_xor_digest(seed, &mut mgf_digest, db);
    })
}

///Decrypts OAEP padding.
///
/// Note that whether this function returns an error or not discloses secret
/// information. If an attacker can cause this function to run repeatedly and
/// learn whether each instance returned an error then they can decrypt and
/// forge signatures as if they had the private key.
///
/// See `decrypt_session_key` for a way of solving this problem.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
pub(crate) fn oaep_decrypt<D, MGD>(
    em: &mut [u8],
    digest: &mut D,
    mgf_digest: &mut MGD,
    label: Option<Box<[u8]>>,
    k: usize,
) -> Result<Vec<u8>>
where
    D: Digest + FixedOutputReset,
    MGD: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::Decryption);
    }

    Digest::update(digest, &label);

    let expected_p_hash = digest.finalize_reset();

    let res = decrypt_inner(em, h_size, &expected_p_hash, k, |seed, db| {
        mgf1_xor(seed, mgf_digest, db);
        mgf1_xor(db, mgf_digest, seed);
    })?;
    if res.is_none().into() {
        return Err(Error::Decryption);
    }

    let index = res.unwrap();

    Ok(em[index as usize..].to_vec())
}

///Decrypts OAEP padding.
///
/// Note that whether this function returns an error or not discloses secret
/// information. If an attacker can cause this function to run repeatedly and
/// learn whether each instance returned an error then they can decrypt and
/// forge signatures as if they had the private key.
///
/// See `decrypt_session_key` for a way of solving this problem.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
pub(crate) fn oaep_decrypt_digest<D, MGD>(
    em: &mut [u8],
    label: Option<Box<[u8]>>,
    k: usize,
) -> Result<Vec<u8>>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    let expected_p_hash = D::digest(&label);

    let res = decrypt_inner(em, h_size, &expected_p_hash, k, |seed, db| {
        let mut mgf_digest = MGD::new();
        mgf1_xor_digest(seed, &mut mgf_digest, db);
        mgf1_xor_digest(db, &mut mgf_digest, seed);
    })?;
    if res.is_none().into() {
        return Err(Error::Decryption);
    }

    let index = res.unwrap();

    Ok(em[index as usize..].to_vec())
}

/// Decrypts OAEP padding. It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured.
#[inline]
fn decrypt_inner<MGF: FnMut(&mut [u8], &mut [u8])>(
    em: &mut [u8],
    h_size: usize,
    expected_p_hash: &[u8],
    k: usize,
    mut mgf: MGF,
) -> Result<CtOption<u32>> {
    if k < 11 {
        return Err(Error::Decryption);
    }

    if k < h_size * 2 + 2 {
        return Err(Error::Decryption);
    }

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h_size);

    mgf(seed, db);

    let hash_are_equal = db[0..h_size].ct_eq(expected_p_hash);

    // The remainder of the plaintext must be zero or more 0x00, followed
    // by 0x01, followed by the message.
    //   looking_for_index: 1 if we are still looking for the 0x01
    //   index: the offset of the first 0x01 byte
    //   zero_before_one: 1 if we saw a non-zero byte before the 1
    let mut looking_for_index = Choice::TRUE;
    let mut index = 0u32;
    let mut nonzero_before_one = Choice::FALSE;

    #[allow(clippy::cast_possible_truncation, reason = "TODO")]
    for (i, el) in db.iter().skip(h_size).enumerate() {
        let equals0 = el.ct_eq(&0u8);
        let equals1 = el.ct_eq(&1u8);
        index.ct_assign(&(i as u32), looking_for_index & equals1);
        looking_for_index &= !equals1;
        nonzero_before_one |= looking_for_index & !equals0;
    }

    let valid = hash_are_equal & !nonzero_before_one & !looking_for_index;

    #[allow(clippy::cast_possible_truncation, reason = "TODO")]
    Ok(CtOption::new(index + 2 + (h_size * 2) as u32, valid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ChaCha8Rng;
    use rand_core::SeedableRng;
    use sha1::Sha1;
    use sha2::Sha256;

    #[test]
    fn decrypt_ignores_first_octet() {
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let k = 128;
        let label = b"label";

        // Empty, short, and maximum-length messages exercise both ends of DB.
        for msg_len in [0, 1, k - 2 * <Sha256 as Digest>::output_size() - 2] {
            let msg = vec![0x42; msg_len];
            let em = oaep_encrypt_digest::<_, Sha256, Sha1>(
                &mut rng,
                &msg,
                Some(label.as_slice().into()),
                k,
            )
            .unwrap();
            assert_eq!(em[0], 0);

            for first_octet in 0..=u8::MAX {
                let mut encoded = em.to_vec();
                encoded[0] = first_octet;

                assert_eq!(
                    oaep_decrypt(
                        &mut encoded.clone(),
                        &mut Sha256::new(),
                        &mut Sha1::new(),
                        Some(label.as_slice().into()),
                        k,
                    ),
                    Ok(msg.clone()),
                );
                assert_eq!(
                    oaep_decrypt_digest::<Sha256, Sha1>(
                        &mut encoded,
                        Some(label.as_slice().into()),
                        k,
                    ),
                    Ok(msg.clone()),
                );
            }
        }
    }

    #[test]
    fn decrypt_rejects_invalid_db() {
        let h_size = <Sha256 as Digest>::output_size();
        let p_hash = Sha256::digest(b"");
        let mut em = [0u8; 128];
        em[1 + h_size..1 + 2 * h_size].copy_from_slice(&p_hash);
        let separator = em.len() - 1;
        em[separator] = 1;

        for first_octet in [0, 1, 0xff] {
            em[0] = first_octet;

            // Wrong label hash, nonzero PS, missing separator, wrong separator.
            for (index, value) in [
                (1 + h_size, p_hash[0] ^ 1),
                (1 + 2 * h_size, 2),
                (separator, 0),
                (separator, 2),
            ] {
                let mut invalid = em;
                invalid[index] = value;
                let result =
                    decrypt_inner(&mut invalid, h_size, &p_hash, em.len(), |_, _| {}).unwrap();

                assert!(result.is_none().to_bool());
            }
        }
    }
}
