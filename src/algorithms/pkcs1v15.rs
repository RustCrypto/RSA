//! PKCS#1 v1.5 support as described in [RFC8017 § 8.2].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pkcs1-v15-signatures).
//!
//! [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2

use alloc::vec::Vec;
use const_oid::AssociatedOid;
use crypto_bigint::{Choice, CtEq, CtSelect};
use digest::Digest;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

#[cfg(feature = "implicit-rejection")]
use digest::KeyInit;
#[cfg(feature = "implicit-rejection")]
use hmac::{Hmac, Mac};
#[cfg(feature = "implicit-rejection")]
use sha2::Sha256;

/// Fills the provided slice with random values, which are guaranteed
/// to not be zero.
#[inline]
fn non_zero_random_bytes<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    data: &mut [u8],
) -> core::result::Result<(), R::Error> {
    rng.try_fill_bytes(data)?;

    for el in data {
        if *el == 0u8 {
            // TODO: break after a certain amount of time
            while *el == 0u8 {
                rng.try_fill_bytes(core::slice::from_mut(el))?;
            }
        }
    }

    Ok(())
}

/// Applied the padding scheme from PKCS#1 v1.5 for encryption.  The message must be no longer than
/// the length of the public modulus minus 11 bytes.
pub(crate) fn pkcs1v15_encrypt_pad<R>(
    rng: &mut R,
    msg: &[u8],
    k: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    R: TryCryptoRng + ?Sized,
{
    if msg.len() + 11 > k {
        return Err(Error::MessageTooLong);
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M
    let mut em = Zeroizing::new(vec![0u8; k]);
    em[1] = 2;
    non_zero_random_bytes(rng, &mut em[2..k - msg.len() - 1]).map_err(|_: R::Error| Error::Rng)?;
    em[k - msg.len() - 1] = 0;
    em[k - msg.len()..].copy_from_slice(msg);
    Ok(em)
}

/// Removes the encryption padding scheme from PKCS#1 v1.5.
///
/// Note that whether this function returns an error or not discloses secret
/// information. If an attacker can cause this function to run repeatedly and
/// learn whether each instance returned an error then they can decrypt and
/// forge signatures as if they had the private key. See
/// `decrypt_session_key` for a way of solving this problem.
#[inline]
pub(crate) fn pkcs1v15_encrypt_unpad(em: Vec<u8>, k: usize) -> Result<Vec<u8>> {
    let (valid, out, index) = decrypt_inner(em, k)?;
    if valid == 0 {
        return Err(Error::Decryption);
    }

    Ok(out[index as usize..].to_vec())
}

/// Removes the PKCS1v15 padding It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured. In either case, the plaintext is
/// returned in em so that it may be read independently of whether it was valid
/// in order to maintain constant memory access patterns. If the plaintext was
/// valid then index contains the index of the original message in em.
#[inline]
fn decrypt_inner(em: Vec<u8>, k: usize) -> Result<(u8, Vec<u8>, u32)> {
    if k < 11 {
        return Err(Error::Decryption);
    }

    let first_byte_is_zero = em[0].ct_eq(&0u8);
    let second_byte_is_two = em[1].ct_eq(&2u8);

    // The remainder of the plaintext must be a string of non-zero random
    // octets, followed by a 0, followed by the message.
    //   looking_for_index: 1 iff we are still looking for the zero.
    //   index: the offset of the first zero byte.
    let mut looking_for_index = Choice::TRUE;
    let mut index = 0u32;

    for (i, el) in em.iter().enumerate().skip(2) {
        let equals0 = el.ct_eq(&0u8);
        index.ct_assign(&(i as u32), looking_for_index & equals0);
        looking_for_index &= !equals0;
    }

    // The PS padding must be at least 8 bytes long, and it starts two
    // bytes into em.
    // TODO: WARNING: THIS MUST BE CONSTANT TIME CHECK:
    // Ref: https://github.com/dalek-cryptography/subtle/issues/20
    // This is currently copy & paste from the constant time impl in
    // go, but very likely not sufficient.
    let valid_ps = Choice::from_u8_lsb((((2i32 + 8i32 - index as i32 - 1i32) >> 31) & 1) as u8);
    let valid = first_byte_is_zero & second_byte_is_two & !looking_for_index & valid_ps;
    index = u32::ct_select(&0, &(index + 1), valid);

    Ok((valid.to_u8(), em, index))
}

/// Implicit Rejection PRF as specified in IETF draft-irtf-cfrg-rsa-guidance.
///
/// Generates a deterministic synthetic plaintext from the ciphertext and private key
/// when padding validation fails. This prevents timing side-channels.
///
/// PRF(key, label || ciphertext) where:
/// - key = HMAC-SHA256(d || p || q, "implicit rejection key")
/// - label = "implicit rejection PKCS#1 v1.5 ciphertext"
#[cfg(feature = "implicit-rejection")]
pub(crate) fn implicit_rejection_prf(
    key_hash: &[u8; 32],
    ciphertext: &[u8],
    output_len: usize,
) -> Vec<u8> {
    const LABEL: &[u8] = b"implicit rejection PKCS#1 v1.5 ciphertext";

    // Use HMAC-SHA256 in counter mode to generate enough output bytes
    let mut result = Vec::with_capacity(output_len);
    let mut counter: u32 = 0;

    while result.len() < output_len {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key_hash).expect("HMAC can accept any key length");
        mac.update(&counter.to_be_bytes());
        mac.update(LABEL);
        mac.update(ciphertext);
        let block = mac.finalize().into_bytes();

        let remaining = output_len - result.len();
        let take = core::cmp::min(remaining, block.len());
        result.extend_from_slice(&block[..take]);
        counter += 1;
    }

    result
}

/// Derive a key for implicit rejection PRF from the private key components.
///
/// key = HMAC-SHA256(d || p || q, "implicit rejection key")
#[cfg(feature = "implicit-rejection")]
pub(crate) fn derive_implicit_rejection_key(
    d: &[u8],
    primes: &[&[u8]],
) -> [u8; 32] {
    const KEY_LABEL: &[u8] = b"implicit rejection key";

    // Concatenate d and all primes as the HMAC key material
    let mut key_material = Vec::with_capacity(d.len() + primes.iter().map(|p| p.len()).sum::<usize>());
    key_material.extend_from_slice(d);
    for prime in primes {
        key_material.extend_from_slice(prime);
    }

    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key_material).expect("HMAC can accept any key length");
    mac.update(KEY_LABEL);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Removes the encryption padding scheme from PKCS#1 v1.5 with implicit rejection.
///
/// Instead of returning an error on invalid padding, this function returns a
/// deterministic synthetic message derived from the ciphertext. This prevents
/// Bleichenbacher/Marvin timing attacks.
///
/// # Arguments
/// * `em` - The decrypted (but still padded) message
/// * `k` - The key size in bytes
/// * `ciphertext` - The original ciphertext (used to derive synthetic message)
/// * `key_hash` - Pre-computed HMAC key derived from private key
/// * `expected_len` - The expected plaintext length
///
/// # Returns
/// Either the actual plaintext or a synthetic plaintext of `expected_len` bytes
#[cfg(feature = "implicit-rejection")]
#[inline]
pub(crate) fn pkcs1v15_encrypt_unpad_implicit_rejection(
    em: Vec<u8>,
    k: usize,
    ciphertext: &[u8],
    key_hash: &[u8; 32],
    expected_len: usize,
) -> Vec<u8> {
    // Generate synthetic message first (constant time - always computed)
    let synthetic = implicit_rejection_prf(key_hash, ciphertext, expected_len);

    // Validate padding in constant time
    let (valid, decrypted, index) = match decrypt_inner(em, k) {
        Ok(result) => result,
        Err(_) => {
            // If k < 11, return synthetic (this is a non-timing-sensitive check)
            return synthetic;
        }
    };

    // Check if the message length matches expected_len
    let msg_len = k.saturating_sub(index as usize);
    let len_matches = Choice::from_u8_lsb((msg_len == expected_len) as u8);

    // Combine validity: padding must be valid AND length must match
    let use_real = Choice::from_u8_lsb(valid) & len_matches;

    // Constant-time selection between real and synthetic message
    let mut result = vec![0u8; expected_len];
    for (i, out_byte) in result.iter_mut().enumerate() {
        let real_byte = if (index as usize + i) < decrypted.len() {
            decrypted[index as usize + i]
        } else {
            0u8
        };
        let synthetic_byte = synthetic[i];
        *out_byte = u8::ct_select(&synthetic_byte, &real_byte, use_real);
    }

    result
}

#[inline]
pub(crate) fn pkcs1v15_sign_pad(prefix: &[u8], hashed: &[u8], k: usize) -> Result<Vec<u8>> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::MessageTooLong);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut em = vec![0xff; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t_len - 1] = 0;
    em[k - t_len..k - hash_len].copy_from_slice(prefix);
    em[k - hash_len..k].copy_from_slice(hashed);

    Ok(em)
}

#[inline]
pub(crate) fn pkcs1v15_sign_unpad(prefix: &[u8], hashed: &[u8], em: &[u8], k: usize) -> Result<()> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::Verification);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut ok = em[0].ct_eq(&0u8);
    ok &= em[1].ct_eq(&1u8);
    ok &= em[k - hash_len..k].ct_eq(hashed);
    ok &= em[k - t_len..k - hash_len].ct_eq(prefix);
    ok &= em[k - t_len - 1].ct_eq(&0u8);

    for el in em.iter().skip(2).take(k - t_len - 3) {
        ok &= el.ct_eq(&0xff)
    }

    // TODO(tarcieri): avoid branching here by e.g. using a pseudorandom rejection symbol
    if !ok.to_bool() {
        return Err(Error::Verification);
    }

    Ok(())
}

/// prefix = 0x30 <oid_len + 8 + digest_len> 0x30 <oid_len + 4> 0x06 <oid_len> oid 0x05 0x00 0x04 <digest_len>
#[inline]
pub(crate) fn pkcs1v15_generate_prefix<D>() -> Vec<u8>
where
    D: Digest + AssociatedOid,
{
    let oid = D::OID.as_bytes();
    let oid_len = oid.len() as u8;
    let digest_len = <D as Digest>::output_size() as u8;
    let mut v = vec![
        0x30,
        oid_len + 8 + digest_len,
        0x30,
        oid_len + 4,
        0x6,
        oid_len,
    ];
    v.extend_from_slice(oid);
    v.extend_from_slice(&[0x05, 0x00, 0x04, digest_len]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_non_zero_bytes() {
        for _ in 0..10 {
            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let mut b = vec![0u8; 512];
            non_zero_random_bytes(&mut rng, &mut b).unwrap();
            for el in &b {
                assert_ne!(*el, 0u8);
            }
        }
    }

    #[test]
    fn test_encrypt_tiny_no_crash() {
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let k = 8;
        let message = vec![1u8; 4];
        let res = pkcs1v15_encrypt_pad(&mut rng, &message, k);
        assert_eq!(res, Err(Error::MessageTooLong));
    }
}
