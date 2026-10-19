//! PKCS#1 v1.5 support as described in [RFC8017 § 8.2].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pkcs1-v15-signatures).
//!
//! [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2

use alloc::vec::Vec;
use const_oid::AssociatedOid;
use crypto_bigint::{Choice, CtAssign, CtEq, CtGt, CtOption};
use digest::Digest;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

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
pub(crate) fn pkcs1v15_encrypt_unpad(em: &[u8], k: usize) -> Result<Vec<u8>> {
    if k < 11 || em.len() != k {
        return Err(Error::Decryption);
    }

    // TODO(tarcieri): padding validity is exposed here until implicit rejection is implemented.
    let index = decrypt_inner(em, k)
        .into_option()
        .ok_or(Error::Decryption)?;

    Ok(em[index as usize..].to_vec())
}

/// Checks EME-PKCS1-v1_5 encoding as described in [draft-irtf-cfrg-rsa-guidance-10 §7.2, step 4].
///
/// Returns the message's starting index in a [`CtOption`], present when the padding is valid.
/// Scans all of `em` regardless of padding validity, leaving the encoded message available to
/// the caller for subsequent message selection. Both the validity and index remain secret.
///
/// Callers must establish `k >= 11`, `em.len() == k`, and `k <= u32::MAX` before calling.
/// These public length preconditions are checked by debug assertions.
///
/// [draft-irtf-cfrg-rsa-guidance-10 §7.2, step 4]: https://www.ietf.org/archive/id/draft-irtf-cfrg-rsa-guidance-10.html#section-7.2
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    reason = "indices fit in u32 by the public length precondition"
)]
fn decrypt_inner(em: &[u8], k: usize) -> CtOption<u32> {
    debug_assert!(k >= 11);
    debug_assert_eq!(em.len(), k);
    debug_assert!(u32::try_from(k).is_ok());

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

    // PS starts at offset 2 and must contain at least 8 nonzero octets,
    // so the first zero separator must occur at offset 10 or later.
    let valid_ps = index.ct_gt(&9);
    let valid = first_byte_is_zero & second_byte_is_two & !looking_for_index & valid_ps;

    CtOption::new(index + 1, valid)
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
        ok &= el.ct_eq(&0xff);
    }

    // TODO(tarcieri): avoid branching here by e.g. using a pseudorandom rejection symbol
    if !ok.to_bool() {
        return Err(Error::Verification);
    }

    Ok(())
}

/// prefix = 0x30 <oid_len + 8 + digest_len> 0x30 <oid_len + 4> 0x06 <oid_len> oid 0x05 0x00 0x04 <digest_len>
#[inline]
#[allow(clippy::cast_possible_truncation, reason = "TODO")]
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

    #[test]
    fn test_decrypt_inner_minimum_padding() {
        let em = [0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 42];
        assert_eq!(decrypt_inner(&em, em.len()).into_option(), Some(11));
        assert_eq!(pkcs1v15_encrypt_unpad(&em, em.len()).unwrap(), [42]);

        // Seven PS octets must fail even when the total length is at least 11.
        let em = [0, 2, 1, 2, 3, 4, 5, 6, 7, 0, 42];
        assert!(decrypt_inner(&em, em.len()).is_none().to_bool());
        assert_eq!(
            pkcs1v15_encrypt_unpad(&em, em.len()),
            Err(Error::Decryption)
        );
    }

    #[test]
    fn test_decrypt_inner_empty_message() {
        let em = [0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0];
        assert_eq!(decrypt_inner(&em, em.len()).into_option(), Some(11));
        assert!(pkcs1v15_encrypt_unpad(&em, em.len()).unwrap().is_empty());
    }

    #[test]
    fn test_decrypt_inner_missing_delimiter() {
        let em = [0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert!(decrypt_inner(&em, em.len()).is_none().to_bool());
        assert_eq!(
            pkcs1v15_encrypt_unpad(&em, em.len()),
            Err(Error::Decryption)
        );
    }

    #[test]
    fn test_decrypt_inner_invalid_header() {
        for header in [[1, 2], [0, 1], [1, 1], [0, 0]] {
            let mut em = [0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 42];
            em[..2].copy_from_slice(&header);
            assert!(decrypt_inner(&em, em.len()).is_none().to_bool());
            assert_eq!(
                pkcs1v15_encrypt_unpad(&em, em.len()),
                Err(Error::Decryption)
            );
        }
    }

    #[test]
    fn test_decrypt_inner_first_delimiter() {
        // Zeros in the message do not change its starting index.
        let em = [0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 42, 0, 43];
        assert_eq!(decrypt_inner(&em, em.len()).into_option(), Some(11));
        assert_eq!(pkcs1v15_encrypt_unpad(&em, em.len()).unwrap(), [42, 0, 43]);

        // A later zero cannot rescue a PS that ended too early.
        let em = [0, 2, 1, 2, 3, 4, 5, 6, 7, 0, 8, 0, 42];
        assert!(decrypt_inner(&em, em.len()).is_none().to_bool());
        assert_eq!(
            pkcs1v15_encrypt_unpad(&em, em.len()),
            Err(Error::Decryption)
        );
    }

    #[test]
    fn test_unpad_invalid_lengths() {
        for k in 0..11 {
            assert_eq!(
                pkcs1v15_encrypt_unpad(&vec![0; k], k),
                Err(Error::Decryption)
            );
        }

        let em = [0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 42];
        for k in [em.len() - 1, em.len() + 1] {
            assert_eq!(pkcs1v15_encrypt_unpad(&em, k), Err(Error::Decryption));
        }
    }
}
