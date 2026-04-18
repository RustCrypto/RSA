//! PKCS#1 v1.5 support as described in [RFC8017 § 8.2].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pkcs1-v15-signatures).
//!
//! [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2

use alloc::{vec, vec::Vec};
use const_oid::AssociatedOid;
use crypto_bigint::{BoxedUint, Choice, CtEq};
use digest::{Digest, KeyInit};
use hmac::{Hmac, Mac};
use rand_core::TryCryptoRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::algorithms::pad::i2osp_modulus_width;
use crate::errors::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

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
#[inline]
pub(crate) fn pkcs1v15_encrypt_unpad(
    em: &[u8],
    d: &BoxedUint,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if em.len() < 11 {
        return Err(Error::Decryption);
    }

    let k = em.len();
    let kdk = derive_kdk(d, k, ciphertext)?;
    let candidate_lengths = irprf_sha256_hmac(&kdk, b"length", 256)?;
    let alt_len = select_alt_len_ct(candidate_lengths.as_ref(), (k - 11) as u32);
    let alt_message = irprf_sha256_hmac(&kdk, b"message", k)?;
    let scan = scan_pkcs1v15_encryption_block(em);

    Ok(select_message_ct(
        em,
        alt_message.as_ref(),
        scan.real_len,
        alt_len,
        scan.valid,
    ))
}

#[inline]
fn derive_kdk(d: &BoxedUint, k: usize, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if ciphertext.len() > k {
        return Err(Error::Decryption);
    }

    let d_bytes = i2osp_modulus_width(d, k);
    let dh = Sha256::digest(d_bytes.as_slice());
    let mut padded_ciphertext = Zeroizing::new(vec![0u8; k]);
    padded_ciphertext[k - ciphertext.len()..].copy_from_slice(ciphertext);

    let mut mac = HmacSha256::new_from_slice(dh.as_ref()).map_err(|_| Error::Internal)?;
    mac.update(padded_ciphertext.as_slice());

    let mut kdk = Zeroizing::new([0u8; 32]);
    kdk.copy_from_slice(&mac.finalize().into_bytes());
    Ok(kdk)
}

#[inline]
fn irprf_sha256_hmac(kdk: &[u8; 32], label: &[u8], out_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    if out_len >= 8192 {
        return Err(Error::ModulusTooLarge);
    }

    let bit_len = out_len.checked_mul(8).ok_or(Error::ModulusTooLarge)?;
    let bit_len = u16::try_from(bit_len).map_err(|_| Error::ModulusTooLarge)?;
    let mut out = Zeroizing::new(Vec::with_capacity(out_len + 32));
    let mut counter = 0u16;

    while out.len() < out_len {
        let mut mac = HmacSha256::new_from_slice(kdk).map_err(|_| Error::Internal)?;
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&bit_len.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
        counter = counter.checked_add(1).ok_or(Error::Internal)?;
    }

    out.truncate(out_len);
    Ok(out)
}

#[derive(Clone, Copy, Debug)]
struct ScanResult {
    valid: Choice,
    real_len: u32,
}

#[inline]
fn select_alt_len_ct(cl: &[u8], max_msg_len: u32) -> u32 {
    debug_assert_eq!(cl.len(), 256);

    let max_bits = u32::BITS - max_msg_len.leading_zeros();
    let mask = if max_bits == 0 {
        0
    } else if max_bits >= u32::BITS {
        u32::MAX
    } else {
        (1u32 << max_bits) - 1
    };

    cl.chunks_exact(2).fold(0u32, |selected, candidate| {
        let candidate = u16::from_be_bytes([candidate[0], candidate[1]]) as u32 & mask;
        let within_range = Choice::from_u32_le(candidate, max_msg_len);
        within_range.select_u32(selected, candidate)
    })
}

#[inline]
fn scan_pkcs1v15_encryption_block(em: &[u8]) -> ScanResult {
    if em.len() < 11 {
        return ScanResult {
            valid: Choice::FALSE,
            real_len: 0,
        };
    }

    let prefix_ok = em[0].ct_eq(&0u8) & em[1].ct_eq(&2u8);
    let mut searching = Choice::TRUE;
    let mut found_sep = Choice::FALSE;
    let mut sep_index = 0u32;

    for (i, byte) in em.iter().enumerate().skip(2) {
        let is_zero = byte.ct_eq(&0u8);
        let capture = searching & is_zero;
        sep_index = capture.select_u32(sep_index, i as u32);
        found_sep |= is_zero;
        searching &= !is_zero;
    }

    let real_len = found_sep.select_u32(0, em.len() as u32 - (sep_index + 1));
    let ps_len = found_sep.select_u32(0, sep_index.wrapping_sub(2));
    let valid = prefix_ok & found_sep & Choice::from_u32_le(8, ps_len);

    ScanResult { valid, real_len }
}

#[inline]
fn clamp_len(len: u32, max_msg_len: u32) -> u32 {
    Choice::from_u32_lt(max_msg_len, len).select_u32(len, max_msg_len)
}

#[inline]
fn gather_message_byte_ct(tail: &[u8], start: u32, len: u32, index: u32) -> u8 {
    let mut selected = 0u8;
    let in_range = Choice::from_u32_lt(index, len);
    let target = start.wrapping_add(index);

    for (source_index, &byte) in tail.iter().enumerate() {
        let source_index = source_index as u32;
        let take = in_range & source_index.ct_eq(&target);
        selected = take.select_u8(selected, byte);
    }

    selected
}

#[inline]
fn select_message_ct(em: &[u8], am: &[u8], real_len: u32, alt_len: u32, valid: Choice) -> Vec<u8> {
    debug_assert_eq!(em.len(), am.len());
    debug_assert!(em.len() >= 11);

    let max_msg_len = (em.len() - 11) as u32;
    let real_len = clamp_len(real_len, max_msg_len);
    let alt_len = clamp_len(alt_len, max_msg_len);
    let selected_len = valid.select_u32(alt_len, real_len) as usize;
    let tail = max_msg_len as usize;
    let em_tail = &em[11..];
    let am_tail = &am[11..];
    let em_start = max_msg_len.wrapping_sub(real_len);
    let am_start = max_msg_len.wrapping_sub(alt_len);
    let mut out = vec![0u8; tail];

    for (i, out_byte) in out.iter_mut().enumerate() {
        let index = i as u32;
        let em_byte = gather_message_byte_ct(em_tail, em_start, real_len, index);
        let am_byte = gather_message_byte_ct(am_tail, am_start, alt_len, index);
        *out_byte = valid.select_u8(am_byte, em_byte);
    }

    out.truncate(selected_len);
    out
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

    #[test]
    fn test_select_alt_len_ct_uses_last_candidate_within_range() {
        let mut cl = [0xffu8; 256];
        cl[0..2].copy_from_slice(&15u16.to_be_bytes());
        cl[2..4].copy_from_slice(&9u16.to_be_bytes());
        cl[4..6].copy_from_slice(&3u16.to_be_bytes());

        assert_eq!(select_alt_len_ct(&cl, 10), 3);
    }

    #[test]
    fn test_select_alt_len_ct_handles_full_u32_mask() {
        let cl = [0xffu8; 256];

        assert_eq!(select_alt_len_ct(&cl, u32::MAX), 0xffff);
    }

    #[test]
    fn test_irprf_sha256_hmac_rejects_8192_octets() {
        let kdk = [0u8; 32];

        assert_eq!(
            irprf_sha256_hmac(&kdk, b"message", 8192),
            Err(Error::ModulusTooLarge)
        );
    }

    #[test]
    fn test_scan_pkcs1v15_encryption_block_valid() {
        let em = [
            0x00, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
        ];
        let scan = scan_pkcs1v15_encryption_block(&em);

        assert!(bool::from(scan.valid));
        assert_eq!(scan.real_len, 1);
    }

    #[test]
    fn test_scan_pkcs1v15_encryption_block_missing_separator() {
        let em = [
            0x00, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let scan = scan_pkcs1v15_encryption_block(&em);

        assert!(!bool::from(scan.valid));
        assert_eq!(scan.real_len, 0);
    }

    #[test]
    fn test_select_message_ct_returns_valid_message_bytes() {
        let em = [0u8, 2, 9, 9, 9, 9, 9, 9, 9, 9, 0, 0xaa, 0xbb];
        let am = [0u8, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0xcc, 0xdd];

        let out = select_message_ct(&em, &am, 2, 2, Choice::TRUE);

        assert_eq!(out, vec![0xaa, 0xbb]);
    }

    #[test]
    fn test_select_message_ct_returns_rejection_symbol_bytes() {
        let em = [0u8, 2, 9, 9, 9, 9, 9, 9, 9, 9, 0, 0xaa, 0xbb];
        let am = [0u8, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0xcc, 0xdd];

        let out = select_message_ct(&em, &am, 2, 2, Choice::FALSE);

        assert_eq!(out, vec![0xcc, 0xdd]);
    }
}
