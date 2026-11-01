//! Side-channel-free decoding and selection for `draft-irtf-cfrg-rsa-guidance-10` §7.2.

use crypto_bigint::{Choice, CtAssign, CtEq, CtGt, CtSelect};

/// Step 3.3: select AL from the 128 big-endian candidate lengths CL.
///
/// `max_message_len` is the public bound k - 11, not k - 10.
pub(crate) fn select_al(cl: &[u8], max_message_len: u16) -> u16 {
    debug_assert_eq!(cl.len(), 256);
    let mut mask = max_message_len;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;

    // Zero the high bits, then keep the last admissible candidate (or zero).
    cl.chunks_exact(2).fold(0u16, |al, bytes| {
        let candidate = u16::from_be_bytes([bytes[0], bytes[1]]) & mask;
        al.ct_select(&candidate, !candidate.ct_gt(&max_message_len))
    })
}

/// Step 4: EME-PKCS1-v1_5 decoding, returning `(check, L)`.
///
/// `check` is set if any padding check fails. L is the length following the first zero separator,
/// or zero if no separator exists. Both remain secret.
///
/// The caller must establish the public bounds `11 <= k <= u32::MAX` and `em.len() == k`.
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    reason = "k fits in u32 by the public precondition"
)]
pub(crate) fn eme_pkcs1v15_decode(em: &[u8], k: usize) -> (Choice, u32) {
    debug_assert!(k >= 11);
    debug_assert_eq!(em.len(), k);
    debug_assert!(u32::try_from(k).is_ok());

    // EM = 0x00 || 0x02 || PS || 0x00 || M.
    let mut check = !em[0].ct_eq(&0u8) | !em[1].ct_eq(&2u8);
    let mut looking_for_separator = Choice::TRUE;
    let mut separator = 0u32;
    for (i, octet) in em.iter().enumerate().skip(2) {
        let is_zero = octet.ct_eq(&0u8);
        separator.ct_assign(&(i as u32), looking_for_separator & is_zero);
        looking_for_separator &= !is_zero;
    }

    // Always check for a separator and at least eight nonzero PS octets.
    check |= looking_for_separator | !separator.ct_gt(&9);
    let l = 0u32.ct_select(&(k as u32 - separator - 1), !looking_for_separator);
    (check, l)
}

/// Step 5: select the last AL octets of AM if check is set, otherwise the last L of EM.
///
/// Select the entire encoded buffer in place before exposing the final length. Both EM and AM are
/// read at every offset, independently of check, AL, and L. The caller may then expose the returned
/// length and copy that suffix of EM.
///
/// The buffers must have the same public length `k`; AL and L must be at most `k`.
#[inline]
pub(crate) fn select_message(em: &mut [u8], am: &[u8], al: u16, l: u32, check: Choice) -> u32 {
    debug_assert_eq!(em.len(), am.len());
    let length = l.ct_select(&u32::from(al), check);
    for (em_octet, am_octet) in em.iter_mut().zip(am) {
        em_octet.ct_assign(am_octet, check);
    }
    length
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_admissible_length() {
        let mut cl = [0xff; 256];
        cl[..2].copy_from_slice(&5u16.to_be_bytes());
        cl[252..254].copy_from_slice(&20u16.to_be_bytes());
        assert_eq!(select_al(&cl, 20), 20);
        cl[..2].fill(0xff);
        cl[252..254].fill(0xff);
        assert_eq!(select_al(&cl, 20), 0);
        assert_eq!(select_al(&cl, 0), 0);
    }

    #[test]
    fn every_separator_and_header() {
        const K: usize = 32;
        let am = [0xa5; K];
        // Includes missing separator, PS lengths 0..7, empty and maximum messages, and later zeros
        // which must not change the first separator's meaning.
        for header in [[0, 2], [1, 2], [0, 1], [1, 1], [0, 0]] {
            for separator in 2..=K {
                for later_zero in [false, true] {
                    let mut original = [0x42; K];
                    original[..2].copy_from_slice(&header);
                    if separator < K {
                        original[separator] = 0;
                        if later_zero {
                            original[K - 1] = 0;
                        }
                    }
                    let (check, l) = eme_pkcs1v15_decode(&original, K);
                    let invalid = header != [0, 2] || !(10..K).contains(&separator);
                    let expected_l = if separator < K { K - separator - 1 } else { 0 };
                    assert_eq!(check.to_bool(), invalid);
                    assert_eq!(l as usize, expected_l);
                    for al in [0, 1, 21] {
                        let mut em = original;
                        let length = select_message(&mut em, &am, al, l, check) as usize;
                        let expected = if invalid {
                            &am[K - usize::from(al)..]
                        } else {
                            &original[K - expected_l..]
                        };
                        assert_eq!(&em[K - length..], expected);
                    }
                }
            }
        }
    }

    #[test]
    fn minimum_modulus_length() {
        let em = [0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0];
        let (check, l) = eme_pkcs1v15_decode(&em, em.len());
        assert!(!check.to_bool());
        assert_eq!(l, 0);
    }
}
