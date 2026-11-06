//! Exponent and CRT modulus blinding for RSA private operations.

use super::reduction::to_monty;
use crypto_bigint::{
    BoxedUint, ConcatenatingMul, Odd, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// Return `exponent + b * totient` for a fresh, uniformly random 128-bit `b`.
///
/// This meets the minimum of 64 bits or two machine words in CFRG RSA guidance §6.4
/// on both 32-bit and 64-bit targets. All arithmetic uses public storage precisions.
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-rsa-guidance-10.html#section-6.4>
pub(crate) fn blind_exponent<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    exponent: &BoxedUint,
    totient: &BoxedUint,
) -> Result<Zeroizing<BoxedUint>> {
    let mut bytes = Zeroizing::new([0u8; 16]);
    rng.try_fill_bytes(bytes.as_mut()).map_err(|_| Error::Rng)?;
    let b =
        Zeroizing::new(BoxedUint::from_le_slice(bytes.as_ref(), 128).map_err(|_| Error::Internal)?);

    let bits = exponent.bits_precision().max(totient.bits_precision());
    let totient = Zeroizing::new(totient.resize_unchecked(bits));
    let mut blinded = Zeroizing::new(totient.concatenating_mul(&*b));
    // Both inputs are below 2^bits, so b * totient + exponent fits in bits + 128 bits.
    blinded.wrapping_add_assign(exponent);
    Ok(blinded)
}

/// Multiply a CRT prime by a fresh random odd factor, using public storage widths.
///
/// With `r` uniform over 128 bits, `g = 2*r + 1` is positive and odd and retains all
/// 128 bits of randomness. Odd factors permit Montgomery arithmetic without rejection sampling.
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-rsa-guidance-10.html#section-6.5>
pub(crate) fn blind_modulus<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    prime: &Odd<BoxedUint>,
) -> Result<Odd<BoxedUint>> {
    let mut bytes = Zeroizing::new([0u8; 16]);
    rng.try_fill_bytes(bytes.as_mut()).map_err(|_| Error::Rng)?;
    // Reserve the extra bit before doubling, including when every random byte is 0xff.
    let mut g =
        Zeroizing::new(BoxedUint::from_le_slice(bytes.as_ref(), 129).map_err(|_| Error::Internal)?);
    g.shl_assign(1);
    g.wrapping_add_assign(BoxedUint::one());
    Odd::new(prime.concatenating_mul(&*g))
        .into_option()
        .ok_or(Error::Internal)
}

/// Exponentiate modulo a fresh multiple of `p`, then return the residue modulo `p`.
///
/// `exponent` may already be blinded using a multiple of `p - 1`. Reduce back to `p`
/// before CRT recombination, whose precomputed coefficient uses the original primes.
pub(crate) fn pow_mod_blinded<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    base: &BoxedUint,
    exponent: &BoxedUint,
    p: &BoxedMontyParams,
) -> Result<BoxedMontyForm> {
    let params = BoxedMontyParams::new(blind_modulus(rng, p.modulus())?);
    let base = Zeroizing::new(to_monty(base, &params));
    let powered = Zeroizing::new(base.pow(exponent));
    let residue = Zeroizing::new(powered.retrieve());
    Ok(to_monty(&residue, p))
}

/// Compute φ(n) = ∏(p_i - 1) at the public modulus precision for non-CRT operations.
///
/// The factors must belong to a valid RSA key; then every partial product is below n.
pub(crate) fn totient(primes: &[Odd<BoxedUint>], bits: u32) -> Result<Zeroizing<BoxedUint>> {
    if primes.len() < 2 {
        return Err(Error::NprimesTooSmall);
    }

    let mut totient = Zeroizing::new(BoxedUint::one_with_precision(bits));
    for prime in primes {
        let pm1 = Zeroizing::new(prime.wrapping_sub(BoxedUint::one()));
        totient = Zeroizing::new(totient.wrapping_mul(&*pm1));
    }
    Ok(totient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PrivateKey,
        algorithms::rsa::rsa_decrypt_and_check,
        traits::{PrivateKeyParts, PublicKeyParts},
    };
    use alloc::{collections::VecDeque, vec::Vec};
    use rand_core::TryRng;

    struct MockRng(VecDeque<Vec<u8>>);

    impl TryRng for MockRng {
        type Error = core::fmt::Error;

        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> core::result::Result<(), Self::Error> {
            let next = self.0.pop_front().ok_or(core::fmt::Error)?;
            bytes.copy_from_slice(&next);
            Ok(())
        }
    }

    impl TryCryptoRng for MockRng {}

    #[test]
    fn exponent_blinding_arithmetic() {
        for (exponent_bits, totient_bits) in [(64, 64), (64, 128), (128, 64)] {
            let exponent = BoxedUint::from(17u64).resize_unchecked(exponent_bits);
            let phi = BoxedUint::from(60u64).resize_unchecked(totient_bits);
            let bits = exponent_bits.max(totient_bits) + 128;

            let mut rng = MockRng(
                [0u128, 1, u128::MAX]
                    .map(|b| b.to_le_bytes().to_vec())
                    .into(),
            );

            for expected in [
                (&exponent).resize_unchecked(bits),
                BoxedUint::from(77u64).resize_unchecked(bits),
                // 17 + (2^128 - 1) * 60 = 60 * 2^128 - 43.
                (&phi)
                    .resize_unchecked(bits)
                    .shl(128)
                    .wrapping_sub(BoxedUint::from(43u64)),
            ] {
                let blinded = blind_exponent(&mut rng, &exponent, &phi).expect("blinded exponent");
                assert_eq!(*blinded, expected);
                assert_eq!(blinded.bits_precision(), bits);
            }

            assert!(rng.0.is_empty());
        }

        // Maximum values exercise the carry into the widened exponent's highest limb.
        let max = BoxedUint::max(128);
        let mut rng = MockRng([vec![0xff; 16]].into());
        let blinded = blind_exponent(&mut rng, &max, &max).expect("blinded exponent");

        assert_eq!(*blinded, max.resize_unchecked(256).shl(128));
        assert_eq!(blinded.bits_precision(), 256);
    }

    #[test]
    fn modulus_blinding_arithmetic() {
        for bits in [64, 128, 192] {
            let prime = Odd::new(BoxedUint::max(bits)).expect("odd modulus");
            let blinded_bits = bits + BoxedUint::zero_with_precision(129).bits_precision();
            let p = prime.as_ref().resize_unchecked(blinded_bits);
            let mut rng = MockRng(
                [0u128, 1, u128::MAX]
                    .map(|r| r.to_le_bytes().to_vec())
                    .into(),
            );
            for expected in [
                p.clone(),
                p.shl(1).wrapping_add(&p),
                p.shl(129).wrapping_sub(&p),
            ] {
                let blinded = blind_modulus(&mut rng, &prime).expect("blinded modulus");
                assert_eq!(blinded.as_ref(), &expected);
                assert_eq!(blinded.bits_precision(), blinded_bits);
            }
            assert!(rng.0.is_empty());
        }
    }

    #[test]
    fn modulus_blinding_reduces_to_original_prime() {
        // Exercise inputs both narrower and wider than the blinded modulus, and primes whose
        // values are much smaller than their storage widths (as in unbalanced RSA keys).
        for bits in [64, 128, 192] {
            let p = Odd::new(BoxedUint::from(53u64).resize_unchecked(bits)).expect("prime");
            let params = BoxedMontyParams::new(p);
            for base_bits in [64, 512] {
                for base in [
                    BoxedUint::max(base_bits),
                    BoxedUint::zero_with_precision(base_bits),
                ] {
                    for exponent in [0u64, 17] {
                        let exponent = BoxedUint::from(exponent);
                        let expected = to_monty(&base, &params).pow(&exponent).retrieve();
                        // r=26 makes g=p=53, so this also covers a factor sharing the prime.
                        for r in [0u128, 26, u128::MAX] {
                            let mut rng = MockRng([r.to_le_bytes().to_vec()].into());
                            let actual = pow_mod_blinded(&mut rng, &base, &exponent, &params)
                                .expect("blinded exponentiation");
                            assert_eq!(actual.retrieve(), expected);
                            assert_eq!(actual.bits_precision(), bits);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn blinding_private_operations() {
        let two_prime =
            PrivateKey::from_p_q(61u64.into(), 53u64.into(), 17u64.into()).expect("two-prime key");
        let multi_prime =
            PrivateKey::from_primes(vec![61u64.into(), 53u64.into(), 47u64.into()], 17u64.into())
                .expect("multiprime key");

        for mut key in [two_prime, multi_prime] {
            for clear_precomputed in [false, true] {
                if clear_precomputed {
                    key.clear_precomputed();
                }

                let crt = key.dp().is_some() && key.primes().len() == 2;
                let bits = key.n_bits_precision();

                for c in [
                    BoxedUint::zero_with_precision(bits),
                    BoxedUint::one_with_precision(bits),
                    BoxedUint::from(42u64).resize_unchecked(bits),
                    key.primes()[0].as_ref().resize_unchecked(bits), // Not coprime to n.
                    key.primes()[1].as_ref().resize_unchecked(bits),
                    key.n().wrapping_sub(BoxedUint::one()),
                ] {
                    let expected = rsa_decrypt_and_check::<MockRng>(&key, None, &c)
                        .expect("unblinded reference");
                    let mut requests = VecDeque::new();

                    // The last case makes both blinded CRT moduli equal to n (g_p=q, g_q=p).
                    // The random factors need not be coprime to either prime or to one another.
                    let blindings = [(0, [0u128; 2]), (0xff, [u128::MAX; 2]), (0xa5, [26, 30])];
                    for (factor, [rp, rq]) in blindings {
                        let mut base = vec![0; key.size()];
                        base[0] = 1; // Invertible base factor, without rejection sampling.
                        requests.push_back(base);
                        requests.push_back(vec![factor; 16]);
                        if crt {
                            requests.push_back(vec![factor ^ 0xff; 16]);
                            requests.push_back(rp.to_le_bytes().to_vec());
                            requests.push_back(rq.to_le_bytes().to_vec());
                        }
                    }
                    let mut rng = MockRng(requests.clone());
                    // Reusing a key must request fresh factors for each exponent and modulus.
                    for _ in 0..blindings.len() {
                        assert_eq!(
                            rsa_decrypt_and_check(&key, Some(&mut rng), &c)
                                .expect("blinded result"),
                            expected,
                        );
                    }
                    assert!(rng.0.is_empty());

                    // Fail at each exponent and modulus blinding request after base blinding.
                    for available in 1..=if crt { 4 } else { 1 } {
                        let mut rng = MockRng(requests.iter().take(available).cloned().collect());
                        assert_eq!(
                            rsa_decrypt_and_check(&key, Some(&mut rng), &c),
                            Err(Error::Rng),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn totient_requires_factors() {
        assert_eq!(totient(&[], 128), Err(Error::NprimesTooSmall));
        assert_eq!(
            totient(&[Odd::new(BoxedUint::from(61u64)).expect("odd prime")], 128),
            Err(Error::NprimesTooSmall),
        );
    }
}
