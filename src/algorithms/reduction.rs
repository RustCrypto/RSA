//! Reduction modulo an odd, potentially secret modulus using fixed-width Montgomery arithmetic.

use crypto_bigint::{
    BoxedUint, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};

/// Convert any input precision to Montgomery form. Loop counts and allocations depend only on
/// buffer precisions, which callers must choose independently of secret values.
pub(crate) fn to_monty(x: &BoxedUint, p: &BoxedMontyParams) -> BoxedMontyForm {
    let bits = p.bits_precision();

    if x.bits_precision() <= bits {
        // With R = 2^bits, x < R and R² mod p < p, so REDC's input is below R*p.
        return BoxedMontyForm::new(x.resize_unchecked(bits), p);
    }

    // Evaluate base-R digits with Horner's rule. R^2 mod p is the Montgomery representation of R,
    // so this avoids division even when the input is wider than the secret modulus.
    let radix = BoxedMontyForm::from_montgomery(p.as_ref().r2().clone(), p);
    let digit = |limbs: &[crypto_bigint::Limb]| {
        let mut value = BoxedUint::zero_with_precision(bits);
        value.as_mut_limbs()[..limbs.len()].copy_from_slice(limbs);
        BoxedMontyForm::new(value, p)
    };

    // Align digits at the low end; only the highest digit may be short.
    let mut chunks = x.as_limbs().chunks(p.modulus().as_limbs().len()).rev();
    let mut acc = digit(chunks.next().expect("nonempty integer"));
    for chunk in chunks {
        acc *= &radix;
        acc += &digit(chunk);
    }

    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::Odd;

    #[test]
    fn reduction_with_leading_zero_moduli_and_partial_digits() {
        for bits in [64, 128, 192] {
            for modulus in [
                BoxedUint::from(1u64),
                BoxedUint::from(3u64),
                BoxedUint::from(u64::MAX),
                BoxedUint::max(bits),
            ] {
                let modulus = Odd::new(modulus.resize_unchecked(bits)).expect("odd modulus");
                let params = BoxedMontyParams::new(modulus.clone());
                for input_bits in [64u32, 128, 192, 256, 320, 512] {
                    let bytes: Vec<u8> = (0..input_bits.div_ceil(8))
                        .map(|i| i.wrapping_mul(73).wrapping_add(19).to_le_bytes()[0])
                        .collect();
                    for input in [
                        BoxedUint::zero_with_precision(input_bits),
                        BoxedUint::one_with_precision(input_bits),
                        BoxedUint::max(input_bits),
                        BoxedUint::from_be_slice(&bytes, input_bits).expect("pattern"),
                    ] {
                        let expected = input
                            .rem_vartime(modulus.as_nz_ref())
                            .resize_unchecked(bits);
                        assert_eq!(to_monty(&input, &params).retrieve(), expected);
                    }
                }
            }
        }
    }
}
