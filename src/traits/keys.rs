//! Traits related to the key components

use crate::key::SecretPrime;
use alloc::boxed::Box;
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, NonZero, Odd,
};
use zeroize::Zeroize;

/// Components of an RSA public key.
pub trait PublicKeyParts {
    /// Returns the modulus of the key.
    fn n(&self) -> &NonZero<BoxedUint>;

    /// Returns the public exponent of the key.
    fn e(&self) -> &BoxedUint;

    /// Returns `k`, the modulus length in octets from RFC8017: `ceil(modBits / 8)`.
    ///
    /// Ciphertexts and signatures have this length, including any leading zero octets.
    /// This may be smaller than the modulus's allocated storage width.
    fn size(&self) -> usize {
        (self.n().bits() as usize).div_ceil(8)
    }

    /// Returns the parameters for montgomery operations.
    fn n_params(&self) -> &BoxedMontyParams;

    /// Returns the limb-aligned storage precision of `n` in bits.
    ///
    /// This can exceed the modulus bit length (`modBits` in RFC8017). Use this precision for
    /// integer arithmetic and decoding representatives, and [`Self::size`] for wire encodings.
    fn n_bits_precision(&self) -> u32 {
        self.n().bits_precision()
    }

    /// Returns the big endian serialization of the modulus of the key
    fn n_bytes(&self) -> Box<[u8]> {
        self.n().to_be_bytes_trimmed_vartime()
    }

    /// Returns the big endian serialization of the public exponent of the key
    fn e_bytes(&self) -> Box<[u8]> {
        self.e().to_be_bytes_trimmed_vartime()
    }
}

/// Components of an RSA private key.
pub trait PrivateKeyParts: PublicKeyParts {
    /// Returns the private exponent of the key.
    fn d(&self) -> &BoxedUint;

    /// Returns the prime factors as [`Odd`].
    fn primes(&self) -> &[Odd<BoxedUint>];

    /// Returns prime `p` if precomputed.
    fn p(&self) -> Option<&SecretPrime>;

    /// Returns prime `q` if precomputed.
    fn q(&self) -> Option<&SecretPrime>;

    /// Returns the precomputed dp value, D mod (P-1)
    fn dp(&self) -> Option<&BoxedUint>;

    /// Returns the precomputed dq value, D mod (Q-1)
    fn dq(&self) -> Option<&BoxedUint>;

    /// Returns the precomputed qinv value, Q^-1 mod P
    fn qinv(&self) -> Option<&BoxedMontyForm>;

    /// Returns an iterator over the CRT Values
    fn crt_values(&self) -> Option<&[CrtValue]>;
}

/// Contains the precomputed Chinese remainder theorem values.
#[derive(Debug, Clone)]
pub struct CrtValue {
    /// D mod (prime - 1)
    pub(crate) exp: BoxedUint,
    /// R·Coeff ≡ 1 mod Prime.
    pub(crate) coeff: BoxedUint,
    /// product of primes prior to this (inc p and q)
    pub(crate) r: BoxedUint,
}

impl Zeroize for CrtValue {
    fn zeroize(&mut self) {
        self.exp.zeroize();
        self.coeff.zeroize();
        self.r.zeroize();
    }
}

impl Drop for CrtValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}
