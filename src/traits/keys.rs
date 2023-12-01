//! Traits related to the key components

use alloc::vec::Vec;

use crypto_bigint::{modular::BoxedResidueParams, BoxedUint, NonZero};
use num_bigint::{BigInt, BigUint, IntoBigInt};
use zeroize::Zeroize;

use crate::key::to_biguint;

/// Components of an RSA public key.
pub trait PublicKeyParts {
    /// Returns the modulus of the key.
    fn n(&self) -> BigUint;

    /// Returns the public exponent of the key.
    fn e(&self) -> BigUint;

    /// Returns the modulus size in bytes. Raw signatures and ciphertexts for
    /// or by this public key will have the same size.
    fn size(&self) -> usize {
        (self.n().bits() + 7) / 8
    }
}

pub trait PublicKeyPartsNew {
    /// Returns the modulus of the key.
    fn n(&self) -> &NonZero<BoxedUint>;

    /// Returns the public exponent of the key.
    fn e(&self) -> &BoxedUint;

    fn n_params(&self) -> BoxedResidueParams;

    fn n_bits_precision(&self) -> usize {
        self.n().bits_precision()
    }

    /// Returns the modulus size in bytes. Raw signatures and ciphertexts for
    /// or by this public key will have the same size.
    fn size(&self) -> usize {
        (self.n().bits() + 7) / 8
    }
}

impl<T: PublicKeyPartsNew> PublicKeyParts for T {
    fn n(&self) -> BigUint {
        to_biguint(&PublicKeyPartsNew::n(self).clone().get())
    }

    fn e(&self) -> BigUint {
        to_biguint(PublicKeyPartsNew::e(self))
    }

    fn size(&self) -> usize {
        PublicKeyPartsNew::size(self)
    }
}

/// Components of an RSA private key.
pub trait PrivateKeyParts: PublicKeyParts {
    /// Returns the private exponent of the key.
    fn d(&self) -> BigUint;

    /// Returns the prime factors.
    fn primes(&self) -> Vec<BigUint>;

    /// Returns the precomputed dp value, D mod (P-1)
    fn dp(&self) -> Option<BigUint>;

    /// Returns the precomputed dq value, D mod (Q-1)
    fn dq(&self) -> Option<BigUint>;

    /// Returns the precomputed qinv value, Q^-1 mod P
    fn qinv(&self) -> Option<BigInt>;

    /// Returns an iterator over the CRT Values
    fn crt_values(&self) -> Option<Vec<CrtValue>>;
}

/// Components of an RSA private key.
impl<T: PrivateKeyPartsNew> PrivateKeyParts for T {
    fn d(&self) -> BigUint {
        to_biguint(PrivateKeyPartsNew::d(self))
    }
    fn primes(&self) -> Vec<BigUint> {
        PrivateKeyPartsNew::primes(self)
            .iter()
            .map(to_biguint)
            .collect()
    }
    fn dp(&self) -> Option<BigUint> {
        PrivateKeyPartsNew::dp(self).map(to_biguint)
    }

    fn dq(&self) -> Option<BigUint> {
        PrivateKeyPartsNew::dq(self).map(to_biguint)
    }
    fn qinv(&self) -> Option<BigInt> {
        PrivateKeyPartsNew::qinv(self).and_then(|v| to_biguint(v).into_bigint())
    }

    fn crt_values(&self) -> Option<Vec<CrtValue>> {
        None
    }
}

/// Components of an RSA private key.
pub trait PrivateKeyPartsNew: PublicKeyPartsNew {
    /// Returns the private exponent of the key.
    fn d(&self) -> &BoxedUint;

    /// Returns the prime factors.
    fn primes(&self) -> &[BoxedUint];

    /// Returns the precomputed dp value, D mod (P-1)
    fn dp(&self) -> Option<&BoxedUint>;

    /// Returns the precomputed dq value, D mod (Q-1)
    fn dq(&self) -> Option<&BoxedUint>;

    /// Returns the precomputed qinv value, Q^-1 mod P
    fn qinv(&self) -> Option<&BoxedUint>;

    /// Returns an iterator over the CRT Values
    fn crt_values(&self) -> Option<&[CrtValueNew]>;

    fn p_params(&self) -> Option<&BoxedResidueParams>;

    fn q_params(&self) -> Option<&BoxedResidueParams>;
}

/// Contains the precomputed Chinese remainder theorem values.
#[derive(Debug, Clone)]
pub struct CrtValueNew {
    /// D mod (prime - 1)
    pub(crate) exp: BoxedUint,
    /// R·Coeff ≡ 1 mod Prime.
    pub(crate) coeff: BoxedUint,
    /// product of primes prior to this (inc p and q)
    pub(crate) r: BoxedUint,
}

/// Contains the precomputed Chinese remainder theorem values.
#[derive(Debug, Clone)]
pub struct CrtValue {
    /// D mod (prime - 1)
    pub(crate) exp: BigInt,
    /// R·Coeff ≡ 1 mod Prime.
    pub(crate) coeff: BigInt,
    /// product of primes prior to this (inc p and q)
    pub(crate) r: BigInt,
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

impl Zeroize for CrtValueNew {
    fn zeroize(&mut self) {
        self.exp.zeroize();
        self.coeff.zeroize();
        self.r.zeroize();
    }
}

impl Drop for CrtValueNew {
    fn drop(&mut self) {
        self.zeroize();
    }
}
