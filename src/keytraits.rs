//! Traits related to the key components

use num_bigint::BigUint;

/// Components of an RSA public key.
pub trait PublicKeyParts {
    /// Returns the modulus of the key.
    fn n(&self) -> &BigUint;

    /// Returns the public exponent of the key.
    fn e(&self) -> &BigUint;

    /// Returns the modulus size in bytes. Raw signatures and ciphertexts for
    /// or by this public key will have the same size.
    fn size(&self) -> usize {
        (self.n().bits() + 7) / 8
    }
}

/// Components of an RSA private key.
pub trait PrivateKeyParts: PublicKeyParts {
    /// Returns the private exponent of the key.
    fn d(&self) -> &BigUint;

    /// Returns the prime factors.
    fn primes(&self) -> &[BigUint];
}
