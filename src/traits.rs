//! Generic traits for message encryption and decryption

use alloc::vec::Vec;
use rand_core::CryptoRngCore;

use crate::errors::Result;

/// Encrypt the message using provided random source
pub trait RandomizedEncryptor {
    /// Encrypt the given message.
    fn encrypt_with_rng<R: CryptoRngCore + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Decrypt the given message
pub trait Decryptor {
    /// Decrypt the given message.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Decrypt the given message using provided random source
pub trait RandomizedDecryptor {
    /// Decrypt the given message.
    fn decrypt_with_rng<R: CryptoRngCore + ?Sized>(
        &self,
        rng: &mut R,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;
}
