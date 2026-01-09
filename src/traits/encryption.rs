//! Encryption-related traits.

use alloc::vec::Vec;
use rand_core::CryptoRng;

use crate::errors::Result;

/// Encrypt the message using provided random source
pub trait RandomizedEncryptor {
    /// Encrypt the given message.
    fn encrypt_with_rng<R: CryptoRng + ?Sized>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>>;
}

/// Decrypt the given message
pub trait Decryptor {
    /// Decrypt the given message.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Decrypt the given message using provided random source
pub trait RandomizedDecryptor {
    /// Decrypt the given message.
    fn decrypt_with_rng<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Decrypt with implicit rejection to prevent Bleichenbacher/Marvin timing attacks.
///
/// Instead of returning an error on invalid PKCS#1 v1.5 padding, this trait
/// returns a deterministic synthetic message derived from the ciphertext using
/// a PRF keyed by the private key. This prevents timing side-channels that could
/// leak information about padding validity.
///
/// See [IETF draft-irtf-cfrg-rsa-guidance](https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-guidance/)
/// for the specification of implicit rejection.
#[cfg(feature = "implicit-rejection")]
pub trait ImplicitRejectionDecryptor {
    /// Decrypt the ciphertext with implicit rejection.
    ///
    /// This method **never fails** due to padding errors. On invalid padding,
    /// it returns a deterministic synthetic plaintext derived from the ciphertext.
    /// The caller cannot distinguish between valid and invalid ciphertexts
    /// based on the return value or timing.
    ///
    /// # Arguments
    /// * `ciphertext` - The RSA ciphertext to decrypt
    /// * `expected_len` - The expected length of the plaintext (e.g., 48 for TLS premaster secret)
    ///
    /// # Returns
    /// Either the actual plaintext (if padding was valid) or a synthetic plaintext
    /// of `expected_len` bytes.
    fn decrypt_implicit_rejection(&self, ciphertext: &[u8], expected_len: usize)
        -> Result<Vec<u8>>;

    /// Decrypt the ciphertext with implicit rejection and RSA blinding.
    ///
    /// Same as [`decrypt_implicit_rejection`](Self::decrypt_implicit_rejection), but uses RSA blinding
    /// with the provided RNG for additional side-channel protection against power analysis
    /// and electromagnetic attacks on the modular exponentiation.
    ///
    /// # Arguments
    /// * `rng` - Random number generator for blinding
    /// * `ciphertext` - The RSA ciphertext to decrypt
    /// * `expected_len` - The expected length of the plaintext (e.g., 48 for TLS premaster secret)
    ///
    /// # Returns
    /// Either the actual plaintext (if padding was valid) or a synthetic plaintext
    /// of `expected_len` bytes.
    fn decrypt_implicit_rejection_blinded<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ciphertext: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>>;
}

/// Encryption keypair with an associated encryption key.
pub trait EncryptingKeypair {
    /// Encrypting key type for this keypair.
    type EncryptingKey: Clone;

    /// Get the encrypting key which can encrypt messages to be decrypted by
    /// the decryption key portion of this keypair.
    fn encrypting_key(&self) -> Self::EncryptingKey;
}
