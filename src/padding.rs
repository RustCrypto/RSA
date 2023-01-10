//! Supported padding schemes.

use alloc::vec::Vec;

use rand_core::CryptoRngCore;

use crate::errors::Result;
use crate::key::{PrivateKey, PublicKey};

/// Padding scheme used for encryption.
pub trait PaddingScheme {
    /// Decrypt the given message using the given private key.
    ///
    /// If an `rng` is passed, it uses RSA blinding to help mitigate timing
    /// side-channel attacks.
    fn decrypt<Rng: CryptoRngCore, Priv: PrivateKey>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &Priv,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;

    /// Encrypt the given message using the given public key.
    fn encrypt<Rng: CryptoRngCore, Pub: PublicKey>(
        self,
        rng: &mut Rng,
        pub_key: &Pub,
        msg: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Digital signature scheme.
pub trait SignatureScheme {
    /// Sign the given digest.
    fn sign<Rng: CryptoRngCore, Priv: PrivateKey>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &Priv,
        hashed: &[u8],
    ) -> Result<Vec<u8>>;

    /// Verify a signed message.
    ///
    /// `hashed` must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    ///
    /// If the message is valid `Ok(())` is returned, otherwise an `Err` indicating failure.
    fn verify<Pub: PublicKey>(self, pub_key: &Pub, hashed: &[u8], sig: &[u8]) -> Result<()>;
}
