//! Supported padding schemes.

use alloc::vec::Vec;

use rand_core::TryCryptoRng;

use crate::errors::Result;
use crate::{PrivateKey, PublicKey};

/// Padding scheme used for encryption.
pub trait PaddingScheme {
    /// Decrypt the given message using the given private key.
    ///
    /// If an `rng` is passed, it uses RSA blinding to help mitigate timing side-channel attacks.
    #[allow(clippy::missing_errors_doc, reason = "TODO")]
    fn decrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;

    /// Encrypt the given message using the given public key.
    #[allow(clippy::missing_errors_doc, reason = "TODO")]
    fn encrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: &mut Rng,
        pub_key: &PublicKey,
        msg: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Digital signature scheme.
pub trait SignatureScheme {
    /// Sign the given digest.
    #[allow(clippy::missing_errors_doc, reason = "TODO")]
    fn sign<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &PrivateKey,
        hashed: &[u8],
    ) -> Result<Vec<u8>>;

    /// Verify a signed message.
    ///
    /// `hashed` must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    ///
    /// If the message is valid `Ok(())` is returned, otherwise an `Err` indicating failure.
    #[allow(clippy::missing_errors_doc, reason = "TODO")]
    fn verify(self, pub_key: &PublicKey, hashed: &[u8], sig: &[u8]) -> Result<()>;
}
