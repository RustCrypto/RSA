use alloc::vec::Vec;
use num_bigint::BigUint;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::errors::Result;
use crate::internals;
use crate::key::{RsaPrivateKey, RsaPublicKey};

pub trait EncryptionPrimitive {
    /// Do NOT use directly! Only for implementors.
    fn raw_encryption_primitive(&self, plaintext: &[u8], pad_size: usize) -> Result<Vec<u8>> {
        let int = Zeroizing::new(BigUint::from_bytes_be(plaintext));
        self.raw_int_encryption_primitive(&int, pad_size)
    }

    fn raw_int_encryption_primitive(&self, plaintext: &BigUint, pad_size: usize)
        -> Result<Vec<u8>>;
}

pub trait DecryptionPrimitive {
    /// Do NOT use directly! Only for implementors.
    fn raw_decryption_primitive<R: CryptoRngCore + ?Sized>(
        &self,
        rng: Option<&mut R>,
        ciphertext: &[u8],
        pad_size: usize,
    ) -> Result<Vec<u8>> {
        let int = Zeroizing::new(BigUint::from_bytes_be(ciphertext));
        self.raw_int_decryption_primitive(rng, &int, pad_size)
    }

    fn raw_int_decryption_primitive<R: CryptoRngCore + ?Sized>(
        &self,
        rng: Option<&mut R>,
        ciphertext: &BigUint,
        pad_size: usize,
    ) -> Result<Vec<u8>>;
}

impl EncryptionPrimitive for RsaPublicKey {
    fn raw_int_encryption_primitive(
        &self,
        plaintext: &BigUint,
        pad_size: usize,
    ) -> Result<Vec<u8>> {
        let c = Zeroizing::new(internals::encrypt(self, &plaintext));
        let c_bytes = Zeroizing::new(c.to_bytes_be());
        internals::left_pad(&c_bytes, pad_size)
    }
}

impl DecryptionPrimitive for RsaPrivateKey {
    fn raw_int_decryption_primitive<R: CryptoRngCore + ?Sized>(
        &self,
        rng: Option<&mut R>,
        ciphertext: &BigUint,
        pad_size: usize,
    ) -> Result<Vec<u8>> {
        let m = Zeroizing::new(internals::decrypt_and_check(rng, self, &ciphertext)?);
        let m_bytes = Zeroizing::new(m.to_bytes_be());
        internals::left_pad(&m_bytes, pad_size)
    }
}
