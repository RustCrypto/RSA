use num_bigint::BigUint;
use rand::Rng;
use zeroize::Zeroize;

use crate::errors::Result;
use crate::internals;
use crate::key::{PublicKeyParts, RSAPrivateKey, RSAPublicKey};

pub trait EncryptionPrimitive {
    /// Do NOT use directly! Only for implementors.
    fn raw_encryption_primitive(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
}

pub trait DecryptionPrimitive {
    /// Do NOT use directly! Only for implementors.
    fn raw_decryption_primitive<R: Rng>(
        &self,
        rng: Option<&mut R>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;
}

impl EncryptionPrimitive for RSAPublicKey {
    fn raw_encryption_primitive(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut m = BigUint::from_bytes_be(plaintext);
        let mut c = internals::encrypt(self, &m);
        let mut c_bytes = c.to_bytes_be();
        let ciphertext = internals::left_pad(&c_bytes, self.size());

        // clear out tmp values
        m.zeroize();
        c.zeroize();
        c_bytes.zeroize();

        Ok(ciphertext)
    }
}

impl<'a> EncryptionPrimitive for &'a RSAPublicKey {
    fn raw_encryption_primitive(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        (*self).raw_encryption_primitive(plaintext)
    }
}

impl DecryptionPrimitive for RSAPrivateKey {
    fn raw_decryption_primitive<R: Rng>(
        &self,
        rng: Option<&mut R>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut c = BigUint::from_bytes_be(ciphertext);
        let mut m = internals::decrypt_and_check(rng, self, &c)?;
        let mut m_bytes = m.to_bytes_be();
        let plaintext = internals::left_pad(&m_bytes, self.size());

        // clear tmp values
        c.zeroize();
        m.zeroize();
        m_bytes.zeroize();

        Ok(plaintext)
    }
}

impl<'a> DecryptionPrimitive for &'a RSAPrivateKey {
    fn raw_decryption_primitive<R: Rng>(
        &self,
        rng: Option<&mut R>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        (*self).raw_decryption_primitive(rng, ciphertext)
    }
}
