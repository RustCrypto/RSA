//! RSA-ext trait definitions.

use alloc::vec::Vec;

use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

use zeroize::{Zeroize, Zeroizing};

use crate::algorithms::pad::left_pad;
use crate::algorithms::rsa::rsa_decrypt;
use crate::errors::{Error, Result};
use crate::key;

use crate::traits::PublicKeyParts;
use crate::{RsaPrivateKey, RsaPublicKey};

/// RsaPrivateKey Ext
pub trait RsaPrivateKeyExt {
    /// private_key encrypt
    fn encrypt_ext<R: RngCore + CryptoRng>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>>;
    /// RsaPublicKey decrypt
    fn pub_decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}
/// RsaPrivateKey Ext
pub trait RsaPublicKeyExt {
    /// RsaPublicKey decrypt
    fn decrypt_ext(&self, data: &[u8]) -> Result<Vec<u8>>;
}
impl RsaPublicKeyExt for RsaPublicKey {
    fn decrypt_ext(&self, data: &[u8]) -> Result<Vec<u8>> {
        let e = self.e();
        let n = self.n();

        let k: usize = self.size();
        let mut ret = vec![];
        for v in data.chunks(k) {
            let m = BigUint::from_bytes_be(v);
            let m = m.modpow(e, n);
            let m = Zeroizing::new(m);
            let m = Zeroizing::new(m.to_bytes_be());
            let mut out = vec![0u8; k];
            out[k - m.len()..].copy_from_slice(&m);

            if out[0] != 0 {
                break;
            }
            if out[1] != 0 && out[1] != 1 {
                break;
            }
            let mut i = 2;
            while i < out.len() {
                if out[i] == 0 {
                    break;
                }
                i += 1;
            }

            i += 1;
            if i == out.len() {
                break;
            }
            ret.extend(&out[i..]);
        }
        Ok(ret)
    }
}

impl RsaPrivateKeyExt for RsaPrivateKey {
    fn encrypt_ext<R: RngCore + CryptoRng>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        let pub_key: RsaPublicKey = self.into();
        key::check_public(&pub_key)?;
        let k = pub_key.size();
        let max = k - 11;
        let chunks = msg.chunks(max);
        let mut ret = vec![];
        for sub in chunks {
            let msg = sub;
            let t_len = msg.len();
            // EM = 0x00 || 0x02 || PS || 0x00 || M
            let mut em = Zeroizing::new(vec![0u8; k]);
            em[1] = 1;
            for i in 2..(k - t_len - 1) {
                em[i] = 0xff;
            }
            // non_zero_random_bytes(rng, &mut em[2..k - msg.len() - 1]);
            // em[k - msg.len() - 1] = 0;
            em[k - msg.len()..].copy_from_slice(msg);

            let mut m = BigUint::from_bytes_be(&em);
            let mut c = rsa_decrypt(Some(rng), self, &m)?;
            let mut c_bytes = c.to_bytes_be();
            let ciphertext = left_pad(&c_bytes, k)?;
            if k < ciphertext.len() {
                return Err(Error::Verification);
            }
            // clear out tmp values
            m.zeroize();
            c.zeroize();
            c_bytes.zeroize();

            ret.extend(ciphertext);
        }
        Ok(ret)
    }

    /// RsaPublicKey decrypt
    fn pub_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let public_key = self.to_public_key();
        public_key.decrypt_ext(data)
    }
}
