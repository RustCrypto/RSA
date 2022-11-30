use alloc::vec::Vec;

use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Error, Result};
use crate::key;

use crate::{internals, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
/// private_key encrypt keep pace with gorsa, java and php
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    pri_key: &RsaPrivateKey,
    msg: &[u8],
) -> Result<Vec<u8>> {
    let pub_key: RsaPublicKey = pri_key.into();
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
        let mut c = internals::decrypt(Some(rng), pri_key, &m)?;
        let mut c_bytes = c.to_bytes_be();
        let pad_size = pub_key.size();
        let mut ciphertext = internals::left_pad(&c_bytes, pad_size);

        if pad_size < ciphertext.len() {
            return Err(Error::Verification);
        }

        // clear out tmp values
        m.zeroize();
        c.zeroize();
        c_bytes.zeroize();

        ret.append(&mut ciphertext);
    }
    Ok(ret)
}
