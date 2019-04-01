use num_bigint::BigUint;
use rand::Rng;
use zeroize::Zeroize;

use crate::errors::{Error, Result};
use crate::hash::Hash;
use crate::internals;
use crate::key::{self, PublicKey};


pub struct OaepOptions<H:Hash> {
    pub hash:H,
    pub label:Option<String>,
}

fn inc_counter(counter: &mut[u8]) {

    if counter[3]==u8::max_value() {
        counter[3] = 0;
    } else {
        counter[3] += 1;
        return;
    }

    if counter[2]==u8::max_value() {
        counter[2] = 0;
    } else {
        counter[2] += 1;
        return;
    }

    if counter[1]==u8::max_value() {
        counter[1] = 0;
    } else {
        counter[1] += 1;
        return;
    }

    if counter[0] == u8::max_value() {
        counter[0]=0u8;
        counter[1]=0u8;
        counter[2]=0u8;
        counter[3]=0u8;
    } else {
        counter[0]+=1;
    }

}

fn mgf1_xor<H:Hash>(out: &mut[u8], h: &H, seed: &[u8]) {
    let mut counter = vec![0u8; 4];
    let mut i = 0;

    while i < out.len() {
        let mut digest_data = vec![0u8;seed.len()+4];
        digest_data[0..seed.len()].copy_from_slice(seed);
        digest_data[seed.len()..].copy_from_slice(&counter);

        let digest = h.digest(digest_data.as_slice());
        let mut j = 0;
        loop {
            if j>= digest.len() || i >= out.len() {
                break;
            }

            out[i]^= digest[j];
            j+=1;
            i+=1;
        }
        inc_counter(counter.as_mut_slice());
    }

}

// Encrypts the given message with RSA and the padding
// scheme from PKCS#1 v1.5.  The message must be no longer than the
// length of the public modulus minus 11 bytes.
#[inline]
pub fn encrypt<R: Rng, K: PublicKey, H: Hash>(rng: &mut R, pub_key: &K, msg: &[u8], oaep_options: OaepOptions<H>) -> Result<Vec<u8>> {
    key::check_public(pub_key)?;

    let h = oaep_options.hash;
    let k = pub_key.size();

    if msg.len() > k - 2*h.size() -2 {
        return Err(Error::MessageTooLong);
    }

    let label = match oaep_options.label {
        Some(l) => l,
        None => "".to_owned(),
    };

    let mut em = vec![0u8; k];

    let (_, payload) = em.split_at_mut(1);
    let (seed,db) = payload.split_at_mut(h.size());
    rng.fill(seed);

    // Data block DB =  pHash || PS || 01 || M
    let db_len =  k - h.size() -1;

    let p_hash = h.digest(label.as_bytes());
    db[0..h.size()].copy_from_slice(p_hash.as_slice());
    db[db_len - msg.len() -1 ] = 1;
    db[db_len - msg.len()..].copy_from_slice( msg);

    mgf1_xor(db,&h,seed);
    mgf1_xor(seed, &h, db);

    {
        let mut m = BigUint::from_bytes_be(&em);
        let mut c = internals::encrypt(pub_key, &m).to_bytes_be();
        internals::copy_with_left_pad(&mut em, &c);

        // clear out tmp values
        m.zeroize();
        c.zeroize();
    }



    Ok(em)
}


#[cfg(test)]
mod tests {

    use super::*;
    use rand::thread_rng;
    use crate::key::RSAPublicKey;
    use crate::hash::Hashes;
    use hex;

    #[test]
    fn test_encrypt_decrypt_oaep() {
        let mut rng = thread_rng();

        let m = BigUint::parse_bytes(b"d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078cc780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf6776fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b",16).unwrap();
        let e = BigUint::parse_bytes(b"10001",16).unwrap();

        println!("{:?}",e);

        let pub_key: RSAPublicKey = RSAPublicKey::new(m,e).unwrap();

        let input = "hello world";
        let ciphertext = encrypt(&mut rng, &pub_key, input.as_bytes(), OaepOptions {
                hash: Hashes::SHA1,
                label: None,
        }).unwrap();



        //
        println!("echo \"{}\" | xxd -r -p  | openssl rsautl -inkey ./test/data/rsa_prkey.pem -decrypt -oaep", hex::encode(ciphertext));


    }

}