use crate::{
    errors::{Error, Result},
    parse::rsa_oid,
    RSAPrivateKey, RSAPublicKey,
};
use num_bigint::{BigUint, ToBigInt};
use num_traits::Zero;
use simple_asn1::{to_der, ASN1Block};

#[cfg(feature = "pem")]
impl RSAPrivateKey {
    /// Converts RSA Private key into `PKCS1` encoded bytes in pem format.
    ///
    /// Encodes the key with the header:
    /// `-----BEGIN RSA PRIVATE KEY-----`
    ///
    /// # Example
    ///
    /// ```
    /// use rsa::RSAPrivateKey;
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let bits = 2048;
    /// let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    ///
    /// let _ = private_key.to_pem_pkcs1();
    /// ```
    pub fn to_pem_pkcs1(&self) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from("RSA PRIVATE KEY"),
            contents: self.to_pkcs1()?,
        };
        Ok(pem::encode(&pem))
    }

    /// Converts RSA Private key into `PKCS8` encoded bytes in pem format.
    ///
    /// Encodes the key with the header:
    /// `-----BEGIN PRIVATE KEY-----`
    ///
    /// # Example
    ///
    /// ```
    /// use rsa::RSAPrivateKey;
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let bits = 2048;
    /// let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    ///
    /// let _ = private_key.to_pem_pkcs8();
    /// ```
    pub fn to_pem_pkcs8(&self) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from("PRIVATE KEY"),
            contents: self.to_pkcs8()?,
        };
        Ok(pem::encode(&pem))
    }
}

#[cfg(feature = "pem")]
impl RSAPublicKey {
    /// Converts RSA Public key into `PKCS1` encoded bytes in pem format.
    ///
    /// Encodes the key with the header:
    /// `-----BEGIN RSA PUBLIC KEY-----`
    ///
    /// # Example
    ///
    /// ```
    /// use rsa::{RSAPrivateKey, RSAPublicKey};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let bits = 2048;
    /// let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    /// let public_key = RSAPublicKey::from(&private_key);
    ///
    /// let _ = public_key.to_pem_pkcs1();
    /// ```
    pub fn to_pem_pkcs1(&self) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from("RSA PUBLIC KEY"),
            contents: self.to_pkcs1()?,
        };
        Ok(pem::encode(&pem))
    }
    /// Converts RSA Public key into `PKCS8` encoded bytes in pem format.
    ///
    /// Encodes the key with the header:
    /// `-----BEGIN PUBLIC KEY-----`
    ///
    /// # Example
    ///
    /// ```
    /// use rsa::{RSAPrivateKey, RSAPublicKey};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let bits = 2048;
    /// let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    /// let public_key = RSAPublicKey::from(&private_key);
    ///
    /// let _ = public_key.to_pem_pkcs8();
    /// ```
    pub fn to_pem_pkcs8(&self) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from("PUBLIC KEY"),
            contents: self.to_pkcs8()?,
        };
        Ok(pem::encode(&pem))
    }
}

fn to_bigint(value: &crate::BigUint) -> simple_asn1::BigInt {
    // TODO can be switched if simple_asn1 BigInt type is updated
    // This is not very clean because of the exports available from simple_asn1
    simple_asn1::BigInt::from_signed_bytes_le(&value.to_bigint().unwrap().to_signed_bytes_le())
}

impl RSAPrivateKey {
    /// Encodes an RSA Private key to into `PKCS1` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN RSA PRIVATE KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    pub fn to_pkcs1(&self) -> Result<Vec<u8>> {
        // TODO should version be changed to anything?
        let version = ASN1Block::Integer(0, to_bigint(&BigUint::zero()));
        let n = ASN1Block::Integer(0, to_bigint(&self.n));
        let e = ASN1Block::Integer(0, to_bigint(&self.e));
        let d = ASN1Block::Integer(0, to_bigint(&self.d));
        let mut blocks = vec![version, n, e, d];

        // Encode primes
        blocks.extend(
            self.primes
                .iter()
                .map(|p| ASN1Block::Integer(0, to_bigint(p))),
        );
        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| Error::EncodeError {
            reason: format!("failed to encode ASN.1 sequence of blocks: {}", e),
        })
    }

    /// Encodes an RSA Private key to into `PKCS8` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN PRIVATE KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    pub fn to_pkcs8(&self) -> Result<Vec<u8>> {
        let version = ASN1Block::Integer(0, to_bigint(&BigUint::zero()));
        let oid = ASN1Block::ObjectIdentifier(0, rsa_oid());
        let alg = ASN1Block::Sequence(0, vec![oid]);
        let octet_string = ASN1Block::OctetString(0, self.to_pkcs1()?);
        let blocks = vec![version, alg, octet_string];

        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| Error::EncodeError {
            reason: format!("failed to encode ASN.1 sequence of blocks: {}", e),
        })
    }
}

impl RSAPublicKey {
    /// Encodes an RSA Public key to into `PKCS1` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN RSA PUBLIC KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    pub fn to_pkcs1(&self) -> Result<Vec<u8>> {
        let n = ASN1Block::Integer(0, to_bigint(&self.n));
        let e = ASN1Block::Integer(0, to_bigint(&self.e));
        let blocks = vec![n, e];

        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| Error::EncodeError {
            reason: format!("failed to encode ASN.1 sequence of blocks: {}", e),
        })
    }
    /// Encodes an RSA Public key to into `PKCS8` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN PUBLIC KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    pub fn to_pkcs8(&self) -> Result<Vec<u8>> {
        let oid = ASN1Block::ObjectIdentifier(0, rsa_oid());
        let alg = ASN1Block::Sequence(0, vec![oid]);

        let bz = self.to_pkcs1()?;
        let octet_string = ASN1Block::BitString(0, bz.len(), bz);
        let blocks = vec![alg, octet_string];

        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| Error::EncodeError {
            reason: format!("failed to encode ASN.1 sequence of blocks: {}", e),
        })
    }
}

#[cfg(all(test, feature = "pem"))]
mod tests {
    use crate::{RSAPrivateKey, RSAPublicKey};
    use rand::thread_rng;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::convert::TryFrom;

    #[test]
    fn priv_pem_encoding_pkcs8() {
        const PKCS8_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\r\nMEACAQAwCwYJKoZIhvcNAQEBBC4wLAIBAAIJAJGyCM1NTAwDAgMBAAECCQCMDHwC\r\nEdIqAQIFAMEBAQECBQDBQAkD\r\n-----END PRIVATE KEY-----\r\n";
        let mut rng = XorShiftRng::from_seed([1; 16]);
        let key = RSAPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let pem_str = key
            .to_pem_pkcs8()
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS8_PRIVATE_KEY);
    }
    #[test]
    fn priv_pem_encoding_pkcs1() {
        const PKCS1_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\r\nMCwCAQACCQCRsgjNTUwMAwIDAQABAgkAjAx8AhHSKgECBQDBAQEBAgUAwUAJAw==\r\n-----END RSA PRIVATE KEY-----\r\n";
        let mut rng = XorShiftRng::from_seed([1; 16]);
        let key = RSAPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let pem_str = key
            .to_pem_pkcs1()
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS1_PRIVATE_KEY);
    }

    #[test]
    fn pub_pem_encoding_pkcs8() {
        const PKCS8_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\r\nMCIwCwYJKoZIhvcNAQEBAxN+MBACCQCRsgjNTUwMAwIDAQAB\r\n-----END PUBLIC KEY-----\r\n";
        let mut rng = XorShiftRng::from_seed([1; 16]);
        let key = RSAPrivateKey::new(&mut rng, 64)
            .expect("failed to generate key")
            .to_public_key();
        let pem_str = key
            .to_pem_pkcs8()
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS8_PUBLIC_KEY);
    }

    #[test]
    fn pub_pem_encoding_pkcs1() {
        const PKCS1_PUBLIC_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\r\nMBACCQCRsgjNTUwMAwIDAQAB\r\n-----END RSA PUBLIC KEY-----\r\n";

        let mut rng = XorShiftRng::from_seed([1; 16]);
        let key = RSAPrivateKey::new(&mut rng, 64)
            .expect("failed to generate key")
            .to_public_key();
        let pem_str = key
            .to_pem_pkcs1()
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS1_PUBLIC_KEY);
    }

    #[test]
    fn symmetric_private_key_encoding_pkcs1() {
        let mut rng = thread_rng();
        let key = RSAPrivateKey::new(&mut rng, 128).unwrap();
        let pem2 = pem::parse(key.to_pem_pkcs1().unwrap()).expect("pem::parse failed");
        let key2 = RSAPrivateKey::try_from(pem2).expect("RSAPrivateKey::try_from failed");
        assert_eq!(key, key2);
    }

    #[test]
    fn symmetric_private_key_encoding_pkcs8() {
        let mut rng = thread_rng();
        let key = RSAPrivateKey::new(&mut rng, 128).unwrap();
        let pem2 = pem::parse(key.to_pem_pkcs8().unwrap()).expect("pem::parse failed");
        let key2 = RSAPrivateKey::try_from(pem2).expect("RSAPrivateKey::try_from failed");
        assert_eq!(key, key2);
    }

    #[test]
    fn symmetric_public_key_encoding_pkcs1() {
        let mut rng = thread_rng();
        let key = RSAPrivateKey::new(&mut rng, 128).unwrap().to_public_key();
        let pem2 = pem::parse(key.to_pem_pkcs1().unwrap()).expect("pem::parse failed");
        let key2 = RSAPublicKey::try_from(pem2).expect("RSAPublicKey::try_from failed");
        assert_eq!(key, key2);
    }

    #[test]
    fn symmetric_public_key_encoding_pkcs8() {
        let mut rng = thread_rng();
        let key = RSAPrivateKey::new(&mut rng, 128).unwrap().to_public_key();
        let pem2 = pem::parse(key.to_pem_pkcs8().unwrap()).expect("pem::parse failed");
        let key2 = RSAPublicKey::try_from(pem2).expect("RSAPublicKey::try_from failed");
        assert_eq!(key, key2);
    }
}
