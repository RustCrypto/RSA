use crate::{
    errors::{Error, Result},
    parse::rsa_oid,
    RSAPrivateKey, RSAPublicKey,
};
use num_bigint::BigUint;
use num_bigint_other::Sign;
use num_traits::Zero;
use simple_asn1::{to_der, ASN1Block};

impl RSAPrivateKey {
    #[cfg(feature = "pem")]
    pub fn to_pem_pkcs1(&self) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from("RSA PRIVATE KEY"),
            contents: self.encode_pkcs1()?,
        };
        Ok(pem::encode(&pem))
    }
    #[cfg(feature = "pem")]
    pub fn to_pem_pkcs8(&self) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from("PRIVATE KEY"),
            contents: self.encode_pkcs8()?,
        };
        Ok(pem::encode(&pem))
    }
}

impl RSAPublicKey {
    #[cfg(feature = "pem")]
    pub fn to_pem_pkcs1(&self) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from("RSA PUBLIC KEY"),
            contents: self.encode_pkcs1()?,
        };
        Ok(pem::encode(&pem))
    }
    #[cfg(feature = "pem")]
    pub fn to_pem_pkcs8(&self) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from("PUBLIC KEY"),
            contents: self.encode_pkcs8()?,
        };
        Ok(pem::encode(&pem))
    }
}

fn to_bigint(value: &crate::BigUint) -> simple_asn1::BigInt {
    // TODO can be switched if simple_asn1 BigInt type is updated
    simple_asn1::BigInt::from_bytes_le(Sign::Plus, &value.to_bytes_le())
}

impl RSAPrivateKey {
    /// TODO docs
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    pub fn encode_pkcs1(&self) -> Result<Vec<u8>> {
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

    /// Parse a `PKCS8` encoded RSA Private Key.
    ///
    /// The `der` data is expected to be the `base64` decoded content
    /// following a `-----BEGIN PRIVATE KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    pub fn encode_pkcs8(&self) -> Result<Vec<u8>> {
        let version = ASN1Block::Integer(0, to_bigint(&BigUint::zero()));
        let oid = ASN1Block::ObjectIdentifier(0, rsa_oid());
        let alg = ASN1Block::Sequence(0, vec![oid]);
        let octet_string = ASN1Block::OctetString(0, self.encode_pkcs1()?);
        let blocks = vec![version, alg, octet_string];

        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| Error::EncodeError {
            reason: format!("failed to encode ASN.1 sequence of blocks: {}", e),
        })
    }
}

impl RSAPublicKey {
    /// Parse a `PKCS1` encoded RSA Public Key.
    ///
    /// The `der` data is expected to be the `base64` decoded content
    /// following a `-----BEGIN RSA PUBLIC KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    pub fn encode_pkcs1(&self) -> Result<Vec<u8>> {
        let n = ASN1Block::Integer(0, to_bigint(&self.n));
        let e = ASN1Block::Integer(0, to_bigint(&self.e));
        let blocks = vec![n, e];

        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| Error::EncodeError {
            reason: format!("failed to encode ASN.1 sequence of blocks: {}", e),
        })
    }
    /// Parse a `PKCS8` encoded RSA Public Key.
    ///
    /// The `der` data is expected to be the `base64` decoded content
    /// following a `-----BEGIN PUBLIC KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    pub fn encode_pkcs8(&self) -> Result<Vec<u8>> {
        let oid = ASN1Block::ObjectIdentifier(0, rsa_oid());
        let alg = ASN1Block::Sequence(0, vec![oid]);

        let bz = self.encode_pkcs1()?;
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

    use std::convert::TryFrom;

    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    const PKCS8_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\r\nMEACAQAwCwYJKoZIhvcNAQEBBC4wLAIBAAIJAJGyCM1NTAwDAgMBAAECCQCMDHwC\r\nEdIqAQIFAMEBAQECBQDBQAkD\r\n-----END PRIVATE KEY-----\r\n";
    const PKCS1_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\r\nMCwCAQACCQCRsgjNTUwMAwIDAQABAgkAjAx8AhHSKgECBQDBAQEBAgUAwUAJAw==\r\n-----END RSA PRIVATE KEY-----\r\n";
    const PKCS8_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\r\nMCIwCwYJKoZIhvcNAQEBAxN+MBACCQCRsgjNTUwMAwIDAQAB\r\n-----END PUBLIC KEY-----\r\n";
    const PKCS1_PUBLIC_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\r\nMBACCQCRsgjNTUwMAwIDAQAB\r\n-----END RSA PUBLIC KEY-----\r\n";

    #[test]
    fn priv_pem_encoding_pkcs8() {
        let mut rng = XorShiftRng::from_seed([1; 16]);
        let key = RSAPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let pem_str = key
            .to_pem_pkcs8()
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS8_PRIVATE_KEY);
    }
    #[test]
    fn priv_pem_encoding_pkcs1() {
        let mut rng = XorShiftRng::from_seed([1; 16]);
        let key = RSAPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let pem_str = key
            .to_pem_pkcs1()
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS1_PRIVATE_KEY);
    }

    #[test]
    fn pub_pem_encoding_pkcs8() {
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
