use crate::{
    errors::{Error, Result},
    key::PublicKeyParts,
    parse::rsa_oid,
    PublicKey, RSAPrivateKey, RSAPublicKey,
};
use num_bigint::{BigUint, ToBigInt, ModInverse};
use num_traits::Zero;
use pem::{EncodeConfig, LineEnding};
use simple_asn1::{to_der, ASN1Block, BigInt};
use std::prelude::v1::*;
use std::{vec, format};

const BYTE_BIT_SIZE: usize = 8;
const DEFAULT_ENCODING_CONFIG: EncodeConfig = EncodeConfig {
    line_ending: LineEnding::LF,
};

#[cfg(feature = "pem")]
/// Trait for encoding the private key in the PEM format
/// 
/// Important: Encoding multi prime keys isn't supported. See [RustCrypto/RSA#66](https://github.com/RustCrypto/RSA/issues/66) for more info
pub trait PrivateKeyPemEncoding: PrivateKeyEncoding {
    const PKCS1_HEADER: &'static str;
    const PKCS8_HEADER: &'static str = "PRIVATE KEY";

    /// Converts a Private key into `PKCS1` encoded bytes in pem format.
    ///
    /// Encodes the key with the header:
    /// `-----BEGIN <name> PRIVATE KEY-----`
    ///
    /// # Example
    ///
    /// ```
    /// use rsa::{RSAPrivateKey, PrivateKeyPemEncoding};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let bits = 2048;
    /// let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    ///
    /// let _ = private_key.to_pem_pkcs1();
    /// ```
    fn to_pem_pkcs1(&self) -> Result<String> {
        self.to_pem_pkcs1_with_config(DEFAULT_ENCODING_CONFIG)
    }

    /// Converts a Private key into `PKCS1` encoded bytes in pem format with encoding config.
    ///
    /// # Example
    /// ```
    /// # use rsa::{RSAPrivateKey, PrivateKeyPemEncoding};
    /// # use rand::rngs::OsRng;
    /// use pem::{EncodeConfig, LineEnding};
    /// # let mut rng = OsRng;
    /// # let bits = 2048;
    /// # let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    ///
    /// let _ = private_key.to_pem_pkcs1_with_config(EncodeConfig {
    ///     line_ending: LineEnding::CRLF,
    /// });
    /// ```
    fn to_pem_pkcs1_with_config(&self, config: EncodeConfig) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from(Self::PKCS1_HEADER),
            contents: self.to_pkcs1()?,
        };
        Ok(pem::encode_config(&pem, config))
    }

    /// Converts a Private key into `PKCS8` encoded bytes in pem format.
    ///
    /// Encodes the key with the header:
    /// `-----BEGIN PRIVATE KEY-----`
    ///
    /// # Example
    ///
    /// ```
    /// use rsa::{RSAPrivateKey, PrivateKeyPemEncoding};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let bits = 2048;
    /// let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    ///
    /// let _ = private_key.to_pem_pkcs8();
    /// ```
    fn to_pem_pkcs8(&self) -> Result<String> {
        self.to_pem_pkcs8_with_config(DEFAULT_ENCODING_CONFIG)
    }

    /// Converts a Private key into `PKCS8` encoded bytes in pem format with encoding config.
    ///
    /// # Example
    /// ```
    /// # use rsa::{RSAPrivateKey, PrivateKeyPemEncoding};
    /// # use rand::rngs::OsRng;
    /// use pem::{EncodeConfig, LineEnding};
    /// # let mut rng = OsRng;
    /// # let bits = 2048;
    /// # let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    ///
    /// let _ = private_key.to_pem_pkcs8_with_config(EncodeConfig {
    ///     line_ending: LineEnding::CRLF,
    /// });
    /// ```
    fn to_pem_pkcs8_with_config(&self, config: EncodeConfig) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from(Self::PKCS8_HEADER),
            contents: self.to_pkcs8()?,
        };
        Ok(pem::encode_config(&pem, config))
    }
}

#[cfg(feature = "pem")]
impl PrivateKeyPemEncoding for RSAPrivateKey {
    const PKCS1_HEADER: &'static str = "RSA PRIVATE KEY";
}

#[cfg(feature = "pem")]
pub trait PublicKeyPemEncoding: PublicKeyEncoding {
    const PKCS1_HEADER: &'static str;
    const PKCS8_HEADER: &'static str = "PUBLIC KEY";

    /// Converts a Public key into `PKCS1` encoded bytes in pem format.
    ///
    /// Encodes the key with the header:
    /// `-----BEGIN <name> PUBLIC KEY-----`
    ///
    /// # Example
    ///
    /// ```
    /// use rsa::{RSAPrivateKey, RSAPublicKey, PublicKeyPemEncoding};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let bits = 2048;
    /// let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    /// let public_key = RSAPublicKey::from(&private_key);
    ///
    /// let _ = public_key.to_pem_pkcs1();
    /// ```
    fn to_pem_pkcs1(&self) -> Result<String> {
        self.to_pem_pkcs1_with_config(DEFAULT_ENCODING_CONFIG)
    }

    /// Converts a Public key into `PKCS1` encoded bytes in pem format with encoding config.
    ///
    /// # Example
    /// ```
    /// use rsa::{RSAPrivateKey, RSAPublicKey, PublicKeyPemEncoding};
    /// # use rand::rngs::OsRng;
    /// use pem::{EncodeConfig, LineEnding};
    /// # let mut rng = OsRng;
    /// # let bits = 2048;
    /// # let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    /// # let public_key = RSAPublicKey::from(&private_key);
    ///
    /// let _ = public_key.to_pem_pkcs1_with_config(EncodeConfig {
    ///     line_ending: LineEnding::CRLF,
    /// });
    /// ```
    fn to_pem_pkcs1_with_config(&self, config: EncodeConfig) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from(Self::PKCS1_HEADER),
            contents: self.to_pkcs1()?,
        };
        Ok(pem::encode_config(&pem, config))
    }

    /// Converts a Public key into `PKCS8` encoded bytes in pem format.
    ///
    /// Encodes the key with the header:
    /// `-----BEGIN PUBLIC KEY-----`
    ///
    /// # Example
    ///
    /// ```
    /// use rsa::{RSAPrivateKey, RSAPublicKey, PublicKeyPemEncoding};
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let bits = 2048;
    /// let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    /// let public_key = RSAPublicKey::from(&private_key);
    ///
    /// let _ = public_key.to_pem_pkcs8();
    /// ```
    fn to_pem_pkcs8(&self) -> Result<String> {
        self.to_pem_pkcs8_with_config(DEFAULT_ENCODING_CONFIG)
    }

    /// Converts a Public key into `PKCS8` encoded bytes in pem format with encoding config.
    ///
    /// # Example
    /// ```
    /// use rsa::{RSAPrivateKey, RSAPublicKey, PublicKeyPemEncoding};
    /// # use rand::rngs::OsRng;
    /// use pem::{EncodeConfig, LineEnding};
    /// # let mut rng = OsRng;
    /// # let bits = 2048;
    /// # let private_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    /// # let public_key = RSAPublicKey::from(&private_key);
    ///
    /// let _ = public_key.to_pem_pkcs8_with_config(EncodeConfig {
    ///     line_ending: LineEnding::CRLF,
    /// });
    /// ```
    fn to_pem_pkcs8_with_config(&self, config: EncodeConfig) -> Result<String> {
        let pem = pem::Pem {
            tag: String::from(Self::PKCS8_HEADER),
            contents: self.to_pkcs8()?,
        };
        Ok(pem::encode_config(&pem, config))
    }
}

impl PublicKeyPemEncoding for RSAPublicKey {
    const PKCS1_HEADER: &'static str = "RSA PUBLIC KEY";
}

fn to_bigint(value: &crate::BigUint) -> simple_asn1::BigInt {
    // TODO can be switched if simple_asn1 BigInt type is updated
    // This is not very clean because of the exports available from simple_asn1
    simple_asn1::BigInt::from_signed_bytes_le(&value.to_bigint().unwrap().to_signed_bytes_le())
}

/// Trait for encoding the private key in the PKCS#1/PKCS#8 format
/// 
/// Important: Encoding multi prime keys isn't supported. See [RustCrypto/RSA#66](https://github.com/RustCrypto/RSA/issues/66) for more info
pub trait PrivateKeyEncoding {
    /// Encodes a Private key to into `PKCS1` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN <name> PRIVATE KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem> 
    fn to_pkcs1(&self) -> Result<Vec<u8>>;

    /// Encodes a Private key to into `PKCS8` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN PRIVATE KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    fn to_pkcs8(&self) -> Result<Vec<u8>>;
}

impl PrivateKeyEncoding for RSAPrivateKey {
    fn to_pkcs1(&self) -> Result<Vec<u8>> {
        // Check if the key is multi prime
        if self.primes.len() > 2 {
            return Err(Error::EncodeError {
                reason: "multi prime key encoding isn't supported. see RustCrypto/RSA#66".into(),
            });
        }

        // Version 0 = "regular" (two prime) key
        // Version 1 = multi prime key
        let version = ASN1Block::Integer(0, to_bigint(&BigUint::zero()));
        let n = ASN1Block::Integer(0, to_bigint(&self.n()));
        let e = ASN1Block::Integer(0, to_bigint(&self.e()));
        let d = ASN1Block::Integer(0, to_bigint(&self.d));
        let mut blocks = vec![version, n, e, d];

        // Encode primes
        blocks.extend(
            self.primes
                .iter()
                .take(2)
                .map(|p| ASN1Block::Integer(0, to_bigint(p))),
        );
        // Encode exponents
        blocks.extend(self.primes.iter().take(2).map(|p| {
            let exponent = &self.d % (p - 1u8);
            ASN1Block::Integer(0, to_bigint(&exponent))
        }));
        // Encode coefficient
        let coefficient = (&self.primes[1])
            .mod_inverse(&self.primes[0])
            .ok_or(Error::EncodeError {
                reason: "mod inverse failed".into()
            })?;
        blocks.push(ASN1Block::Integer(
            0,
            BigInt::from_signed_bytes_le(&coefficient.to_signed_bytes_le()),
        ));

        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| Error::EncodeError {
            reason: format!("failed to encode ASN.1 sequence of blocks: {}", e),
        })
    }

    fn to_pkcs8(&self) -> Result<Vec<u8>> {
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

pub trait PublicKeyEncoding: PublicKey {
    /// Encodes a Public key to into `PKCS1` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN <name> PUBLIC KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    fn to_pkcs1(&self) -> Result<Vec<u8>> {
        let n = ASN1Block::Integer(0, to_bigint(&self.n()));
        let e = ASN1Block::Integer(0, to_bigint(&self.e()));
        let blocks = vec![n, e];

        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| Error::EncodeError {
            reason: format!("failed to encode ASN.1 sequence of blocks: {}", e),
        })
    }
    /// Encodes a Public key to into `PKCS8` bytes.
    ///
    /// This data will be `base64` encoded which would be used
    /// following a `-----BEGIN PUBLIC KEY-----` header.
    ///
    /// <https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem>
    fn to_pkcs8(&self) -> Result<Vec<u8>> {
        let oid = ASN1Block::ObjectIdentifier(0, rsa_oid());
        let alg = ASN1Block::Sequence(0, vec![oid]);

        let bz = self.to_pkcs1()?;
        let octet_string = ASN1Block::BitString(0, bz.len() * BYTE_BIT_SIZE, bz);
        let blocks = vec![alg, octet_string];

        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| Error::EncodeError {
            reason: format!("failed to encode ASN.1 sequence of blocks: {}", e),
        })
    }
}

impl PublicKeyEncoding for RSAPublicKey {}

#[cfg(all(test, feature = "pem"))]
mod tests {
    use super::{EncodeConfig, LineEnding, PrivateKeyPemEncoding, PublicKeyPemEncoding};
    use crate::{RSAPrivateKey, RSAPublicKey};
    use rand::thread_rng;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::convert::TryFrom;

    #[test]
    fn priv_pem_encoding_pkcs8() {
        const PKCS8_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMFICAQAwCwYJKoZIhvcNAQEBBEAwPgIBAAIJAJGyCM1NTAwDAgMBAAECCQCMDHwC\nEdIqAQIFAMEBAQECBQDBQAkDAgMDBAECBAHfV/cCBQC7RXbf\n-----END PRIVATE KEY-----\n";
        let mut rng = XorShiftRng::from_seed([1; 16]);
        let key = RSAPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let pem_str = key
            .to_pem_pkcs8()
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS8_PRIVATE_KEY);
    }
    #[test]
    fn priv_pem_encoding_pkcs1() {
        const PKCS1_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\nMD4CAQACCQCRsgjNTUwMAwIDAQABAgkAjAx8AhHSKgECBQDBAQEBAgUAwUAJAwID\nAwQBAgQB31f3AgUAu0V23w==\n-----END RSA PRIVATE KEY-----\n";
        let mut rng = XorShiftRng::from_seed([1; 16]);
        let key = RSAPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let pem_str = key
            .to_pem_pkcs1()
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS1_PRIVATE_KEY);
    }

    #[test]
    fn pub_pem_encoding_pkcs8() {
        const PKCS8_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCIwCwYJKoZIhvcNAQEBAxMAMBACCQCRsgjNTUwMAwIDAQAB\n-----END PUBLIC KEY-----\n";
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
        const PKCS1_PUBLIC_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMBACCQCRsgjNTUwMAwIDAQAB\n-----END RSA PUBLIC KEY-----\n";

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

    #[test]
    fn pem_encoding_config() {
        const PKCS8_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\r\nMFICAQAwCwYJKoZIhvcNAQEBBEAwPgIBAAIJAJGyCM1NTAwDAgMBAAECCQCMDHwC\r\nEdIqAQIFAMEBAQECBQDBQAkDAgMDBAECBAHfV/cCBQC7RXbf\r\n-----END PRIVATE KEY-----\r\n";
        const PKCS8_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\r\nMCIwCwYJKoZIhvcNAQEBAxMAMBACCQCRsgjNTUwMAwIDAQAB\r\n-----END PUBLIC KEY-----\r\n";
        let mut rng = XorShiftRng::from_seed([1; 16]);
        let key = RSAPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let pub_key = key.to_public_key();
        let pem_str = key
            .to_pem_pkcs8_with_config(EncodeConfig {
                line_ending: LineEnding::CRLF,
            })
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS8_PRIVATE_KEY);
        let pem_str = pub_key
            .to_pem_pkcs8_with_config(EncodeConfig {
                line_ending: LineEnding::CRLF,
            })
            .expect("failed to encode private key to pem string");
        assert_eq!(pem_str, PKCS8_PUBLIC_KEY);
    }
}
