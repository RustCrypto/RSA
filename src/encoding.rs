//! PKCS#1 and PKCS#8 encoding support.
//!
//! Note: PKCS#1 support is achieved through a blanket impl of the
//! `pkcs1` crate's traits for types which impl the `pkcs8` crate's traits.

use crate::{
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey, RsaPublicKey,
};
use core::convert::{TryFrom, TryInto};
use crypto_bigint::{BoxedUint, NonZero, Odd};
use pkcs8::{
    der::{asn1::OctetStringRef, Encode},
    Document, EncodePrivateKey, EncodePublicKey, ObjectIdentifier, SecretDocument,
};
use zeroize::Zeroizing;

/// ObjectID for the RSA PSS keys
pub const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// Verify that the `AlgorithmIdentifier` for a key is correct.
pub(crate) fn verify_algorithm_id(
    algorithm: &pkcs8::AlgorithmIdentifierRef,
) -> pkcs8::spki::Result<()> {
    match algorithm.oid {
        pkcs1::ALGORITHM_OID => {
            if algorithm.parameters_any()? != pkcs8::der::asn1::Null.into() {
                return Err(pkcs8::spki::Error::KeyMalformed);
            }
        }
        ID_RSASSA_PSS => {
            if algorithm.parameters.is_some() {
                return Err(pkcs8::spki::Error::KeyMalformed);
            }
        }
        _ => return Err(pkcs8::spki::Error::OidUnknown { oid: algorithm.oid }),
    };

    Ok(())
}

impl TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for RsaPrivateKey {
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        verify_algorithm_id(&private_key_info.algorithm)?;

        let pkcs1_key = pkcs1::RsaPrivateKey::try_from(private_key_info.private_key)?;

        // Multi-prime RSA keys not currently supported
        if pkcs1_key.version() != pkcs1::Version::TwoPrime {
            return Err(pkcs1::Error::Version.into());
        }

        let key_malformed = pkcs8::Error::KeyMalformed;

        let bits =
            u32::try_from(pkcs1_key.modulus.as_bytes().len()).map_err(|_| key_malformed)? * 8;

        let n = BoxedUint::from_be_slice(pkcs1_key.modulus.as_bytes(), bits)
            .map_err(|_| key_malformed)?;
        let n = Option::from(Odd::new(n)).ok_or(key_malformed)?;

        // exponent potentially needs padding
        let mut e_slice = [0u8; 8];
        let raw_e_slice = pkcs1_key.public_exponent.as_bytes();
        e_slice[8 - raw_e_slice.len()..].copy_from_slice(raw_e_slice);
        let e = u64::from_be_bytes(e_slice);

        let d = BoxedUint::from_be_slice(pkcs1_key.private_exponent.as_bytes(), bits)
            .map_err(|_| key_malformed)?;

        let prime1 = BoxedUint::from_be_slice(pkcs1_key.prime1.as_bytes(), bits)
            .map_err(|_| key_malformed)?;
        let prime2 = BoxedUint::from_be_slice(pkcs1_key.prime2.as_bytes(), bits)
            .map_err(|_| key_malformed)?;
        let primes = vec![prime1, prime2];

        RsaPrivateKey::from_components(n, e, d, primes).map_err(|_| key_malformed)
    }
}

impl TryFrom<pkcs8::SubjectPublicKeyInfoRef<'_>> for RsaPublicKey {
    type Error = pkcs8::spki::Error;

    fn try_from(spki: pkcs8::SubjectPublicKeyInfoRef<'_>) -> pkcs8::spki::Result<Self> {
        verify_algorithm_id(&spki.algorithm)?;

        let pkcs1_key = pkcs1::RsaPublicKey::try_from(
            spki.subject_public_key
                .as_bytes()
                .ok_or(pkcs8::spki::Error::KeyMalformed)?,
        )?;

        let key_malformed = pkcs8::spki::Error::KeyMalformed;
        let bits =
            u32::try_from(pkcs1_key.modulus.as_bytes().len()).map_err(|_| key_malformed)? * 8;
        let n = BoxedUint::from_be_slice(pkcs1_key.modulus.as_bytes(), bits)
            .map_err(|_| key_malformed)?;

        // exponent potentially needs padding
        let mut e_slice = [0u8; 8];
        let raw_e_slice = pkcs1_key.public_exponent.as_bytes();
        e_slice[8 - raw_e_slice.len()..].copy_from_slice(raw_e_slice);
        let e = u64::from_be_bytes(e_slice);

        RsaPublicKey::new(n, e).map_err(|_| pkcs8::spki::Error::KeyMalformed)
    }
}

impl EncodePrivateKey for RsaPrivateKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        // Check if the key is multi prime
        if self.primes.len() > 2 {
            return Err(pkcs1::Error::Version.into());
        }

        let modulus = self.n().to_be_bytes();
        let public_exponent = self.e().to_be_bytes();
        let private_exponent = Zeroizing::new(self.d().to_be_bytes());
        let prime1 = Zeroizing::new(self.primes[0].to_be_bytes());
        let prime2 = Zeroizing::new(self.primes[1].to_be_bytes());

        let bits = self.d().bits_precision();

        let exponent1 = Zeroizing::new(
            (self.d() % NonZero::new(&self.primes[0].widen(bits) - &BoxedUint::one()).unwrap())
                .to_be_bytes(),
        );
        let exponent2 = Zeroizing::new(
            (self.d() % NonZero::new(&self.primes[1].widen(bits) - &BoxedUint::one()).unwrap())
                .to_be_bytes(),
        );
        let coefficient = Zeroizing::new(
            self.crt_coefficient()
                .ok_or(pkcs1::Error::Crypto)?
                .to_be_bytes(),
        );

        let private_key = pkcs1::RsaPrivateKey {
            modulus: pkcs1::UintRef::new(&modulus)?,
            public_exponent: pkcs1::UintRef::new(&public_exponent)?,
            private_exponent: pkcs1::UintRef::new(&private_exponent)?,
            prime1: pkcs1::UintRef::new(&prime1)?,
            prime2: pkcs1::UintRef::new(&prime2)?,
            exponent1: pkcs1::UintRef::new(&exponent1)?,
            exponent2: pkcs1::UintRef::new(&exponent2)?,
            coefficient: pkcs1::UintRef::new(&coefficient)?,
            other_prime_infos: None,
        }
        .to_der()?;

        pkcs8::PrivateKeyInfoRef::new(
            pkcs1::ALGORITHM_ID,
            OctetStringRef::new(private_key.as_ref())?,
        )
        .try_into()
    }
}

impl EncodePublicKey for RsaPublicKey {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document> {
        let modulus = self.n().to_be_bytes();
        let public_exponent = self.e().to_be_bytes();

        let subject_public_key = pkcs1::RsaPublicKey {
            modulus: pkcs1::UintRef::new(&modulus)?,
            public_exponent: pkcs1::UintRef::new(&public_exponent)?,
        }
        .to_der()?;

        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs1::ALGORITHM_ID,
            subject_public_key: pkcs8::der::asn1::BitStringRef::new(
                0,
                subject_public_key.as_ref(),
            )?,
        }
        .try_into()
    }
}
