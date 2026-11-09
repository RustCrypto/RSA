//! PKCS#1 and PKCS#8 encoding support.

#![cfg(feature = "encoding")]

use crate::{
    PrivateKey, PublicKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use core::convert::{TryFrom, TryInto};
use crypto_bigint::{BoxedUint, NonZero, Resize};
use pkcs8::{
    Document, EncodePrivateKey, EncodePublicKey, ObjectIdentifier, SecretDocument,
    der::{
        Decode,
        asn1::{self, AsUintRef},
    },
};
use zeroize::Zeroizing;

/// ObjectID for the RSA PSS keys
pub const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// Maximum allowed modulus size in bits.
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const MAX_MODULUS_BITS: usize = PublicKey::MAX_SIZE / 8;

// PKCS#1

/// Get the number of bits required to store a given `UintRef`.
fn bits_for_uint_ref(encoded_modulus: asn1::UintRef<'_>) -> pkcs1::Result<u32> {
    u32::try_from(encoded_modulus.as_bytes().len())
        .ok()
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or(pkcs1::Error::KeyMalformed)
}

/// Parse the modulus from an `asn1::UintRef`.
fn encoded_modulus_to_uint(encoded_modulus: asn1::UintRef<'_>) -> pkcs1::Result<BoxedUint> {
    if encoded_modulus.as_bytes().len() > MAX_MODULUS_BITS {
        return Err(pkcs1::Error::KeyMalformed);
    }

    let bits = bits_for_uint_ref(encoded_modulus)?;
    uint_from_slice(encoded_modulus.as_bytes(), bits)
}

/// Convert the given byte slice into a [`BoxedUint`].
fn uint_from_slice(data: &[u8], bits: u32) -> pkcs1::Result<BoxedUint> {
    BoxedUint::from_be_slice(data, bits).map_err(|_| pkcs1::Error::KeyMalformed)
}

impl pkcs1::DecodeRsaPrivateKey for PrivateKey {
    fn from_pkcs1_der(bytes: &[u8]) -> pkcs1::Result<Self> {
        pkcs1::RsaPrivateKeyRef::from_der(bytes)?.try_into()
    }
}

impl pkcs1::DecodeRsaPublicKey for PublicKey {
    fn from_pkcs1_der(bytes: &[u8]) -> pkcs1::Result<Self> {
        pkcs1::RsaPublicKeyRef::from_der(bytes)?.try_into()
    }
}

impl<U: AsUintRef> TryFrom<pkcs1::RsaPrivateKey<U>> for PrivateKey {
    type Error = pkcs1::Error;

    fn try_from(pkcs1_key: pkcs1::RsaPrivateKey<U>) -> pkcs1::Result<PrivateKey> {
        use pkcs1::Error::KeyMalformed;

        // Multi-prime RSA keys not currently supported
        if pkcs1_key.version() != pkcs1::Version::TwoPrime {
            return Err(pkcs1::Error::Version);
        }

        let n = encoded_modulus_to_uint(pkcs1_key.modulus.as_uint_ref())?;
        let bits = n.bit_width();
        let bits_e = bits_for_uint_ref(pkcs1_key.public_exponent.as_uint_ref())?;
        let e = uint_from_slice(pkcs1_key.public_exponent.as_uint_ref().as_bytes(), bits_e)?;
        let e = Option::from(e).ok_or(KeyMalformed)?;

        let d = uint_from_slice(pkcs1_key.private_exponent.as_uint_ref().as_bytes(), bits)?;
        let prime1 = uint_from_slice(pkcs1_key.prime1.as_uint_ref().as_bytes(), bits)?;
        let prime2 = uint_from_slice(pkcs1_key.prime2.as_uint_ref().as_bytes(), bits)?;
        let primes = vec![prime1, prime2];

        PrivateKey::from_components(n, e, d, primes).map_err(|_| KeyMalformed)
    }
}

impl<U: AsUintRef> TryFrom<pkcs1::RsaPublicKey<U>> for PublicKey {
    type Error = pkcs1::Error;

    fn try_from(pkcs1_key: pkcs1::RsaPublicKey<U>) -> pkcs1::Result<Self> {
        use pkcs1::Error::KeyMalformed;

        let n = encoded_modulus_to_uint(pkcs1_key.modulus.as_uint_ref())?;
        let bits_e = bits_for_uint_ref(pkcs1_key.public_exponent.as_uint_ref())?;
        let e = uint_from_slice(pkcs1_key.public_exponent.as_uint_ref().as_bytes(), bits_e)?;

        PublicKey::new(n, e).map_err(|_| KeyMalformed)
    }
}

impl pkcs1::EncodeRsaPrivateKey for PrivateKey {
    fn to_pkcs1_der(&self) -> pkcs1::Result<SecretDocument> {
        // Check if the key is multi prime
        if self.primes.len() > 2 {
            return Err(pkcs1::Error::Crypto);
        }

        let modulus = self.n().to_be_bytes();
        let public_exponent = self.e().to_be_bytes();
        let private_exponent = Zeroizing::new(self.d().to_be_bytes());
        let prime1 = Zeroizing::new(self.primes[0].to_be_bytes());
        let prime2 = Zeroizing::new(self.primes[1].to_be_bytes());

        let bits = self.d().bits_precision();

        debug_assert!(bits >= self.primes[0].bit_width_vartime());
        debug_assert!(bits >= self.primes[1].bit_width_vartime());

        let exponent1 = Zeroizing::new(
            (self.d()
                % NonZero::new(self.primes[0].as_ref().resize_unchecked(bits) - &BoxedUint::one())
                    .unwrap())
            .to_be_bytes(),
        );
        let exponent2 = Zeroizing::new(
            (self.d()
                % NonZero::new(self.primes[1].as_ref().resize_unchecked(bits) - &BoxedUint::one())
                    .unwrap())
            .to_be_bytes(),
        );
        let coefficient = Zeroizing::new(
            self.crt_coefficient()
                .ok_or(pkcs1::Error::Crypto)?
                .to_be_bytes(),
        );

        Ok(SecretDocument::encode_msg(&pkcs1::RsaPrivateKey {
            modulus: asn1::UintRef::new(&modulus)?,
            public_exponent: asn1::UintRef::new(&public_exponent)?,
            private_exponent: asn1::UintRef::new(&private_exponent)?,
            prime1: asn1::UintRef::new(&prime1)?,
            prime2: asn1::UintRef::new(&prime2)?,
            exponent1: asn1::UintRef::new(&exponent1)?,
            exponent2: asn1::UintRef::new(&exponent2)?,
            coefficient: asn1::UintRef::new(&coefficient)?,
            other_prime_infos: None,
        })?)
    }
}

impl pkcs1::EncodeRsaPublicKey for PublicKey {
    fn to_pkcs1_der(&self) -> pkcs1::Result<Document> {
        let modulus = self.n().to_be_bytes();
        let public_exponent = self.e().to_be_bytes();

        Ok(Document::encode_msg(&pkcs1::RsaPublicKeyRef {
            modulus: asn1::UintRef::new(&modulus)?,
            public_exponent: asn1::UintRef::new(&public_exponent)?,
        })?)
    }
}

// PKCS#8

/// Verify that the `AlgorithmIdentifier` for a key is correct.
pub(crate) fn verify_algorithm_id(algorithm: &spki::AlgorithmIdentifierRef) -> spki::Result<()> {
    match algorithm.oid {
        pkcs1::ALGORITHM_OID => {
            if algorithm.parameters_any()? != asn1::Null.into() {
                return Err(spki::Error::KeyMalformed);
            }
        }
        ID_RSASSA_PSS => {
            if algorithm.parameters.is_some() {
                return Err(spki::Error::KeyMalformed);
            }
        }
        _ => return Err(spki::Error::OidUnknown { oid: algorithm.oid }),
    };

    Ok(())
}

impl TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for PrivateKey {
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        verify_algorithm_id(&private_key_info.algorithm)?;

        pkcs1::RsaPrivateKeyRef::try_from(private_key_info.private_key)
            .and_then(TryInto::try_into)
            .map_err(pkcs1_error_to_pkcs8)
    }
}

impl TryFrom<pkcs8::SubjectPublicKeyInfoRef<'_>> for PublicKey {
    type Error = spki::Error;

    fn try_from(spki: pkcs8::SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        use spki::Error::KeyMalformed;

        verify_algorithm_id(&spki.algorithm)?;

        pkcs1::RsaPublicKeyRef::try_from(spki.subject_public_key.as_bytes().ok_or(KeyMalformed)?)
            .and_then(TryInto::try_into)
            .map_err(pkcs1_error_to_spki)
    }
}

impl EncodePrivateKey for PrivateKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        let private_key =
            pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(self).map_err(pkcs1_error_to_pkcs8)?;

        pkcs8::PrivateKeyInfoRef::new(
            pkcs1::ALGORITHM_ID,
            asn1::OctetStringRef::new(private_key.as_bytes())?,
        )
        .try_into()
    }
}

impl EncodePublicKey for PublicKey {
    fn to_public_key_der(&self) -> spki::Result<Document> {
        let subject_public_key =
            pkcs1::EncodeRsaPublicKey::to_pkcs1_der(self).map_err(pkcs1_error_to_spki)?;

        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs1::ALGORITHM_ID,
            subject_public_key: asn1::BitStringRef::new(0, subject_public_key.as_ref())?,
        }
        .try_into()
    }
}

/// Convert `pkcs1::Result` to `pkcs8::Result`.
fn pkcs1_error_to_pkcs8(error: pkcs1::Error) -> pkcs8::Error {
    match error {
        pkcs1::Error::Asn1(e) => pkcs8::Error::Asn1(e),
        _ => pkcs8::KeyError::Invalid.into(),
    }
}

/// Convert `pkcs1::Result` to `spki::Result`.
fn pkcs1_error_to_spki(error: pkcs1::Error) -> spki::Error {
    match error {
        pkcs1::Error::Asn1(e) => spki::Error::Asn1(e),
        _ => spki::Error::KeyMalformed,
    }
}
