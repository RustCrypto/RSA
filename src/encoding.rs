//! PKCS#1 encoding support

use crate::{key::PublicKeyParts, BigUint, RsaPrivateKey, RsaPublicKey};
use num_bigint::ModInverse;
use pkcs1::{
    FromRsaPrivateKey, FromRsaPublicKey, RsaPrivateKeyDocument, RsaPublicKeyDocument,
    ToRsaPrivateKey, ToRsaPublicKey,
};
use zeroize::Zeroizing;

impl FromRsaPrivateKey for RsaPrivateKey {
    fn from_pkcs1_private_key(pkcs1_key: pkcs1::RsaPrivateKey<'_>) -> pkcs1::Result<Self> {
        let n = BigUint::from_bytes_be(pkcs1_key.modulus.as_bytes());
        let e = BigUint::from_bytes_be(pkcs1_key.public_exponent.as_bytes());
        let d = BigUint::from_bytes_be(pkcs1_key.private_exponent.as_bytes());
        let prime1 = BigUint::from_bytes_be(pkcs1_key.prime1.as_bytes());
        let prime2 = BigUint::from_bytes_be(pkcs1_key.prime2.as_bytes());
        let primes = vec![prime1, prime2];
        Ok(RsaPrivateKey::from_components(n, e, d, primes))
    }
}

impl FromRsaPublicKey for RsaPublicKey {
    fn from_pkcs1_public_key(pkcs1_key: pkcs1::RsaPublicKey<'_>) -> pkcs1::Result<Self> {
        let n = BigUint::from_bytes_be(pkcs1_key.modulus.as_bytes());
        let e = BigUint::from_bytes_be(pkcs1_key.public_exponent.as_bytes());
        RsaPublicKey::new(n, e).map_err(|_| pkcs1::Error::Crypto)
    }
}

impl ToRsaPrivateKey for RsaPrivateKey {
    fn to_pkcs1_der(&self) -> pkcs1::Result<RsaPrivateKeyDocument> {
        // Check if the key is multi prime
        if self.primes.len() > 2 {
            return Err(pkcs1::Error::Version);
        }

        let modulus = self.n().to_bytes_be();
        let public_exponent = self.e().to_bytes_be();
        let private_exponent = Zeroizing::new(self.d().to_bytes_be());
        let prime1 = Zeroizing::new(self.primes[0].to_bytes_be());
        let prime2 = Zeroizing::new(self.primes[1].to_bytes_be());
        let exponent1 = Zeroizing::new((self.d() % (&self.primes[0] - 1u8)).to_bytes_be());
        let exponent2 = Zeroizing::new((self.d() % (&self.primes[1] - 1u8)).to_bytes_be());
        let coefficient = Zeroizing::new(
            (&self.primes[1])
                .mod_inverse(&self.primes[0])
                .ok_or(pkcs1::Error::Crypto)?
                .to_bytes_be()
                .1,
        );

        Ok(pkcs1::RsaPrivateKey {
            version: pkcs1::Version::TwoPrime,
            modulus: pkcs1::UIntBytes::new(&modulus)?,
            public_exponent: pkcs1::UIntBytes::new(&public_exponent)?,
            private_exponent: pkcs1::UIntBytes::new(&private_exponent)?,
            prime1: pkcs1::UIntBytes::new(&prime1)?,
            prime2: pkcs1::UIntBytes::new(&prime2)?,
            exponent1: pkcs1::UIntBytes::new(&exponent1)?,
            exponent2: pkcs1::UIntBytes::new(&exponent2)?,
            coefficient: pkcs1::UIntBytes::new(&coefficient)?,
        }
        .to_der())
    }
}

impl ToRsaPublicKey for RsaPublicKey {
    fn to_pkcs1_der(&self) -> pkcs1::Result<RsaPublicKeyDocument> {
        let modulus = self.n().to_bytes_be();
        let public_exponent = self.e().to_bytes_be();
        Ok(pkcs1::RsaPublicKey {
            modulus: pkcs1::UIntBytes::new(&modulus)?,
            public_exponent: pkcs1::UIntBytes::new(&public_exponent)?,
        }
        .to_der())
    }
}
