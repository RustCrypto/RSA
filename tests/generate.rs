//! Default RSA key generation and fallible RNG support.

use rand::rngs::ChaCha8Rng;
use rand_core::{SeedableRng, TryCryptoRng, TryRng};
#[cfg(feature = "pkcs1v15")]
use rsa::pkcs1v15;
use rsa::{
    BoxedUint, Error, Generate, PrivateKey, pss,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use sha2::Sha256;
use signature::{Keypair, RandomizedSigner, Verifier};

fn rng() -> ChaCha8Rng {
    ChaCha8Rng::from_seed([42; 32])
}

fn check_key(key: &PrivateKey) {
    assert_eq!(PrivateKey::DEFAULT_BITS, 3072);
    assert_eq!(key.n().bit_width(), 3072);
    assert_eq!(key.e(), &BoxedUint::from(65537u64));
    assert_eq!(key.primes().len(), 2);
    assert_ne!(key.primes()[0], key.primes()[1]);
    assert!(key.dp().is_some());
    assert!(key.dq().is_some());
    assert!(key.qinv().is_some());
    key.validate().unwrap();
}

#[test]
fn generate_private_key() {
    let key = PrivateKey::generate_from_rng(&mut rng());
    check_key(&key);
    assert_eq!(
        key,
        PrivateKey::new(&mut rng(), PrivateKey::DEFAULT_BITS).unwrap()
    );
}

#[test]
#[cfg(feature = "pkcs1v15")]
fn generate_pkcs1v15_signing_key() {
    let key = pkcs1v15::SigningKey::<Sha256>::try_generate_from_rng(&mut rng()).unwrap();
    check_key(key.as_ref());
    let signature = key.try_sign_with_rng(&mut rng(), b"message").unwrap();
    // A verifying key with the standard digest prefix rejects unprefixed signatures.
    pkcs1v15::VerifyingKey::<Sha256>::new(key.as_ref().to_public_key())
        .verify(b"message", &signature)
        .unwrap();
}

#[test]
fn generate_pss_signing_key() {
    let key = pss::SigningKey::<Sha256>::try_generate_from_rng(&mut rng()).unwrap();
    check_key(key.as_ref());
    assert_eq!(key.salt_len(), 32);
    let signature = key.try_sign_with_rng(&mut rng(), b"message").unwrap();
    key.verifying_key().verify(b"message", &signature).unwrap();
}

// A non-Copy, non-Clone error carrying data makes error erasure observable.
#[derive(Debug, PartialEq)]
struct Exhausted(usize);

impl core::fmt::Display for Exhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "entropy exhausted after {} bytes", self.0)
    }
}

impl core::error::Error for Exhausted {}

struct RepeatingRng {
    budget: usize,
    used: usize,
}

impl TryRng for RepeatingRng {
    type Error = Exhausted;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        if bytes.len() > self.budget {
            return Err(Exhausted(self.used));
        }
        self.budget -= bytes.len();
        self.used += bytes.len();
        bytes.fill(0xaa);
        Ok(())
    }
}

impl TryCryptoRng for RepeatingRng {}

fn check_rng_error<T: Generate + core::fmt::Debug>(budget: usize) {
    let mut rng = RepeatingRng { budget, used: 0 };
    let rng: &mut dyn TryCryptoRng<Error = Exhausted> = &mut rng;
    assert_eq!(
        T::try_generate_from_rng(rng).unwrap_err(),
        Exhausted(budget)
    );
}

#[test]
fn generate_preserves_rng_errors() {
    // Fail before sampling, between primes, and after rejecting equal primes. The last case
    // ensures `Generate` retries an invalid candidate instead of returning it or panicking.
    for budget in [0, 192, 384] {
        check_rng_error::<PrivateKey>(budget);
    }
    #[cfg(feature = "pkcs1v15")]
    check_rng_error::<pkcs1v15::SigningKey<Sha256>>(0);
    check_rng_error::<pss::SigningKey<Sha256>>(0);

    // Existing constructors continue mapping RNG failures to `rsa::Error::Rng`.
    assert_eq!(
        PrivateKey::new(&mut RepeatingRng { budget: 0, used: 0 }, 3072),
        Err(Error::Rng)
    );
}

#[test]
#[cfg(feature = "getrandom")]
fn generate_with_system_rng() {
    check_key(&PrivateKey::try_generate().unwrap());
}
