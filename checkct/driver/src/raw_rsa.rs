//! Small private-operation fixtures through the public hazmat API, plus the reduction helper.

use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use crypto_bigint::{
    BoxedUint, NonZero, Odd, U64, U128,
    modular::{BoxedMontyForm, BoxedMontyParams, FixedMontyParams, MontyParams},
};
use rsa::{
    CrtValue, PublicKey,
    hazmat::rsa_decrypt,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use zeroize::Zeroizing;

#[checkct]
pub fn rsa_decrypt_unblinded_non_crt_128() {
    // SAFETY: This independent, single-threaded analysis has no live allocations.
    unsafe { crate::allocator::reset() };

    // Public modulus (2^64 - 59) * (2^64 - 83), with fixed 128-bit precision.
    let n = BoxedUint::from_be_hex("FFFFFFFFFFFFFF720000000000001321", 128).unwrap();
    let public = PublicKey::new_with_size_limits(n, BoxedUint::from(65537u64), 128..=128).unwrap();

    let mut bytes = [0u8; 16];
    PrivateRng.fill_bytes(&mut bytes);
    let key = NonCrtKey {
        public,
        d: Zeroizing::new(BoxedUint::from_be_slice(&bytes, 128).unwrap()),
    };

    PublicRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f; // Public ciphertext below 2^127 is below the modulus.
    let c = BoxedUint::from_be_slice(&bytes, 128).unwrap();

    // `None` disables blinding. The API processes all 128 exponent bits, including leading zeros.
    // The fixture below selects the non-CRT path.
    let m = rsa_decrypt::<PrivateRng>(None, &key, &c).unwrap();
    black_box(m.as_limbs());
    drop(m);
    drop(key);
}

// Leave `d` unconstrained without including key validation or CRT precomputation in the analysis.
// This fixture checks the private operation's arithmetic, not whether the supplied exponent forms a
// valid RSA key.
struct NonCrtKey {
    public: PublicKey,
    d: Zeroizing<BoxedUint>,
}

impl PublicKeyParts for NonCrtKey {
    fn n(&self) -> &NonZero<BoxedUint> {
        self.public.n()
    }

    fn e(&self) -> &BoxedUint {
        self.public.e()
    }

    fn n_params(&self) -> &BoxedMontyParams {
        self.public.n_params()
    }
}

impl PrivateKeyParts for NonCrtKey {
    fn d(&self) -> &BoxedUint {
        &self.d
    }

    fn primes(&self) -> &[Odd<BoxedUint>] {
        &[]
    }

    fn p(&self) -> Option<&MontyParams<BoxedUint>> {
        None
    }

    fn q(&self) -> Option<&MontyParams<BoxedUint>> {
        None
    }

    fn dp(&self) -> Option<&BoxedUint> {
        None
    }

    fn dq(&self) -> Option<&BoxedUint> {
        None
    }

    fn qinv(&self) -> Option<&BoxedMontyForm> {
        None
    }

    fn crt_values(&self) -> Option<&[CrtValue]> {
        None
    }
}

// These parameters deliberately overapproximate valid RSA keys. Their values are all secret,
// their precisions are public, and each modulus is odd. This checks arithmetic, not key
// validation, the relation n=p*q, or blinding's rejection sampling.
#[checkct]
pub fn rsa_decrypt_unblinded_crt_128() {
    // SAFETY: This independent, single-threaded analysis has no live allocations.
    unsafe { crate::allocator::reset() };

    let n = BoxedUint::from_be_hex("FFFFFFFFFFFFFF720000000000001321", 128).unwrap();
    let public = PublicKey::new_with_size_limits(n, BoxedUint::from(65537u64), 128..=128).unwrap();
    let p = secret_modulus_64();
    let q = secret_modulus_64();
    let primes = vec![p.modulus().clone(), q.modulus().clone()];
    let key = CrtKey {
        public,
        d: BoxedUint::zero_with_precision(128), // Unused on the CRT path.
        qinv: BoxedMontyForm::new(secret_64(), &p),
        p,
        q,
        primes,
        dp: secret_64(),
        dq: secret_64(),
    };
    let mut bytes = [0u8; 16];
    PrivateRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f; // Also covers a secret (already blinded) representative below n.
    let c = BoxedUint::from_be_slice(&bytes, 128).unwrap();
    let m = rsa_decrypt::<PrivateRng>(None, &key, &c).unwrap();
    black_box(m.as_limbs());
}

#[checkct]
pub fn secret_modulus_reduction_192_to_128() {
    // SAFETY: This independent, single-threaded analysis has no live allocations.
    unsafe { crate::allocator::reset() };

    let mut bytes = [0u8; 16];
    PrivateRng.fill_bytes(&mut bytes);
    bytes[15] |= 1;

    let p = BoxedMontyParams::from(FixedMontyParams::new(
        Odd::new(U128::from_be_slice(&bytes)).unwrap(),
    ));

    let mut bytes = [0u8; 24];
    PrivateRng.fill_bytes(&mut bytes);
    let x = BoxedUint::from_be_slice(&bytes, 192).unwrap();
    let out = crate::reduction::to_monty(&x, &p).retrieve();
    black_box(out.as_limbs());
}

fn secret_64() -> BoxedUint {
    let mut bytes = [0u8; 8];
    PrivateRng.fill_bytes(&mut bytes);
    BoxedUint::from_be_slice(&bytes, 64).unwrap()
}

fn secret_modulus_64() -> BoxedMontyParams {
    let mut bytes = [0u8; 8];
    PrivateRng.fill_bytes(&mut bytes);
    bytes[7] |= 1;

    // Build valid, secret precomputed parameters with the fixed-size constructor. The boxed
    // constructor has a modulus-one branch which requires an expensive arithmetic proof in BINSEC.
    // Key import/precomputation is outside this private-operation fixture's scope.
    BoxedMontyParams::from(FixedMontyParams::new(
        Odd::new(U64::from_be_slice(&bytes)).unwrap(),
    ))
}

struct CrtKey {
    public: PublicKey,
    d: BoxedUint,
    primes: alloc::vec::Vec<Odd<BoxedUint>>,
    p: BoxedMontyParams,
    q: BoxedMontyParams,
    dp: BoxedUint,
    dq: BoxedUint,
    qinv: BoxedMontyForm,
}

impl PublicKeyParts for CrtKey {
    fn n(&self) -> &NonZero<BoxedUint> {
        self.public.n()
    }
    fn e(&self) -> &BoxedUint {
        self.public.e()
    }
    fn n_params(&self) -> &BoxedMontyParams {
        self.public.n_params()
    }
}

impl PrivateKeyParts for CrtKey {
    fn d(&self) -> &BoxedUint {
        &self.d
    }

    fn primes(&self) -> &[Odd<BoxedUint>] {
        &self.primes
    }

    fn p(&self) -> Option<&MontyParams<BoxedUint>> {
        Some(self.p.as_ref())
    }

    fn q(&self) -> Option<&MontyParams<BoxedUint>> {
        Some(self.q.as_ref())
    }

    fn dp(&self) -> Option<&BoxedUint> {
        Some(&self.dp)
    }

    fn dq(&self) -> Option<&BoxedUint> {
        Some(&self.dq)
    }

    fn qinv(&self) -> Option<&BoxedMontyForm> {
        Some(&self.qinv)
    }

    fn crt_values(&self) -> Option<&[CrtValue]> {
        None
    }
}
