use alloc::vec::Vec;
use num_bigint::traits::ModInverse;
use num_bigint::Sign::Plus;
use num_bigint::{BigInt, BigUint};
use num_traits::One;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::errors::{Error, Result};

pub trait PublicKeyParts {
    /// Returns the modulus of the key.
    fn n(&self) -> &BigUint;

    /// Returns the public exponent of the key.
    fn e(&self) -> &BigUint;

    /// Returns the modulus size in bytes. Raw signatures and ciphertexts for
    /// or by this public key will have the same size.
    fn size(&self) -> usize {
        (self.n().bits() + 7) / 8
    }
}

pub trait PrivateKeyParts {
    /// Returns the private exponent of the key.
    fn d(&self) -> &BigUint;
    /// Returns the prime factors.
    fn primes(&self) -> &[BigUint];
}

/// Internal trait, not to be exported outside of the crate
pub trait PrivateKeyPartsInt: PrivateKeyParts {
    fn precomputed(&self) -> &Option<PrecomputedValues>;
}

/// Internal representation of the public part of an RSA key.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub(crate) struct RsaPrivateKeyComponents {
    /// Private exponent
    d: BigUint,
    /// Prime factors of N, contains >= 2 elements.
    primes: Vec<BigUint>,
    /// precomputed values to speed up private operations
    #[cfg_attr(feature = "serde", serde(skip))]
    precomputed: Option<PrecomputedValues>,
}

impl RsaPrivateKeyComponents {
    pub fn new(d: BigUint, primes: Vec<BigUint>) -> RsaPrivateKeyComponents {
        let mut k = RsaPrivateKeyComponents {
            d,
            primes,
            precomputed: None,
        };

        let _ = k.precompute();

        k
    }
    /// Performs some calculations to speed up private key operations.
    pub fn precompute(&mut self) -> Result<()> {
        if self.precomputed.is_some() {
            return Ok(());
        }

        let dp = &self.d % (&self.primes[0] - BigUint::one());
        let dq = &self.d % (&self.primes[1] - BigUint::one());
        let qinv = self.primes[1]
            .clone()
            .mod_inverse(&self.primes[0])
            .ok_or(Error::InvalidPrime)?;

        let mut r: BigUint = &self.primes[0] * &self.primes[1];
        let crt_values: Vec<CRTValue> = {
            let mut values = Vec::with_capacity(self.primes.len() - 2);
            for prime in &self.primes[2..] {
                let res = CRTValue {
                    exp: BigInt::from_biguint(Plus, &self.d % (prime - BigUint::one())),
                    r: BigInt::from_biguint(Plus, r.clone()),
                    coeff: BigInt::from_biguint(
                        Plus,
                        r.clone()
                            .mod_inverse(prime)
                            .ok_or(Error::InvalidCoefficient)?
                            .to_biguint()
                            .unwrap(),
                    ),
                };
                r *= prime;

                values.push(res);
            }
            values
        };

        self.precomputed = Some(PrecomputedValues {
            dp,
            dq,
            qinv,
            crt_values,
        });

        Ok(())
    }

    /// Clears precomputed values by setting to None
    pub fn clear_precomputed(&mut self) {
        self.precomputed = None;
    }
}

impl PartialEq for RsaPrivateKeyComponents {
    #[inline]
    fn eq(&self, other: &RsaPrivateKeyComponents) -> bool {
        self.d == other.d && self.primes == other.primes
    }
}

impl Zeroize for RsaPrivateKeyComponents {
    fn zeroize(&mut self) {
        self.d.zeroize();
        for prime in self.primes.iter_mut() {
            prime.zeroize();
        }
        self.primes.clear();
        if self.precomputed.is_some() {
            self.precomputed.take().unwrap().zeroize();
        }
    }
}

impl Drop for RsaPrivateKeyComponents {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PrivateKeyParts for RsaPrivateKeyComponents {
    /// Returns the private exponent of the key.
    fn d(&self) -> &BigUint {
        &self.d
    }
    /// Returns the prime factors.
    fn primes(&self) -> &[BigUint] {
        &self.primes
    }
}

impl PrivateKeyPartsInt for RsaPrivateKeyComponents {
    fn precomputed(&self) -> &Option<PrecomputedValues> {
        &self.precomputed
    }
}

#[derive(Debug, Clone)]
pub struct PrecomputedValues {
    /// D mod (P-1)
    pub(crate) dp: BigUint,
    /// D mod (Q-1)
    pub(crate) dq: BigUint,
    /// Q^-1 mod P
    pub(crate) qinv: BigInt,

    /// CRTValues is used for the 3rd and subsequent primes. Due to a
    /// historical accident, the CRT for the first two primes is handled
    /// differently in PKCS#1 and interoperability is sufficiently
    /// important that we mirror this.
    pub(crate) crt_values: Vec<CRTValue>,
}

impl Zeroize for PrecomputedValues {
    fn zeroize(&mut self) {
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        for val in self.crt_values.iter_mut() {
            val.zeroize();
        }
        self.crt_values.clear();
    }
}

impl Drop for PrecomputedValues {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Contains the precomputed Chinese remainder theorem values.
#[derive(Debug, Clone)]
pub(crate) struct CRTValue {
    /// D mod (prime - 1)
    pub(crate) exp: BigInt,
    /// R·Coeff ≡ 1 mod Prime.
    pub(crate) coeff: BigInt,
    /// product of primes prior to this (inc p and q)
    pub(crate) r: BigInt,
}

impl Zeroize for CRTValue {
    fn zeroize(&mut self) {
        self.exp.zeroize();
        self.coeff.zeroize();
        self.r.zeroize();
    }
}
