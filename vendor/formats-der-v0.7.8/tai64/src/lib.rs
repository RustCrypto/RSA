#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(feature = "std")]
extern crate std;

use core::{fmt, ops, time::Duration};

#[cfg(feature = "serde")]
use serde::{de, ser, Deserialize, Serialize};

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Number of nanoseconds in a second
const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// A `TAI64` label.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Tai64(pub u64);

impl Tai64 {
    /// Unix epoch in `TAI64`: 1970-01-01 00:00:10 TAI.
    pub const UNIX_EPOCH: Self = Self(10 + (1 << 62));

    /// Length of serialized `TAI64` timestamp in bytes.
    pub const BYTE_SIZE: usize = 8;

    /// Get `TAI64N` timestamp according to system clock.
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        Tai64N::now().into()
    }

    /// Parse `TAI64` from a byte slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        slice.try_into()
    }

    /// Serialize TAI64 as bytes
    pub fn to_bytes(self) -> [u8; Self::BYTE_SIZE] {
        self.into()
    }

    /// Convert Unix timestamp to `TAI64`.
    pub fn from_unix(secs: i64) -> Self {
        Tai64((secs + 10 + (1 << 62)) as u64)
    }

    /// Convert `TAI64` to unix timestamp.
    pub fn to_unix(self) -> i64 {
        (self.0 as i64) - (10 + (1 << 62))
    }
}

impl From<Tai64N> for Tai64 {
    /// Remove the nanosecond component from a TAI64N value
    fn from(other: Tai64N) -> Self {
        other.0
    }
}

impl From<[u8; Tai64::BYTE_SIZE]> for Tai64 {
    /// Parse TAI64 from external representation
    fn from(bytes: [u8; Tai64::BYTE_SIZE]) -> Self {
        Tai64(u64::from_be_bytes(bytes))
    }
}

impl<'a> TryFrom<&'a [u8]> for Tai64 {
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self, Error> {
        let bytes: [u8; Tai64::BYTE_SIZE] = slice.try_into().map_err(|_| Error::LengthInvalid)?;
        Ok(bytes.into())
    }
}

impl From<Tai64> for [u8; 8] {
    /// Serialize TAI64 to external representation
    fn from(tai: Tai64) -> [u8; 8] {
        tai.0.to_be_bytes()
    }
}

impl ops::Add<u64> for Tai64 {
    type Output = Self;

    fn add(self, x: u64) -> Self {
        Tai64(self.0 + x)
    }
}

impl ops::Sub<u64> for Tai64 {
    type Output = Self;

    fn sub(self, x: u64) -> Self {
        Tai64(self.0 - x)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Tai64 {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(<[u8; Tai64::BYTE_SIZE]>::deserialize(deserializer)?.into())
    }
}

#[cfg(feature = "serde")]
impl Serialize for Tai64 {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_bytes().serialize(serializer)
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Tai64 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// A `TAI64N` timestamp.
///
/// Invariant: The nanosecond part <= 999999999.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Tai64N(pub Tai64, pub u32);

#[cfg(feature = "zeroize")]
impl Zeroize for Tai64N {
    fn zeroize(&mut self) {
        self.0.zeroize();
        self.1.zeroize();
    }
}

impl Tai64N {
    /// Unix epoch in `TAI64N`: 1970-01-01 00:00:10 TAI.
    pub const UNIX_EPOCH: Self = Self(Tai64::UNIX_EPOCH, 0);

    /// Length of serialized `TAI64N` timestamp.
    pub const BYTE_SIZE: usize = 12;

    /// Get `TAI64N` timestamp according to system clock.
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        Self::from_system_time(&SystemTime::now())
    }

    /// Parse TAI64N from a byte slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        slice.try_into()
    }

    /// Serialize TAI64N as bytes
    pub fn to_bytes(self) -> [u8; Tai64N::BYTE_SIZE] {
        self.into()
    }

    /// Calculate how much time passes since the `other` timestamp.
    ///
    /// Returns `Ok(Duration)` if `other` is earlier than `self`,
    /// `Err(Duration)` otherwise.
    pub fn duration_since(&self, other: &Self) -> Result<Duration, Duration> {
        if self >= other {
            let (carry, n) = if self.1 >= other.1 {
                (0, self.1 - other.1)
            } else {
                (1, NANOS_PER_SECOND + self.1 - other.1)
            };

            let s = (self.0).0 - carry - (other.0).0;
            Ok(Duration::new(s, n))
        } else {
            #[allow(clippy::unwrap_used)]
            Err(other.duration_since(self).unwrap())
        }
    }

    /// Convert `SystemTime` to `TAI64N`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[cfg(feature = "std")]
    pub fn from_system_time(t: &SystemTime) -> Self {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Self::UNIX_EPOCH + d,
            Err(e) => Self::UNIX_EPOCH - e.duration(),
        }
    }

    /// Convert `TAI64N`to `SystemTime`.
    #[cfg(feature = "std")]
    pub fn to_system_time(self) -> SystemTime {
        match self.duration_since(&Self::UNIX_EPOCH) {
            Ok(d) => UNIX_EPOCH + d,
            Err(d) => UNIX_EPOCH - d,
        }
    }
}

impl From<Tai64> for Tai64N {
    /// Remove the nanosecond component from a TAI64N value
    fn from(other: Tai64) -> Self {
        Tai64N(other, 0)
    }
}

impl TryFrom<[u8; Self::BYTE_SIZE]> for Tai64N {
    type Error = Error;

    /// Parse TAI64 from external representation
    fn try_from(bytes: [u8; Tai64N::BYTE_SIZE]) -> Result<Self, Error> {
        let secs = Tai64::from_slice(&bytes[..Tai64::BYTE_SIZE])?;

        let mut nano_bytes = [0u8; 4];
        nano_bytes.copy_from_slice(&bytes[Tai64::BYTE_SIZE..]);
        let nanos = u32::from_be_bytes(nano_bytes);

        if nanos < NANOS_PER_SECOND {
            Ok(Tai64N(secs, nanos))
        } else {
            Err(Error::NanosInvalid)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Tai64N {
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self, Error> {
        let bytes: [u8; Tai64N::BYTE_SIZE] = slice.try_into().map_err(|_| Error::LengthInvalid)?;
        bytes.try_into()
    }
}

impl From<Tai64N> for [u8; Tai64N::BYTE_SIZE] {
    /// Serialize TAI64 to external representation
    fn from(tai: Tai64N) -> [u8; Tai64N::BYTE_SIZE] {
        let mut result = [0u8; Tai64N::BYTE_SIZE];
        result[..Tai64::BYTE_SIZE].copy_from_slice(&tai.0.to_bytes());
        result[Tai64::BYTE_SIZE..].copy_from_slice(&tai.1.to_be_bytes());
        result
    }
}

#[cfg(feature = "std")]
impl From<SystemTime> for Tai64N {
    fn from(t: SystemTime) -> Self {
        Tai64N::from_system_time(&t)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl ops::Add<Duration> for Tai64N {
    type Output = Self;

    fn add(self, d: Duration) -> Self {
        let n = self.1 + d.subsec_nanos();

        let (carry, n) = if n >= NANOS_PER_SECOND {
            (1, n - NANOS_PER_SECOND)
        } else {
            (0, n)
        };

        Tai64N(self.0 + d.as_secs() + carry, n)
    }
}

impl ops::Sub<Duration> for Tai64N {
    type Output = Self;

    fn sub(self, d: Duration) -> Self {
        let (carry, n) = if self.1 >= d.subsec_nanos() {
            (0, self.1 - d.subsec_nanos())
        } else {
            (1, NANOS_PER_SECOND + self.1 - d.subsec_nanos())
        };
        Tai64N(self.0 - carry - d.as_secs(), n)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Tai64N {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use de::Error;
        <[u8; Tai64N::BYTE_SIZE]>::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Tai64N {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_bytes().serialize(serializer)
    }
}

/// TAI64 errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid length
    LengthInvalid,

    /// Nanosecond part must be <= 999999999.
    NanosInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Error::LengthInvalid => "length invalid",
            Error::NanosInvalid => "invalid number of nanoseconds",
        };

        write!(f, "{}", description)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn before_epoch() {
        let t = UNIX_EPOCH - Duration::new(0, 1);
        let tai64n = Tai64N::from_system_time(&t);
        let t1 = tai64n.to_system_time();

        assert_eq!(t, t1);

        let t = UNIX_EPOCH - Duration::new(488294802189, 999999999);
        let tai64n = Tai64N::from_system_time(&t);
        let t1 = tai64n.to_system_time();

        assert_eq!(t, t1);

        let t = UNIX_EPOCH - Duration::new(73234, 68416841);
        let tai64n = Tai64N::from_system_time(&t);
        let t1 = tai64n.to_system_time();

        assert_eq!(t, t1);
    }
}
