//! Serialization primitives for arrays.

use core::fmt;

use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Serialize the given type as lower case hex when using human-readable
/// formats or binary if the format is binary.
pub fn serialize_hex_lower_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    if serializer.is_human_readable() {
        crate::serialize_hex::<_, _, false>(value, serializer)
    } else {
        let mut seq = serializer.serialize_tuple(value.as_ref().len())?;

        for byte in value.as_ref() {
            seq.serialize_element(byte)?;
        }

        seq.end()
    }
}

/// Serialize the given type as upper case hex when using human-readable
/// formats or binary if the format is binary.
pub fn serialize_hex_upper_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    if serializer.is_human_readable() {
        crate::serialize_hex::<_, _, true>(value, serializer)
    } else {
        let mut seq = serializer.serialize_tuple(value.as_ref().len())?;

        for byte in value.as_ref() {
            seq.serialize_element(byte)?;
        }

        seq.end()
    }
}

/// Deserialize from hex when using human-readable formats or binary if the
/// format is binary. Fails if the `buffer` isn't the exact same size as the
/// resulting array.
pub fn deserialize_hex_or_bin<'de, D>(buffer: &mut [u8], deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        struct StrVisitor<'b>(&'b mut [u8]);

        impl<'de> Visitor<'de> for StrVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string of length {}", self.0.len() * 2)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v.len() != self.0.len() * 2 {
                    return Err(Error::invalid_length(v.len(), &self));
                }

                base16ct::mixed::decode(v, self.0).map_err(E::custom)?;

                Ok(())
            }
        }

        deserializer.deserialize_str(StrVisitor(buffer))
    } else {
        struct ArrayVisitor<'b>(&'b mut [u8]);

        impl<'de> Visitor<'de> for ArrayVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array of length {}", self.0.len())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                for (index, byte) in self.0.iter_mut().enumerate() {
                    *byte = match seq.next_element()? {
                        Some(byte) => byte,
                        None => return Err(Error::invalid_length(index, &self)),
                    };
                }

                Ok(())
            }
        }

        deserializer.deserialize_tuple(buffer.len(), ArrayVisitor(buffer))
    }
}

/// [`HexOrBin`] serializer which uses lower case.
pub type HexLowerOrBin<const N: usize> = HexOrBin<N, false>;

/// [`HexOrBin`] serializer which uses upper case.
pub type HexUpperOrBin<const N: usize> = HexOrBin<N, true>;

/// Serializer/deserializer newtype which encodes bytes as either binary or hex.
///
/// Use hexadecimal with human-readable formats, or raw binary with binary formats.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HexOrBin<const N: usize, const UPPERCASE: bool>(pub [u8; N]);

impl<const N: usize, const UPPERCASE: bool> Default for HexOrBin<N, UPPERCASE> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize, const UPPERCASE: bool> AsRef<[u8]> for HexOrBin<N, UPPERCASE> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize, const UPPERCASE: bool> From<&[u8; N]> for HexOrBin<N, UPPERCASE> {
    fn from(bytes: &[u8; N]) -> Self {
        Self(*bytes)
    }
}

impl<const N: usize, const UPPERCASE: bool> From<[u8; N]> for HexOrBin<N, UPPERCASE> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize, const UPPERCASE: bool> From<HexOrBin<N, UPPERCASE>> for [u8; N] {
    fn from(hex_or_bin: HexOrBin<N, UPPERCASE>) -> Self {
        hex_or_bin.0
    }
}

impl<const N: usize, const UPPERCASE: bool> Serialize for HexOrBin<N, UPPERCASE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if UPPERCASE {
            serialize_hex_upper_or_bin(self, serializer)
        } else {
            serialize_hex_lower_or_bin(self, serializer)
        }
    }
}

impl<'de, const N: usize, const UPPERCASE: bool> Deserialize<'de> for HexOrBin<N, UPPERCASE> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut buffer = [0; N];
        deserialize_hex_or_bin(&mut buffer, deserializer)?;

        Ok(Self(buffer))
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize, const UPPERCASE: bool> Zeroize for HexOrBin<N, UPPERCASE> {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}
