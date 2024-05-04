#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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
    unused_qualifications
)]

extern crate alloc;

use der::{
    AnyRef, DecodeValue, Encode, EncodeValue, FixedTag, Length, Reader, Tag, TagNumber, Writer,
};
use spki::ObjectIdentifier;

pub mod negotiation;

/// The `MechType` type is defined in [RFC 1508 Appendix B].
///
/// ```text
///   MechType ::= OBJECT IDENTIFIER
/// ```
///
/// [RFC 1508 Appendix B]: https://datatracker.ietf.org/doc/html/rfc1508#appendix-B
pub type MechType = ObjectIdentifier;

/// InitialContextToken as defined in [RFC 1508 Appendix B].
///
/// ```text
/// InitialContextToken ::=
/// -- option indication (delegation, etc.) indicated within
/// -- mechanism-specific token
/// [APPLICATION 0] IMPLICIT SEQUENCE {
///     thisMech MechType,
///     innerContextToken ANY DEFINED BY thisMec
///          -- contents mechanism-specific
///     }
/// ```
///
/// [RFC 1508 Appendix B]: https://datatracker.ietf.org/doc/html/rfc1508#appendix-B
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialContextToken<'a> {
    /// mechanism type OID
    pub this_mech: MechType,
    /// mechanism-specific content
    pub inner_context_token: AnyRef<'a>,
}

impl<'a> FixedTag for InitialContextToken<'a> {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::new(0),
    };
}

impl<'a> DecodeValue<'a> for InitialContextToken<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        Ok(Self {
            this_mech: reader.decode()?,
            inner_context_token: reader.decode()?,
        })
    }
}

impl<'a> EncodeValue for InitialContextToken<'a> {
    fn value_len(&self) -> der::Result<Length> {
        self.this_mech.encoded_len()? + self.inner_context_token.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.this_mech.encode(writer)?;
        self.inner_context_token.encode(writer)?;

        Ok(())
    }
}

/// The `SubsequentContextToken` type is defined in [RFC 1508 Appendix B].
///
/// ```text
/// subsequentContextToken ::= innerContextToken ANY
/// -- interpretation based on predecessor InitialContextToken
/// ```
///
/// [RFC 1508 Appendix B]: https://datatracker.ietf.org/doc/html/rfc1508#appendix-B
pub type SubsequentContextToken<'a> = AnyRef<'a>;

/// The `PerMsgToken` type is defined in [RFC 1508 Appendix B].
///
/// ```text
/// -- as emitted by GSS_Sign and processed by GSS_Verify
///         innerMsgToken ANY
/// ```
///
/// [RFC 1508 Appendix B]: https://datatracker.ietf.org/doc/html/rfc1508#appendix-B
pub type PerMsgToken<'a> = AnyRef<'a>;

/// The `SealedMessage` type is defined in [RFC 1508 Appendix B].
///
/// ```text
/// SealedMessage ::=
/// -- as emitted by GSS_Seal and processed by GSS_Unseal
/// -- includes internal, mechanism-defined indicator
/// -- of whether or not encrypted
///         sealedUserData ANY
/// ```
///
/// [RFC 1508 Appendix B]: https://datatracker.ietf.org/doc/html/rfc1508#appendix-B
pub type SealedMessage<'a> = AnyRef<'a>;

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use spki::ObjectIdentifier;

    use super::*;

    use der::Decode;

    #[test]
    fn initial_context_token() {
        let gss_bytes = hex!("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d535350000100000005028862000000000000000000000000000000000601b01d0000000f");
        let inner_bytes = hex!("303ca00e300c060a2b06010401823702020aa22a04284e544c4d535350000100000005028862000000000000000000000000000000000601b01d0000000f");

        let gss = InitialContextToken::from_der(&gss_bytes).unwrap();

        assert_eq!(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.2"), gss.this_mech);
        assert_eq!(
            AnyRef::new(
                Tag::ContextSpecific {
                    constructed: true,
                    number: TagNumber::N0
                },
                &inner_bytes
            )
            .unwrap(),
            gss.inner_context_token
        );

        let output = InitialContextToken {
            this_mech: MechType::new_unwrap("1.3.6.1.5.5.2"),
            inner_context_token: AnyRef::new(
                Tag::ContextSpecific {
                    constructed: true,
                    number: TagNumber::N0,
                },
                &inner_bytes,
            )
            .unwrap(),
        };

        let output_bytes = output.to_der().unwrap();

        assert_eq!(&gss_bytes[..], &output_bytes);
    }
}
