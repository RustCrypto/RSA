//! `encapsulated-data` content type [RFC 5652 § 5.2](https://datatracker.ietf.org/doc/html/rfc5652#section-5.2)

use der::{AnyRef, Sequence};
use spki::ObjectIdentifier;

/// Encapsulated content information [RFC 5652 § 5.2](https://datatracker.ietf.org/doc/html/rfc5652#section-5.2)
///
/// ```text
/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType ContentType,
///   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
/// ```
/// Due to a difference in PKCS #7 and CMS the contents type can be either
/// ```text
/// content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
/// ```
/// or
/// ```text
/// eContent [0] EXPLICIT OCTET STRING OPTIONAL
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub struct EncapsulatedContentInfo<'a> {
    /// indicates the type of content.
    pub e_content_type: ObjectIdentifier,

    /// encapsulated content
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub e_content: Option<AnyRef<'a>>,
}
