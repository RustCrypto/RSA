//! `enveloped-data` content type [RFC 5652 § 6](https://datatracker.ietf.org/doc/html/rfc5652#section-6)

use crate::ContentType;

use der::{asn1::OctetStringRef, Sequence};
use spki::AlgorithmIdentifierRef;

type ContentEncryptionAlgorithmIdentifier<'a> = AlgorithmIdentifierRef<'a>;

/// Encrypted content information [RFC 5652 § 6](https://datatracker.ietf.org/doc/html/rfc5652#section-6)
///
/// ```text
/// EncryptedContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   contentEncryptionAlgorithm
///     ContentEncryptionAlgorithmIdentifier,
///   encryptedContent
///     [0] IMPLICIT EncryptedContent OPTIONAL }
///
/// ContentEncryptionAlgorithmIdentifier ::=
///   AlgorithmIdentifier
///
/// EncryptedContent ::= OCTET STRING
/// ```
///
/// The fields of type `EncryptedContentInfo` have the following meanings:
///   - [`content_type`](EncryptedContentInfo::content_type) indicates the type of content.
///   - [`content_encryption_algorithm`](EncryptedContentInfo::content_encryption_algorithm)
///     identifies the content-encryption algorithm (and any associated parameters) under
///     which the content is encrypted.
///     This algorithm is the same for all recipients.
///   - [`encrypted_content`](EncryptedContentInfo::encrypted_content) is the result of
///     encrypting the content. The field is optional, and if the field is not present,
///     its intended value must be supplied by other means.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub struct EncryptedContentInfo<'a> {
    /// indicates the type of content.
    pub content_type: ContentType,

    /// identifies the content-encryption algorithm (and any associated parameters) under
    /// which the content is encrypted.
    pub content_encryption_algorithm: ContentEncryptionAlgorithmIdentifier<'a>,

    /// the encrypted contents;
    /// when not present, its intended value must be supplied by other means.
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub encrypted_content: Option<OctetStringRef<'a>>,
}
