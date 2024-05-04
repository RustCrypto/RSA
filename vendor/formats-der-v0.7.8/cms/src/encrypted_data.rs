//! EncryptedData-related types
use der::Sequence;

use x509_cert::attr::Attributes;

use crate::content_info::CmsVersion;
use crate::enveloped_data::EncryptedContentInfo;

/// The `EncryptedData` type is defined in [RFC 5652 Section 8].
///
/// ```text
///   EncryptedData ::= SEQUENCE {
///       version CMSVersion,
///       encryptedContentInfo EncryptedContentInfo,
///       ...,
///       [[2: unprotectedAttrs [1] IMPLICIT Attributes
///           {{UnprotectedEncAttributes}} OPTIONAL ]] }
/// ```
///
/// [RFC 5652 Section 8]: https://www.rfc-editor.org/rfc/rfc5652#section-8
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncryptedData {
    pub version: CmsVersion,
    pub enc_content_info: EncryptedContentInfo,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unprotected_attrs: Option<Attributes>,
}
