//! AuthenticatedData-related types

use der::asn1::OctetString;
use der::Sequence;

use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attributes;

use crate::content_info::CmsVersion;
use crate::enveloped_data::{OriginatorInfo, RecipientInfos};
use crate::signed_data::EncapsulatedContentInfo;

/// The `AuthenticatedData` type is defined in [RFC 5652 Section 9.1].
///
/// ```text
///   AuthenticatedData ::= SEQUENCE {
///       version CMSVersion,
///       originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///       recipientInfos RecipientInfos,
///       macAlgorithm MessageAuthenticationCodeAlgorithm,
///       digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
///       encapContentInfo EncapsulatedContentInfo,
///       authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
///       mac MessageAuthenticationCode,
///       unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
/// ```
///
/// [RFC 5652 Section 9.1]: https://www.rfc-editor.org/rfc/rfc5652#section-9.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct AuthenticatedData {
    pub version: CmsVersion,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub originator_info: Option<OriginatorInfo>,
    pub recip_infos: RecipientInfos,
    pub mac_alg: AlgorithmIdentifierOwned,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub digest_alg: Option<AlgorithmIdentifierOwned>,
    pub encap_content_info: EncapsulatedContentInfo,
    #[asn1(
        context_specific = "2",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub auth_attrs: Option<Attributes>,
    pub mac: MessageAuthenticationCode,
    #[asn1(
        context_specific = "3",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unauth_attrs: Option<Attributes>,
}
/// The `MessageAuthenticationCode` type is defined in [RFC 5652 Section 9.1].
///
/// ```text
///   MessageAuthenticationCode ::= OCTET STRING
/// ```
///
/// [RFC 5652 Section 9.1]: https://www.rfc-editor.org/rfc/rfc5652#section-9.1
pub type MessageAuthenticationCode = OctetString;
