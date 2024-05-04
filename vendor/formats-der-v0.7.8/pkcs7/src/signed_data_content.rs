//! `signed-data` content type [RFC 5652 § 5](https://datatracker.ietf.org/doc/html/rfc5652#section-5)

use crate::{
    algorithm_identifier_types::DigestAlgorithmIdentifiers,
    certificate_choices::CertificateChoices, cms_version::CmsVersion,
    encapsulated_content_info::EncapsulatedContentInfo,
    revocation_info_choices::RevocationInfoChoices, signer_info::SignerInfos,
};
use der::{asn1::SetOfVec, Sequence};

/// ```text
/// CertificateSet ::= SET OF CertificateChoices
/// ```
pub type CertificateSet<'a> = SetOfVec<CertificateChoices<'a>>;

/// Signed-data content type [RFC 5652 § 5](https://datatracker.ietf.org/doc/html/rfc5652#section-5)
///
/// ```text
/// SignedData ::= SEQUENCE {
///     version CMSVersion,
///     digestAlgorithms DigestAlgorithmIdentifiers,
///     encapContentInfo EncapsulatedContentInfo,
///     certificates [0] IMPLICIT CertificateSet OPTIONAL,
///     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///     signerInfos SignerInfos }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignedDataContent<'a> {
    /// the syntax version number.
    pub version: CmsVersion,

    /// digest algorithm
    pub digest_algorithms: DigestAlgorithmIdentifiers<'a>,

    /// content
    pub encap_content_info: EncapsulatedContentInfo<'a>,

    /// certs
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub certificates: Option<CertificateSet<'a>>,

    /// crls
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub crls: Option<RevocationInfoChoices<'a>>,

    /// signer info
    pub signer_infos: SignerInfos<'a>,
}
