//! SignedData-related types

use crate::cert::{CertificateChoices, IssuerAndSerialNumber};
use crate::content_info::CmsVersion;
use crate::revocation::RevocationInfoChoices;

use core::cmp::Ordering;
use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Choice, DerOrd, Sequence, ValueOrd};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attributes;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::impl_newtype;

/// The `SignedData` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
///   SignedData ::= SEQUENCE {
///       version CMSVersion,
///       digestAlgorithms SET OF DigestAlgorithmIdentifier,
///       encapContentInfo EncapsulatedContentInfo,
///       certificates [0] IMPLICIT CertificateSet OPTIONAL,
///       crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///       signerInfos SignerInfos }
/// ```
///
/// [RFC 5652 Section 5.1]: https://www.rfc-editor.org/rfc/rfc5652#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SignedData {
    pub version: CmsVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub encap_content_info: EncapsulatedContentInfo,
    //todo consider defer decoding certs and CRLs
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<CertificateSet>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<RevocationInfoChoices>,
    pub signer_infos: SignerInfos,
}

/// The `DigestAlgorithmIdentifiers` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// ```
///
/// [RFC 5652 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.1
pub type DigestAlgorithmIdentifiers = SetOfVec<AlgorithmIdentifierOwned>;

/// CertificateSet structure as defined in [RFC 5652 Section 10.2.3].
///
/// ```text
///   CertificateSet ::= SET OF CertificateChoices
/// ```
///
/// [RFC 5652 Section 10.2.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.3
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CertificateSet(pub SetOfVec<CertificateChoices>);
impl_newtype!(CertificateSet, SetOfVec<CertificateChoices>);

#[cfg(feature = "std")]
impl TryFrom<std::vec::Vec<CertificateChoices>> for CertificateSet {
    type Error = der::Error;

    fn try_from(vec: std::vec::Vec<CertificateChoices>) -> der::Result<CertificateSet> {
        Ok(CertificateSet(SetOfVec::try_from(vec)?))
    }
}

/// The `SignerInfos` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
///   SignerInfos ::= SET OF SignerInfo
/// ```
///
/// [RFC 5652 Section 5.1]: https://www.rfc-editor.org/rfc/rfc5652#section-5.1
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SignerInfos(pub SetOfVec<SignerInfo>);
impl_newtype!(SignerInfos, SetOfVec<SignerInfo>);

#[cfg(feature = "std")]
impl TryFrom<std::vec::Vec<SignerInfo>> for SignerInfos {
    type Error = der::Error;

    fn try_from(vec: std::vec::Vec<SignerInfo>) -> der::Result<SignerInfos> {
        Ok(SignerInfos(SetOfVec::try_from(vec)?))
    }
}

/// The `EncapsulatedContentInfo` type is defined in [RFC 5652 Section 5.2].
///
/// ```text
///   EncapsulatedContentInfo ::= SEQUENCE {
///       eContentType       CONTENT-TYPE.&id({ContentSet}),
///       eContent           [0] EXPLICIT OCTET STRING
///               ( CONTAINING CONTENT-TYPE.
///                   &Type({ContentSet}{@eContentType})) OPTIONAL }
/// ```
///
/// [RFC 5652 Section 5.2]: https://www.rfc-editor.org/rfc/rfc5652#section-5.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncapsulatedContentInfo {
    pub econtent_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub econtent: Option<Any>,
}

/// The `SignerInfo` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
///   SignerInfo ::= SEQUENCE {
///       version CMSVersion,
///       sid SignerIdentifier,
///       digestAlgorithm DigestAlgorithmIdentifier,
///       signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///       signatureAlgorithm SignatureAlgorithmIdentifier,
///       signature SignatureValue,
///       unsignedAttrs [1] IMPLICIT Attributes
///           {{UnsignedAttributes}} OPTIONAL }
/// ```
///
/// [RFC 5652 Section 5.3]: https://www.rfc-editor.org/rfc/rfc5652#section-5.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct SignerInfo {
    pub version: CmsVersion,
    pub sid: SignerIdentifier,
    pub digest_alg: AlgorithmIdentifierOwned,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub signed_attrs: Option<SignedAttributes>,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: SignatureValue,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unsigned_attrs: Option<UnsignedAttributes>,
}

/// The `SignerInfo` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
///
/// [RFC 5652 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
pub type SignedAttributes = Attributes;

/// The `SignerIdentifier` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier \[0\] SubjectKeyIdentifier }
/// ```
///
/// [RFC 5652 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

// TODO DEFER ValueOrd is not supported for CHOICE types (see new_enum in value_ord.rs)
impl ValueOrd for SignerIdentifier {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        use der::Encode;
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

/// The `UnsignedAttributes` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
///
/// [RFC 5652 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
pub type UnsignedAttributes = Attributes;

/// The `SignatureValue` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
///   SignatureValue ::= OCTET STRING
/// ```
///
/// [RFC 5652 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
pub type SignatureValue = OctetString;
