//! `SignerInfo` data type [RFC 5652 § 5.3](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)

use crate::{
    algorithm_identifier_types::{DigestAlgorithmIdentifier, SignatureAlgorithmIdentifier},
    cms_version::CmsVersion,
};
use der::{
    asn1::{OctetStringRef, SetOfVec},
    Choice, Sequence, ValueOrd,
};
use x509_cert::{
    attr::Attribute, ext::pkix::SubjectKeyIdentifier, name::Name, serial_number::SerialNumber,
};

/// ```text
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
type SignedAttributes<'a> = SetOfVec<Attribute>;

/// ```text
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
type UnsignedAttributes<'a> = SetOfVec<Attribute>;

/// ```text
/// SignerIdentifier ::= CHOICE {
//    issuerAndSerialNumber IssuerAndSerialNumber,
//    subjectKeyIdentifier [0] SubjectKeyIdentifier }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice, ValueOrd)]
pub enum SignerIdentifier {
    /// issuer and serial number
    IssuerAndSerialNumber(IssuerAndSerialNumber),

    /// subject key identifier
    #[asn1(context_specific = "0")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct IssuerAndSerialNumber {
    pub name: Name,
    pub serial_number: SerialNumber,
}

/// ```text
/// SignerInfos ::= SET OF SignerInfo
/// ```
pub type SignerInfos<'a> = SetOfVec<SignerInfo<'a>>;

/// `SignerInfo` data type [RFC 5652 § 5.3](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)
///
/// ```text
/// SignerInfo ::= SEQUENCE {
///     version CMSVersion,
///     sid SignerIdentifier,
///     digestAlgorithm DigestAlgorithmIdentifier,
///     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///     signatureAlgorithm SignatureAlgorithmIdentifier,
///     signature SignatureValue,
///     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SignerInfo<'a> {
    /// the syntax version number.
    pub version: CmsVersion,

    /// the signer identifier
    pub sid: SignerIdentifier,

    /// the message digest algorithm
    pub digest_algorithm: DigestAlgorithmIdentifier<'a>,

    /// the signed attributes
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub signed_attributes: Option<SignedAttributes<'a>>,

    /// the signature algorithm
    pub signature_algorithm: SignatureAlgorithmIdentifier<'a>,

    /// the signature for content or detached
    pub signature: OctetStringRef<'a>,

    /// the unsigned attributes
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub unsigned_attributes: Option<UnsignedAttributes<'a>>,
}
