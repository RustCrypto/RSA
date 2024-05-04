//! Request-related types

use alloc::vec::Vec;
use der::asn1::{BitString, Int};
use der::Sequence;

use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::Attribute;
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::Version;

use crate::controls::Controls;
use crate::pop::ProofOfPossession;

/// The `CertReqMessages` type is defined in [RFC 4211 Section 3].
///
/// ```text
///   CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
/// ```
///
/// [RFC 4211 Section 3]: https://www.rfc-editor.org/rfc/rfc4211#section-3
pub type CertReqMessages = Vec<CertReqMsg>;

/// The `CertReqMsg` type is defined in [RFC 4211 Section 3].
///
/// ```text
///   CertReqMsg ::= SEQUENCE {
///       certReq   CertRequest,
///       popo       ProofOfPossession  OPTIONAL,
///       -- content depends upon key type
///       regInfo   SEQUENCE SIZE(1..MAX) OF
///           SingleAttribute{{RegInfoSet}} OPTIONAL }
/// ```
///
/// [RFC 4211 Section 3]: https://www.rfc-editor.org/rfc/rfc4211#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertReqMsg {
    pub cert_req: CertRequest,
    pub popo: Option<ProofOfPossession>,
    pub reg_info: Option<AttributeSeq>,
}

/// AttributeSeq corresponds to the type that is inlined in the CertReqMsg definition for the regInfo
/// field, as shown below:
/// ```text
///       regInfo   SEQUENCE SIZE(1..MAX) OF
///           SingleAttribute{{RegInfoSet}} OPTIONAL }
/// ```
pub type AttributeSeq = Vec<Attribute>;

/// The `CertRequest` type is defined in [RFC 4211 Section 5].
///
/// ```text
///   CertRequest ::= SEQUENCE {
///       certReqId     INTEGER,
///       -- ID for matching request and reply
///       certTemplate  CertTemplate,
///       -- Selected fields of cert to be issued
///       controls      Controls OPTIONAL }
///       -- Attributes affecting issuance
/// ```
///
/// [RFC 4211 Section 5]: https://www.rfc-editor.org/rfc/rfc4211#section-5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertRequest {
    pub cert_req_id: Int,
    pub cert_template: CertTemplate,
    pub controls: Option<Controls>,
}

/// The `CertTemplate` type is defined in [RFC 4211 Section 5].
///
/// ```text
///   CertTemplate ::= SEQUENCE {
///       version      [0] Version               OPTIONAL,
///       serialNumber [1] INTEGER               OPTIONAL,
///       signingAlg   [2] AlgorithmIdentifier{SIGNATURE-ALGORITHM,
///                            {SignatureAlgorithms}}   OPTIONAL,
///       issuer       [3] Name                  OPTIONAL,
///       validity     [4] OptionalValidity      OPTIONAL,
///       subject      [5] Name                  OPTIONAL,
///       publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
///       issuerUID    [7] UniqueIdentifier      OPTIONAL,
///       subjectUID   [8] UniqueIdentifier      OPTIONAL,
///       extensions   [9] Extensions{{CertExtensions}}  OPTIONAL }
/// ```
///
/// [RFC 4211 Section 5]: https://www.rfc-editor.org/rfc/rfc4211#section-5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertTemplate {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<Version>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub serial_number: Option<SerialNumber>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub signature: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub issuer: Option<Name>,
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", optional = "true")]
    pub validity: Option<Validity>,
    #[asn1(context_specific = "5", tag_mode = "EXPLICIT", optional = "true")]
    pub subject: Option<Name>,
    #[asn1(context_specific = "6", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_public_key_info: Option<SubjectPublicKeyInfoOwned>,
    #[asn1(context_specific = "7", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitString>,
    #[asn1(context_specific = "8", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitString>,
    #[asn1(context_specific = "9", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

/// The `OptionalValidity` type is defined in [RFC 4211 Section 5].
///
/// ```text
///   OptionalValidity ::= SEQUENCE {
///       notBefore  [0] Time OPTIONAL,
///       notAfter   [1] Time OPTIONAL } -- at least one MUST be present
/// ```
///
/// [RFC 4211 Section 5]: https://www.rfc-editor.org/rfc/rfc4211#section-5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OptionalValidity {
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub not_before: Option<Time>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    pub not_after: Option<Time>,
}
