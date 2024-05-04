#![no_std]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! The ocsp module features encoders and decoders for the structures defined in
//! [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960).

extern crate alloc;

use der::asn1::{BitStringRef, Ia5StringRef, ObjectIdentifier, OctetStringRef, UintRef};
use der::asn1::{GeneralizedTime, Null};
use der::{AnyRef, Choice, Enumerated, Sequence};
use spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlReason};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::Certificate;

use alloc::vec::Vec;
use core::default::Default;
use core::option::Option;

/// OcspNoCheck as defined in [RFC 6960 Section 4.2.2.2.1].
///
/// This extension is identified by the ID_PKIX_OCSP_NOCHECK OID.
///
/// ```text
/// OcspNoCheck ::= NULL
/// ```
///
/// [RFC 6960 Section 4.2.2.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.2.2.1
pub type OcspNoCheck = Null;

/// OCSPRequest structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///    tbsRequest              TBSRequest,
///    optionalSignature   [0] EXPLICIT Signature OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OcspRequest<'a> {
    pub tbs_request: TbsRequest<'a>,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub optional_signature: Option<Signature<'a>>,
}

/// TBSRequest structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// TBSRequest ::= SEQUENCE {
///    version             [0] EXPLICIT Version DEFAULT v1,
///    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
///    requestList             SEQUENCE OF Request,
///    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct TbsRequest<'a> {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub requestor_name: Option<GeneralName>,

    pub request_list: Vec<Request<'a>>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub request_extensions: Option<Extensions>,
}

/// Signature structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Signature ::= SEQUENCE {
///    signatureAlgorithm      AlgorithmIdentifier,
///    signature               BIT STRING,
///    certs                  [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Signature<'a> {
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: BitStringRef<'a>,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<Certificate>>,
}

/// OCSP `Version` as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Version ::= INTEGER { v1(0) }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Version {
    V1 = 0,
}

impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

/// Request structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Request ::= SEQUENCE {
///    reqCert                     CertID,
///    singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Request<'a> {
    pub req_cert: CertId<'a>,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub single_request_extensions: Option<Extensions>,
}

/// CertID structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// CertID ::= SEQUENCE {
///    hashAlgorithm           AlgorithmIdentifier,
///    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
///    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
///    serialNumber            CertificateSerialNumber }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertId<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub issuer_name_hash: OctetStringRef<'a>,
    pub issuer_key_hash: OctetStringRef<'a>,
    pub serial_number: SerialNumber,
}

/// OCSPResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// OCSPResponse ::= SEQUENCE {
///    responseStatus          OCSPResponseStatus,
///    responseBytes           [0] EXPLICIT ResponseBytes OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OcspResponse<'a> {
    pub response_status: OcspResponseStatus,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub response_bytes: Option<ResponseBytes<'a>>,
}

/// OCSPResponseStatus structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// OCSPResponseStatus ::= ENUMERATED {
///    successful          (0),  -- Response has valid confirmations
///    malformedRequest    (1),  -- Illegal confirmation request
///    internalError       (2),  -- Internal error in issuer
///    tryLater            (3),  -- Try again later
///                              -- (4) is not used
///    sigRequired         (5),  -- Must sign the request
///    unauthorized        (6)   -- Request unauthorized
/// }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

/// ResponseBytes structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// ResponseBytes ::= SEQUENCE {
///    responseType            OBJECT IDENTIFIER,
///    response                OCTET STRING }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ResponseBytes<'a> {
    pub response_type: ObjectIdentifier,
    pub response: OctetStringRef<'a>,
}

/// BasicOcspResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// BasicOCSPResponse ::= SEQUENCE {
///   tbsResponseData          ResponseData,
///   signatureAlgorithm       AlgorithmIdentifier,
///   signature                BIT STRING,
///   certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct BasicOcspResponse<'a> {
    pub tbs_response_data: ResponseData<'a>,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitStringRef<'a>,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<AnyRef<'a>>>,
}

/// ResponseData structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1,
///    responderID             ResponderID,
///    producedAt              GeneralizedTime,
///    responses               SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ResponseData<'a> {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,
    pub responder_id: ResponderId<'a>,
    pub produced_at: GeneralizedTime,
    pub responses: Vec<SingleResponse<'a>>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub response_extensions: Option<Extensions>,
}

/// ResponderID structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
// ResponderID ::= CHOICE {
///    byName              [1] Name,
///    byKey               [2] KeyHash }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum ResponderId<'a> {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name),

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(KeyHash<'a>),
}

/// KeyHash structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
///                          -- (i.e., the SHA-1 hash of the value of the
///                          -- BIT STRING subjectPublicKey [excluding
///                          -- the tag, length, and number of unused
///                          -- bits] in the responder's certificate)
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type KeyHash<'a> = OctetStringRef<'a>;

/// SingleResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
// SingleResponse ::= SEQUENCE {
///    certID                  CertID,
///    certStatus              CertStatus,
///    thisUpdate              GeneralizedTime,
///    nextUpdate              [0] EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions        [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SingleResponse<'a> {
    pub cert_id: CertId<'a>,
    pub cert_status: CertStatus,
    pub this_update: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub next_update: Option<GeneralizedTime>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub single_request_extensions: Option<Extensions>,
}

/// CertStatus structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// CertStatus ::= CHOICE {
///    good                [0] IMPLICIT NULL,
///    revoked             [1] IMPLICIT RevokedInfo,
///    unknown             [2] IMPLICIT UnknownInfo }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(UnknownInfo),
}

/// RevokedInfo structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
// RevokedInfo ::= SEQUENCE {
///    revocationTime          GeneralizedTime,
///    revocationReason        [0] EXPLICIT CRLReason OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct RevokedInfo {
    pub revocation_time: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub revocation_reason: Option<CrlReason>,
}

/// RevokedInfo structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// UnknownInfo ::= NULL
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type UnknownInfo = Null;

/// ArchiveCutoff structure as defined in [RFC 6960 Section 4.4.4].
///
/// ```text
// ArchiveCutoff ::= GeneralizedTime
/// ```
///
/// [RFC 6960 Section 4.4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.4
pub type ArchiveCutoff = GeneralizedTime;

/// AcceptableResponses structure as defined in [RFC 6960 Section 4.4.3].
///
/// ```text
// AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
/// ```
///
/// [RFC 6960 Section 4.4.3]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.3
pub type AcceptableResponses = Vec<ObjectIdentifier>;

/// ServiceLocator structure as defined in [RFC 6960 Section 4.4.6].
///
/// ```text
/// ServiceLocator ::= SEQUENCE {
///    issuer                  Name,
///    locator                 AuthorityInfoAccessSyntax }
/// ```
///
/// [RFC 6960 Section 4.4.6]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.6
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ServiceLocator {
    pub issuer: Name,
    pub locator: AuthorityInfoAccessSyntax,
}

/// CrlID structure as defined in [RFC 6960 Section 4.4.2].
///
/// ```text
/// CrlID ::= SEQUENCE {
///     crlUrl               [0] EXPLICIT IA5String OPTIONAL,
///     crlNum               [1] EXPLICIT INTEGER OPTIONAL,
///     crlTime              [2] EXPLICIT GeneralizedTime OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.4.2]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CrlId<'a> {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_url: Option<Ia5StringRef<'a>>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_num: Option<UintRef<'a>>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_time: Option<GeneralizedTime>,
}

/// PreferredSignatureAlgorithms structure as defined in [RFC 6960 Section 4.4.7.1].
///
/// ```text
/// PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm
/// ```
///
/// [RFC 6960 Section 4.4.7.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.7.1
pub type PreferredSignatureAlgorithms<'a> = Vec<PreferredSignatureAlgorithm<'a>>;

/// PreferredSignatureAlgorithm structure as defined in [RFC 6960 Section 4.4.7.1].
///
/// ```text
/// PreferredSignatureAlgorithm ::= SEQUENCE {
///    sigIdentifier   AlgorithmIdentifier,
///    certIdentifier  AlgorithmIdentifier OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.4.7.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.7.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PreferredSignatureAlgorithm<'a> {
    pub sig_identifier: AlgorithmIdentifierRef<'a>,
    pub cert_identifier: Option<AlgorithmIdentifierRef<'a>>,
}
