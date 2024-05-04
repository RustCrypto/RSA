//! Revocation-related types

use alloc::vec::Vec;

use der::Sequence;

use crmf::controls::CertId;
use crmf::request::CertTemplate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::Extensions;

use crate::status::PkiStatusInfo;

/// The `RevReqContent` type is defined in [RFC 4210 Section 5.3.9].
///
/// ```text
///  RevReqContent ::= SEQUENCE OF RevDetails
/// ```
///
/// [RFC 4210 Section 5.3.9]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.9
pub type RevReqContent = Vec<RevDetails>;

/// The `RevDetails` type is defined in [RFC 4210 Section 5.3.9].
///
/// ```text
///  RevDetails ::= SEQUENCE {
///      certDetails         CertTemplate,
///      -- allows requester to specify as much as they can about
///      -- the cert. for which revocation is requested
///      -- (e.g., for cases in which serialNumber is not available)
///      crlEntryDetails     Extensions{{...}}    OPTIONAL
///      -- requested crlEntryExtensions
///  }
/// ```
///
/// [RFC 4210 Section 5.3.9]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.9
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct RevDetails {
    pub cert_details: CertTemplate,
    pub crl_entry_details: Option<Extensions>,
}

/// The `RevRepContent` type is defined in [RFC 4210 Section 5.3.10].
///
/// ```text
///  RevRepContent ::= SEQUENCE {
///      status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
///      revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
///      crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL
///  }
/// ```
///
/// [RFC 4210 Section 5.3.10]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.10
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct RevRepContent<'a> {
    pub status: Vec<PkiStatusInfo<'a>>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub rev_certs: Option<Vec<CertId>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub crls: Option<Vec<CertificateList>>,
}
