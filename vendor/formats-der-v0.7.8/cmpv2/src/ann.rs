//! Announcement-related types

use alloc::boxed::Box;
use alloc::vec::Vec;
use der::asn1::GeneralizedTime;
use der::Sequence;

use crmf::controls::CertId;
use x509_cert::{crl::CertificateList, ext::Extensions};

use crate::header::CmpCertificate;
use crate::status::PkiStatus;

/// The `CAKeyUpdAnnContent` announcement is defined in [RFC 4210 Section 5.3.13].
///
/// ```text
///  CAKeyUpdAnnContent ::= SEQUENCE {
///      oldWithNew   CMPCertificate, -- old pub signed with new priv
///      newWithOld   CMPCertificate, -- new pub signed with old priv
///      newWithNew   CMPCertificate  -- new pub signed with new priv
///  }
/// ```
///
/// [RFC 4210 Section 5.3.13]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.13
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CaKeyUpdAnnContent {
    pub old_with_new: Box<CmpCertificate>,
    pub new_with_old: Box<CmpCertificate>,
    pub new_with_new: Box<CmpCertificate>,
}

/// The `CertAnnContent` announcement is defined in [RFC 4210 Section 5.3.14].
///
/// ```text
///  CertAnnContent ::= CMPCertificate
/// ```
///
/// [RFC 4210 Section 5.3.14]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.14
pub type CertAnnContent = CmpCertificate;

/// The `RevAnnContent` announcement is defined in [RFC 4210 Section 5.3.15].
///
/// ```text
///  RevAnnContent ::= SEQUENCE {
///      status              PKIStatus,
///      certId              CertId,
///      willBeRevokedAt     GeneralizedTime,
///      badSinceDate        GeneralizedTime,
///      crlDetails          Extensions{{...}}  OPTIONAL
///  }
/// ```
///
/// [RFC 4210 Section 5.3.15]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.15
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct RevAnnContent {
    pub status: PkiStatus,
    pub cert_id: CertId,
    pub will_be_revoked_at: GeneralizedTime,
    pub bad_since_date: GeneralizedTime,
    pub crl_details: Option<Extensions>,
}

/// The `CRLAnnContent` announcement is defined in [RFC 4210 Section 5.3.16].
///
/// ```text
///  CRLAnnContent ::= SEQUENCE OF CertificateList
/// ```
///
/// [RFC 4210 Section 5.3.16]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.16
pub type CrlAnnContent = Vec<CertificateList>;
