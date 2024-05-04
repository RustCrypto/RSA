//! ContentInfo types

use crate::cert::CertificateChoices;
use crate::revocation::RevocationInfoChoices;
use crate::signed_data::EncapsulatedContentInfo;
use crate::signed_data::{CertificateSet, SignedData, SignerInfos};
use core::cmp::Ordering;
use der::asn1::SetOfVec;
use der::Encode;
use der::{asn1::ObjectIdentifier, Any, AnyRef, Enumerated, Sequence, ValueOrd};
use x509_cert::{Certificate, PkiPath};

/// The `OtherCertificateFormat` type is defined in [RFC 5652 Section 10.2.5].
///
/// ```text
///  CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
///
/// [RFC 5652 Section 10.2.5]: https://www.rfc-editor.org/rfc/rfc5652#section-10.2.5
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum CmsVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl ValueOrd for CmsVersion {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        (*self as u8).value_cmp(&(*other as u8))
    }
}

/// The `ContentInfo` type is defined in [RFC 5652 Section 3].
///
/// ```text
///   ContentInfo ::= SEQUENCE {
///       contentType        CONTENT-TYPE.
///                       &id({ContentSet}),
///       content            [0] EXPLICIT CONTENT-TYPE.
///                       &Type({ContentSet}{@contentType})}
/// ```
///
/// [RFC 5652 Section 3]: https://www.rfc-editor.org/rfc/rfc5652#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ContentInfo {
    pub content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub content: Any,
}

/// Convert a Certificate to a certs-only SignedData message
impl TryFrom<Certificate> for ContentInfo {
    type Error = der::Error;

    fn try_from(cert: Certificate) -> der::Result<Self> {
        let mut certs = CertificateSet(Default::default());
        certs.0.insert(CertificateChoices::Certificate(cert))?;

        // include empty CRLs field instead of omitting it to match OpenSSL's behavior
        let sd = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::default(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: const_oid::db::rfc5911::ID_DATA,
                econtent: None,
            },
            certificates: Some(certs),
            crls: Some(RevocationInfoChoices(Default::default())),
            signer_infos: SignerInfos(Default::default()),
        };

        let signed_data = sd.to_der()?;
        let content = AnyRef::try_from(signed_data.as_slice())?;

        Ok(ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::from(content),
        })
    }
}

/// Convert a vector of Certificates to a certs-only SignedData message
impl TryFrom<PkiPath> for ContentInfo {
    type Error = der::Error;

    fn try_from(pki_path: PkiPath) -> der::Result<Self> {
        let mut certs = CertificateSet(Default::default());
        for cert in pki_path {
            certs.0.insert(CertificateChoices::Certificate(cert))?;
        }

        // include empty CRLs field instead of omitting it to match OpenSSL's behavior
        let sd = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::default(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: const_oid::db::rfc5911::ID_DATA,
                econtent: None,
            },
            certificates: Some(certs),
            crls: Some(RevocationInfoChoices(Default::default())),
            signer_infos: SignerInfos(Default::default()),
        };

        let signed_data = sd.to_der()?;
        let content = AnyRef::try_from(signed_data.as_slice())?;

        Ok(ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::from(content),
        })
    }
}
