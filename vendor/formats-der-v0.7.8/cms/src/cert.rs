//! Certificate-related types

pub use x509_cert as x509;

use core::cmp::Ordering;
use der::{asn1::ObjectIdentifier, Any, Choice, Sequence, ValueOrd};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::Certificate;

/// The `CertificateChoices` type is defined in [RFC 5652 Section 10.2.2]. Attribute certificate
/// support is not presently implemented.
///
/// ```text
///   CertificateChoices ::= CHOICE {
///       certificate Certificate,
///       extendedCertificate [0] IMPLICIT ExtendedCertificate,
///            -- Obsolete
///       ...,
///       -- [[3: v1AttrCert [1] IMPLICIT AttributeCertificateV1]],
///            -- Obsolete
///       -- [[4: v2AttrCert [2] IMPLICIT AttributeCertificateV2]],
///       [[5: other      [3] IMPLICIT OtherCertificateFormat]] }
/// ```
///
/// [RFC 5652 Section 10.2.2]: https://www.rfc-editor.org/rfc/rfc5652#section-10.2.2
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum CertificateChoices {
    Certificate(Certificate),
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
    Other(OtherCertificateFormat),
    // TODO DEFER add more choices if desired (i.e., AttributeCertificateV2)
}

// TODO DEFER ValueOrd is not supported for CHOICE types (see new_enum in value_ord.rs)
impl ValueOrd for CertificateChoices {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        use der::DerOrd;
        use der::Encode;
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

// TODO DEFER implement support for attribute certs if desired
//   AttributeCertificateV2 ::= AttributeCertificate

/// The `OtherCertificateFormat` type is defined in [RFC 5652 Section 10.2.2].
///
/// ```text
///   OtherCertificateFormat ::= SEQUENCE {
///       otherCertFormat OTHER-CERT-FMT.
///               &id({SupportedCertFormats}),
///       otherCert       OTHER-CERT-FMT.
///               &Type({SupportedCertFormats}{@otherCertFormat})}
/// ```
///
/// [RFC 5652 Section 10.2.2]: https://www.rfc-editor.org/rfc/rfc5652#section-10.2.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OtherCertificateFormat {
    pub other_cert_format: ObjectIdentifier,
    pub other_cert: Any,
}

/// IssuerAndSerialNumber structure as defined in [RFC 5652 Section 10.2.4].
///
/// ```text
/// IssuerAndSerialNumber ::= SEQUENCE {
///   issuer Name,
///   serialNumber CertificateSerialNumber }
/// ```
///
/// [RFC 5652 Section 10.2.4]: https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: SerialNumber,
}
