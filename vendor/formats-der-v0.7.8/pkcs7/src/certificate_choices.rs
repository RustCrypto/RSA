//! `CertificateChoices` [RFC 5652 10.2.2](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.2)

use der::{asn1::BitStringRef, AnyRef, Choice, Sequence, ValueOrd};
use spki::ObjectIdentifier;
use x509_cert::Certificate;

// TODO (smndtrl): Should come from x509 - for now I haven't found a test case in real world
type AttributeCertificateV1<'a> = BitStringRef<'a>;
type AttributeCertificateV2<'a> = BitStringRef<'a>;
type ExtendedCertificate<'a> = BitStringRef<'a>;

/// ```text
/// OtherCertificateFormat ::= SEQUENCE {
///     otherCertFormat OBJECT IDENTIFIER,
///     otherCert ANY DEFINED BY otherCertFormat }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence, ValueOrd)]
pub struct OtherCertificateFormat<'a> {
    other_cert_format: ObjectIdentifier,
    other_cert: AnyRef<'a>,
}

/// ```text
/// CertificateChoices ::= CHOICE {
///     certificate Certificate,
///     extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
///     v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
///     v2AttrCert [2] IMPLICIT AttributeCertificateV2,
///     other [3] IMPLICIT OtherCertificateFormat }
///
/// OtherCertificateFormat ::= SEQUENCE {
///     otherCertFormat OBJECT IDENTIFIER,
///     otherCert ANY DEFINED BY otherCertFormat }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice, ValueOrd)]
#[allow(clippy::large_enum_variant)]
pub enum CertificateChoices<'a> {
    /// X.509 certificate
    Certificate(Certificate),

    /// PKCS #6 extended certificate (obsolete)
    #[deprecated]
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    ExtendedCertificate(ExtendedCertificate<'a>),

    /// version 1 X.509 attribute certificate (ACv1) X.509-97 (obsolete)
    #[deprecated]
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    V1AttrCert(AttributeCertificateV1<'a>),

    /// version 2 X.509 attribute certificate (ACv2) X.509-00
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    V2AttrCert(AttributeCertificateV2<'a>),

    /// any other certificate forma
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT")]
    Other(OtherCertificateFormat<'a>),
}
