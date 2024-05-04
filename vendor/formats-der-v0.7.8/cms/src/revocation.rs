//! Revocation-related types
use core::cmp::Ordering;

use der::asn1::SetOfVec;
use der::{Any, Choice, Sequence, ValueOrd};
use spki::AlgorithmIdentifierOwned;

use x509_cert::crl::CertificateList;
use x509_cert::impl_newtype;

/// The `RevocationInfoChoices` type is defined in [RFC 5652 Section 10.2.1].
///
/// ```text
///   RevocationInfoChoices ::= SET OF RevocationInfoChoice
/// ```
///
/// [RFC 5652 Section 10.2.1]: https://www.rfc-editor.org/rfc/rfc5652#section-10.2.1
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RevocationInfoChoices(pub SetOfVec<RevocationInfoChoice>);
impl_newtype!(RevocationInfoChoices, SetOfVec<RevocationInfoChoice>);

/// The `RevocationInfoChoice` type is defined in [RFC 5652 Section 10.2.1].
///
/// ```text
///   RevocationInfoChoice ::= CHOICE {
///       crl CertificateList,
///       ...,
///       [[5: other [1] IMPLICIT OtherRevocationInfoFormat ]] }
/// ```
///
/// [RFC 5652 Section 10.2.1]: https://www.rfc-editor.org/rfc/rfc5652#section-10.2.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum RevocationInfoChoice {
    Crl(CertificateList),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Other(OtherRevocationInfoFormat),
}

// TODO DEFER ValueOrd is not supported for CHOICE types (see new_enum in value_ord.rs)
impl ValueOrd for RevocationInfoChoice {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        use der::DerOrd;
        use der::Encode;
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

#[cfg(feature = "std")]
impl TryFrom<std::vec::Vec<RevocationInfoChoice>> for RevocationInfoChoices {
    type Error = der::Error;

    fn try_from(vec: std::vec::Vec<RevocationInfoChoice>) -> der::Result<RevocationInfoChoices> {
        Ok(RevocationInfoChoices(SetOfVec::try_from(vec)?))
    }
}

/// The `RevocationInfoChoices` type is defined in [RFC 5652 Section 10.2.1].
///
/// ```text
///   OtherRevocationInfoFormat ::= SEQUENCE {
///       otherRevInfoFormat    OTHER-REVOK-INFO.
///               &id({SupportedOtherRevokInfo}),
///       otherRevInfo          OTHER-REVOK-INFO.
///               &Type({SupportedOtherRevokInfo}{@otherRevInfoFormat})}
/// ```
///
/// [RFC 5652 Section 10.2.1]: https://www.rfc-editor.org/rfc/rfc5652#section-10.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OtherRevocationInfoFormat {
    pub other_format: AlgorithmIdentifierOwned,
    pub other: Any,
}
