//! EnvelopedData-related types

use crate::cert::IssuerAndSerialNumber;
use crate::content_info::CmsVersion;
use crate::revocation::RevocationInfoChoices;
use crate::signed_data::CertificateSet;

use core::cmp::Ordering;
use der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Choice, Sequence, ValueOrd};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::impl_newtype;

/// The `EnvelopedData` type is defined in [RFC 5652 Section 6.1].
///
/// ```text
///   EnvelopedData ::= SEQUENCE {
///       version CMSVersion,
///       originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///       recipientInfos RecipientInfos,
///       encryptedContentInfo EncryptedContentInfo,
///       ...,
///       [[2: unprotectedAttrs [1] IMPLICIT Attributes
///           {{ UnprotectedEnvAttributes }} OPTIONAL ]] }
/// ```
///
/// [RFC 5652 Section 6.1]: https://www.rfc-editor.org/rfc/rfc5652#section-6.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EnvelopedData {
    pub version: CmsVersion,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub originator_info: Option<OriginatorInfo>,
    pub recip_infos: RecipientInfos,
    pub encrypted_content: EncryptedContentInfo,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unprotected_attrs: Option<Attributes>,
}

/// The `OriginatorInfo` type is defined in [RFC 5652 Section 6.1].
///
/// ```text
///   OriginatorInfo ::= SEQUENCE {
///       certs [0] IMPLICIT CertificateSet OPTIONAL,
///       crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
/// ```
///
/// [RFC 5652 Section 6.1]: https://www.rfc-editor.org/rfc/rfc5652#section-6.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OriginatorInfo {
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub certs: Option<CertificateSet>,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub crls: Option<RevocationInfoChoices>,
}

/// The `RecipientInfos` type is defined in [RFC 5652 Section 6.1].
///
/// ```text
///   RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
/// ```
///
/// [RFC 5652 Section 6.1]: https://www.rfc-editor.org/rfc/rfc5652#section-6.1
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecipientInfos(pub SetOfVec<RecipientInfo>);
impl_newtype!(RecipientInfos, SetOfVec<RecipientInfo>);

#[cfg(feature = "std")]
impl TryFrom<std::vec::Vec<RecipientInfo>> for RecipientInfos {
    type Error = der::Error;

    fn try_from(vec: std::vec::Vec<RecipientInfo>) -> der::Result<RecipientInfos> {
        Ok(RecipientInfos(SetOfVec::try_from(vec)?))
    }
}

/// The `EncryptedContentInfo` type is defined in [RFC 5652 Section 6.1].
///
/// ```text
///   EncryptedContentInfo ::= SEQUENCE {
///       contentType ContentType,
///       contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
///       encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
/// ```
///
/// [RFC 5652 Section 6.1]: https://www.rfc-editor.org/rfc/rfc5652#section-6.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncryptedContentInfo {
    pub content_type: ObjectIdentifier,
    pub content_enc_alg: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub encrypted_content: Option<OctetString>,
}

/// The `RecipientInfo` type is defined in [RFC 5652 Section 6.2].
///
/// ```text
///   RecipientInfo ::= CHOICE {
///       ktri           KeyTransRecipientInfo,
///       ...,
///       [[3: kari  [1] KeyAgreeRecipientInfo ]],
///       [[4: kekri [2] KEKRecipientInfo]],
///       [[5: pwri  [3] PasswordRecipientInfo,
///            ori   [4] OtherRecipientInfo ]] }
/// ```
///
/// [RFC 5652 Section 6.2]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum RecipientInfo {
    Ktri(KeyTransRecipientInfo),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Kari(KeyAgreeRecipientInfo),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", constructed = "true")]
    Kekri(KekRecipientInfo),
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", constructed = "true")]
    Pwri(PasswordRecipientInfo),
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", constructed = "true")]
    Ori(OtherRecipientInfo),
}

impl ValueOrd for RecipientInfo {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        use der::DerOrd;
        use der::Encode;
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

/// The `EncryptedKey` type is defined in [RFC 5652 Section 6.2].
///
/// ```text
///   EncryptedKey ::= OCTET STRING
/// ```
///
/// [RFC 5652 Section 6.2]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2
pub type EncryptedKey = OctetString;

/// The `KeyTransRecipientInfo` type is defined in [RFC 5652 Section 6.2.1].
///
/// ```text
///   KeyTransRecipientInfo ::= SEQUENCE {
///       version CMSVersion,  -- always set to 0 or 2
///       rid RecipientIdentifier,
///       keyEncryptionAlgorithm AlgorithmIdentifier
///           {KEY-TRANSPORT, {KeyTransportAlgorithmSet}},
///       encryptedKey EncryptedKey }
/// ```
///
/// [RFC 5652 Section 6.2.1]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct KeyTransRecipientInfo {
    pub version: CmsVersion,
    pub rid: RecipientIdentifier,
    pub key_enc_alg: AlgorithmIdentifierOwned,
    pub enc_key: EncryptedKey,
}

/// The `RecipientIdentifier` type is defined in [RFC 5652 Section 6.2.1].
///
/// ```text
///   RecipientIdentifier ::= CHOICE {
///       issuerAndSerialNumber IssuerAndSerialNumber,
///       ...,
///       [[2: subjectKeyIdentifier [0] SubjectKeyIdentifier ]] }
/// ```
///
/// [RFC 5652 Section 6.2.1]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum RecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

/// The `KeyAgreeRecipientInfo` type is defined in [RFC 5652 Section 6.2.2].
///
/// ```text
///   KeyAgreeRecipientInfo ::= SEQUENCE {
///       version CMSVersion,  -- always set to 3
///       originator [0] EXPLICIT OriginatorIdentifierOrKey,
///       ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
///       keyEncryptionAlgorithm AlgorithmIdentifier
///           {KEY-AGREE, {KeyAgreementAlgorithmSet}},
///       recipientEncryptedKeys RecipientEncryptedKeys }
/// ```
///
/// [RFC 5652 Section 6.2.2]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct KeyAgreeRecipientInfo {
    pub version: CmsVersion,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub originator: OriginatorIdentifierOrKey,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub ukm: Option<UserKeyingMaterial>,
    pub key_enc_alg: AlgorithmIdentifierOwned,
    pub recipient_enc_keys: RecipientEncryptedKeys,
}

/// The `OriginatorIdentifierOrKey` type is defined in [RFC 5652 Section 6.2.2].
///
/// ```text
///   OriginatorIdentifierOrKey ::= CHOICE {
///       issuerAndSerialNumber IssuerAndSerialNumber,
///       subjectKeyIdentifier [0] SubjectKeyIdentifier,
///       originatorKey [1] OriginatorPublicKey }
/// ```
///
/// [RFC 5652 Section 6.2.2]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.2
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum OriginatorIdentifierOrKey {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    OriginatorKey(OriginatorPublicKey),
}

/// The `OriginatorPublicKey` type is defined in [RFC 5652 Section 6.2.2].
///
/// ```text
///   OriginatorPublicKey ::= SEQUENCE {
///       algorithm AlgorithmIdentifier {PUBLIC-KEY, {OriginatorKeySet}},
///       publicKey BIT STRING }
/// ```
///
/// [RFC 5652 Section 6.2.2]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OriginatorPublicKey {
    pub algorithm: AlgorithmIdentifierOwned,
    pub public_key: BitString,
}

/// The `RecipientEncryptedKeys` type is defined in [RFC 5652 Section 6.2.2].
///
/// ```text
///   RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
/// ```
///
/// [RFC 5652 Section 6.2.2]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.2
pub type RecipientEncryptedKeys = alloc::vec::Vec<RecipientEncryptedKey>;

/// The `RecipientEncryptedKey` type is defined in [RFC 5652 Section 6.2.2].
///
/// ```text
///   RecipientEncryptedKey ::= SEQUENCE {
///       rid KeyAgreeRecipientIdentifier,
///       encryptedKey EncryptedKey }
/// ```
///
/// [RFC 5652 Section 6.2.2]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct RecipientEncryptedKey {
    pub rid: KeyAgreeRecipientIdentifier,
    pub enc_key: EncryptedKey,
}

/// The `KeyAgreeRecipientIdentifier` type is defined in [RFC 5652 Section 6.2.2].
///
/// ```text
///   KeyAgreeRecipientIdentifier ::= CHOICE {
///       issuerAndSerialNumber IssuerAndSerialNumber,
///       rKeyId [0] IMPLICIT RecipientKeyIdentifier }
/// ```
///
/// [RFC 5652 Section 6.2.2]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.2
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum KeyAgreeRecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    RKeyId(RecipientKeyIdentifier),
}

/// The `RecipientKeyIdentifier` type is defined in [RFC 5652 Section 6.2.2].
///
/// ```text
///   RecipientKeyIdentifier ::= SEQUENCE {
///       subjectKeyIdentifier SubjectKeyIdentifier,
///       date GeneralizedTime OPTIONAL,
///       other OtherKeyAttribute OPTIONAL }
/// ```
///
/// [RFC 5652 Section 6.2.2]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct RecipientKeyIdentifier {
    pub subject_key_identifier: SubjectKeyIdentifier,
    pub date: Option<GeneralizedTime>,
    pub other: Option<Attribute>,
}

//   SubjectKeyIdentifier ::= OCTET STRING
// reusing from x509-cert crate

/// The `KEKRecipientInfo` type is defined in [RFC 5652 Section 6.2.3].
///
/// ```text
///   KEKRecipientInfo ::= SEQUENCE {
///       version CMSVersion,  -- always set to 4
///       kekid KEKIdentifier,
///       keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///       encryptedKey EncryptedKey }
/// ```
///
/// [RFC 5652 Section 6.2.3]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct KekRecipientInfo {
    pub version: CmsVersion,
    pub kek_id: KekIdentifier,
    pub key_enc_alg: AlgorithmIdentifierOwned,
    pub encrypted_key: EncryptedKey,
}

/// The `KEKIdentifier` type is defined in [RFC 5652 Section 6.2.3].
///
/// ```text
///   KEKIdentifier ::= SEQUENCE {
///       keyIdentifier OCTET STRING,
///       date GeneralizedTime OPTIONAL,
///       other OtherKeyAttribute OPTIONAL }
/// ```
///
/// [RFC 5652 Section 6.2.3]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct KekIdentifier {
    pub kek_identifier: OctetString,
    pub date: Option<GeneralizedTime>,
    pub other: Option<Attribute>,
}

/// The `PasswordRecipientInfo` type is defined in [RFC 5652 Section 6.2.4].
///
/// ```text
///   PasswordRecipientInfo ::= SEQUENCE {
///       version CMSVersion,   -- always set to 0
///       keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
///                               OPTIONAL,
///       keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///       encryptedKey EncryptedKey }
/// ```
///
/// [RFC 5652 Section 6.2.4]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PasswordRecipientInfo {
    pub version: CmsVersion,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub key_derivation_alg: Option<AlgorithmIdentifierOwned>,
    pub key_enc_alg: AlgorithmIdentifierOwned,
    pub enc_key: EncryptedKey,
}

/// The `OtherRecipientInfo` type is defined in [RFC 5652 Section 6.2.5].
///
/// ```text
///   OtherRecipientInfo ::= SEQUENCE {
///       oriType    OTHER-RECIPIENT.
///               &id({SupportedOtherRecipInfo}),
///       oriValue   OTHER-RECIPIENT.
///               &Type({SupportedOtherRecipInfo}{@oriType})}
/// ```
///
/// [RFC 5652 Section 6.2.5]: https://www.rfc-editor.org/rfc/rfc5652#section-6.2.5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OtherRecipientInfo {
    pub ori_type: ObjectIdentifier,
    pub ori_value: Any,
}

/// The `UserKeyingMaterial` type is defined in [RFC 5652 Section 10.2.6].
///
/// ```text
///   UserKeyingMaterial ::= OCTET STRING
/// ```
///
/// [RFC 5652 Section 10.2.5]: https://www.rfc-editor.org/rfc/rfc5652#section-10.2.5
pub type UserKeyingMaterial = OctetString;
