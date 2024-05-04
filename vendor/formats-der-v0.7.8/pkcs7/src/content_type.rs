use der::asn1::ObjectIdentifier;
use der::{DecodeValue, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader, Tag, Writer};

/// Indicates the type of content.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum ContentType {
    /// Plain data content type
    Data,

    /// Signed-data content type
    SignedData,

    /// Enveloped-data content type
    EnvelopedData,

    /// Signed-and-enveloped-data content type
    SignedAndEnvelopedData,

    /// Digested-data content type
    DigestedData,

    /// Encrypted-data content type
    EncryptedData,
}

impl<'a> DecodeValue<'a> for ContentType {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<ContentType> {
        ObjectIdentifier::decode_value(reader, header)?.try_into()
    }
}

impl EncodeValue for ContentType {
    fn value_len(&self) -> der::Result<Length> {
        ObjectIdentifier::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        ObjectIdentifier::from(*self).encode_value(writer)
    }
}

impl FixedTag for ContentType {
    const TAG: Tag = Tag::ObjectIdentifier;
}

impl From<ContentType> for ObjectIdentifier {
    fn from(content_type: ContentType) -> ObjectIdentifier {
        match content_type {
            ContentType::Data => crate::PKCS_7_DATA_OID,
            ContentType::SignedData => crate::PKCS_7_SIGNED_DATA_OID,
            ContentType::EnvelopedData => crate::PKCS_7_ENVELOPED_DATA_OID,
            ContentType::SignedAndEnvelopedData => crate::PKCS_7_SIGNED_AND_ENVELOPED_DATA_OID,
            ContentType::DigestedData => crate::PKCS_7_DIGESTED_DATA_OID,
            ContentType::EncryptedData => crate::PKCS_7_ENCRYPTED_DATA_OID,
        }
    }
}

impl TryFrom<ObjectIdentifier> for ContentType {
    type Error = der::Error;

    fn try_from(oid: ObjectIdentifier) -> der::Result<Self> {
        match oid {
            crate::PKCS_7_DATA_OID => Ok(Self::Data),
            crate::PKCS_7_SIGNED_DATA_OID => Ok(Self::SignedData),
            crate::PKCS_7_ENVELOPED_DATA_OID => Ok(Self::EnvelopedData),
            crate::PKCS_7_SIGNED_AND_ENVELOPED_DATA_OID => Ok(Self::SignedAndEnvelopedData),
            crate::PKCS_7_DIGESTED_DATA_OID => Ok(Self::DigestedData),
            crate::PKCS_7_ENCRYPTED_DATA_OID => Ok(Self::EncryptedData),
            _ => Err(ErrorKind::OidUnknown { oid }.into()),
        }
    }
}
