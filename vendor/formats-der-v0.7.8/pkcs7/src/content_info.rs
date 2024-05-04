use crate::{
    data_content::DataContent, encrypted_data_content::EncryptedDataContent,
    signed_data_content::SignedDataContent, ContentType,
};

use der::{
    asn1::{ContextSpecific, OctetStringRef},
    Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, TagMode, TagNumber,
    Writer,
};

const CONTENT_TAG: TagNumber = TagNumber::new(0);

/// Content exchanged between entities [RFC 5652 § 3](https://datatracker.ietf.org/doc/html/rfc5652#section-3)
///
/// ```text
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content
///     [0] EXPLICIT ANY DEFINED BY contentType }
/// ```
///
/// Note: `content` field was previously optional in [RFC 2315 § 7](https://datatracker.ietf.org/doc/html/rfc2315#section-7).
#[derive(Clone, Debug)]
pub enum ContentInfo<'a> {
    /// Content type `data`
    Data(DataContent<'a>),

    /// Content type `encrypted-data`
    EncryptedData(EncryptedDataContent<'a>),

    /// Content type `signed-data`
    SignedData(SignedDataContent<'a>),

    /// Catch-all case for content types that are not explicitly supported
    ///   - enveloped-data
    ///   - signed-and-enveloped-data
    ///   - digested-data
    Other((ContentType, OctetStringRef<'a>)),
}

impl<'a> ContentInfo<'a> {
    /// return content type of content info
    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Data(_) => ContentType::Data,
            Self::EncryptedData(_) => ContentType::EncryptedData,
            Self::SignedData(_) => ContentType::SignedData,
            Self::Other((content_type, _)) => *content_type,
        }
    }
}

impl<'a> ContentInfo<'a> {
    /// new ContentInfo of `data` content type
    pub fn new_data(content: &'a [u8]) -> Self {
        ContentInfo::Data(content.into())
    }

    /// new Content info of given content type with given raw content
    pub fn new_raw(content_type: ContentType, content: &'a [u8]) -> der::Result<Self> {
        Ok(ContentInfo::Other((
            content_type,
            OctetStringRef::new(content)?,
        )))
    }
}

impl<'a> DecodeValue<'a> for ContentInfo<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<ContentInfo<'a>> {
        #[inline]
        fn decode_context_specific<'a, R: Reader<'a>, T: Decode<'a>>(
            reader: &mut R,
        ) -> der::Result<T> {
            Ok(ContextSpecific::<T>::decode_explicit(reader, CONTENT_TAG)?
                .ok_or_else(|| {
                    der::Tag::ContextSpecific {
                        number: CONTENT_TAG,
                        constructed: false,
                    }
                    .value_error()
                })?
                .value)
        }

        reader.read_nested(header.length, |reader| {
            let content_type = reader.decode()?;
            match content_type {
                ContentType::Data => Ok(ContentInfo::Data(decode_context_specific(reader)?)),
                ContentType::EncryptedData => {
                    Ok(ContentInfo::EncryptedData(decode_context_specific(reader)?))
                }
                ContentType::SignedData => {
                    Ok(ContentInfo::SignedData(decode_context_specific(reader)?))
                }

                _ => Ok(ContentInfo::Other((
                    content_type,
                    decode_context_specific(reader)?,
                ))),
            }
        })
    }
}

impl EncodeValue for ContentInfo<'_> {
    fn value_len(&self) -> der::Result<Length> {
        self.content_type().encoded_len()?
            + match self {
                Self::Data(data) => ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: *data,
                }
                .encoded_len(),
                Self::EncryptedData(data) => ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: *data,
                }
                .encoded_len(),
                Self::SignedData(data) => ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: data.clone(),
                }
                .encoded_len(),
                Self::Other((_, oct_str)) => ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: *oct_str,
                }
                .encoded_len(),
            }?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.content_type().encode(writer)?;

        match self {
            Self::Data(data) => ContextSpecific {
                tag_number: CONTENT_TAG,
                tag_mode: TagMode::Explicit,
                value: *data,
            }
            .encode(writer)?,
            Self::EncryptedData(data) => ContextSpecific {
                tag_number: CONTENT_TAG,
                tag_mode: TagMode::Explicit,
                value: *data,
            }
            .encode(writer)?,
            Self::SignedData(data) => ContextSpecific {
                tag_number: CONTENT_TAG,
                tag_mode: TagMode::Explicit,
                value: data.clone(),
            }
            .encode(writer)?,
            Self::Other((_, oct_str)) => ContextSpecific {
                tag_number: CONTENT_TAG,
                tag_mode: TagMode::Explicit,
                value: *oct_str,
            }
            .encode(writer)?,
        }

        Ok(())
    }
}

impl<'a> Sequence<'a> for ContentInfo<'a> {}

#[cfg(test)]
mod tests {
    use super::{ContentInfo, DataContent};
    use core::convert::TryFrom;
    use der::{asn1::OctetStringRef, Decode, Encode, Length, SliceWriter, TagMode, TagNumber};

    #[test]
    fn simple_data() -> der::Result<()> {
        let mut in_buf = [0u8; 32];

        let hello = "hello".as_bytes();
        assert_eq!(5, hello.len());

        let hello_len = Length::try_from(hello.len())?.for_tlv()?;
        assert_eq!(Length::new(7), hello_len);

        let tagged_hello_len = hello_len.for_tlv()?;
        assert_eq!(Length::new(9), tagged_hello_len);

        let oid_len = crate::PKCS_7_DATA_OID.encoded_len()?;
        assert_eq!(Length::new(11), oid_len);

        let inner_len = (oid_len + tagged_hello_len)?;
        assert_eq!(Length::new(20), inner_len);

        let mut encoder = SliceWriter::new(&mut in_buf);
        encoder.sequence(inner_len, |encoder| {
            crate::PKCS_7_DATA_OID.encode(encoder)?;
            encoder.context_specific(
                TagNumber::new(0),
                TagMode::Explicit,
                &OctetStringRef::new(hello)?,
            )
        })?;
        let encoded_der = encoder.finish().expect("encoding success");
        assert_eq!(22, encoded_der.len());

        let info = ContentInfo::from_der(encoded_der)?;
        match info {
            ContentInfo::Data(DataContent { content }) => assert_eq!(hello, content),
            _ => panic!("unexpected case"),
        }

        let mut out_buf = [0u8; 32];
        let encoded_der2 = info.encode_to_slice(&mut out_buf)?;

        assert_eq!(encoded_der, encoded_der2);

        Ok(())
    }
}
