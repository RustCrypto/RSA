//! `data` content type [RFC 5652 § 4](https://datatracker.ietf.org/doc/html/rfc5652#section-4)

use core::convert::{From, TryFrom};
use der::{
    asn1::OctetStringRef, DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer,
};

/// The content that is just an octet string.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DataContent<'a> {
    /// content bytes
    pub content: &'a [u8],
}

impl AsRef<[u8]> for DataContent<'_> {
    fn as_ref(&self) -> &[u8] {
        self.content
    }
}

impl<'a> From<&'a [u8]> for DataContent<'a> {
    fn from(bytes: &'a [u8]) -> DataContent<'a> {
        DataContent { content: bytes }
    }
}

impl<'a> From<DataContent<'a>> for &'a [u8] {
    fn from(data: DataContent<'a>) -> &'a [u8] {
        data.content
    }
}

impl<'a> DecodeValue<'a> for DataContent<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<DataContent<'a>> {
        Ok(OctetStringRef::decode_value(reader, header)?
            .as_bytes()
            .into())
    }
}

impl<'a> EncodeValue for DataContent<'a> {
    fn value_len(&self) -> der::Result<Length> {
        Length::try_from(self.content.len())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        OctetStringRef::new(self.content)?.encode_value(writer)
    }
}

impl<'a> FixedTag for DataContent<'a> {
    const TAG: Tag = Tag::OctetString;
}
