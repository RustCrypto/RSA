extern crate core;

use cms::compressed_data::CompressedData;
use cms::content_info::{CmsVersion, ContentInfo};
use const_oid::ObjectIdentifier;
use der::{AnyRef, Decode, Encode};

#[test]
fn reencode_compressed_data_test() {
    // read DigestedData object created via:
    //  [11:05 AM] Carl Wallace
    // openssl cms -compress -in data.txt -binary -outform DER -out compressed_data.bin
    let der_ci = include_bytes!("examples/compressed_data.bin");
    let ci = ContentInfo::from_der(der_ci).unwrap();
    assert_eq!(
        ci.content_type,
        const_oid::db::rfc6268::ID_CT_COMPRESSED_DATA
    );

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as DigestedData then re-encode
    let data = CompressedData::from_der(bytes.as_slice()).unwrap();
    assert_eq!(CmsVersion::V0, data.version);

    assert_eq!(
        data.encap_content_info.econtent_type,
        const_oid::db::rfc5911::ID_DATA
    );

    assert_eq!(
        data.compression_alg.oid,
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.8")
    );
    assert_eq!(None, data.compression_alg.parameters);

    let reencoded_data = data.to_der().unwrap();

    // assemble a new ContentInfo and encode it
    let ci2 = ContentInfo {
        content_type: ci.content_type,
        content: AnyRef::try_from(reencoded_data.as_slice())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let reencoded_data_inci = ci2.to_der().unwrap();

    // should match the original
    assert_eq!(reencoded_data_inci, der_ci)
}
