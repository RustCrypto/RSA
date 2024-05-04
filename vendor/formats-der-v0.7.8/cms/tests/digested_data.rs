extern crate core;

use cms::content_info::{CmsVersion, ContentInfo};
use cms::digested_data::DigestedData;
use const_oid::ObjectIdentifier;
use der::{AnyRef, Decode, Encode};
use hex_literal::hex;

#[test]
fn reencode_digested_data_test() {
    // read DigestedData object created via:
    //  openssl cms --digest_create -in data.txt -binary -outform DER -out digested_data.bin
    let der_ci = include_bytes!("examples/digested_data.bin");
    let ci = ContentInfo::from_der(der_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_DIGESTED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_der().unwrap();

    // parse as DigestedData then re-encode
    let data = DigestedData::from_der(bytes.as_slice()).unwrap();
    assert_eq!(CmsVersion::V0, data.version);

    let encap_data = include_bytes!("examples/data.txt");
    assert_eq!(
        data.encap_content_info.econtent_type,
        const_oid::db::rfc5911::ID_DATA
    );
    assert_eq!(
        data.encap_content_info.econtent.as_ref().unwrap().value(),
        encap_data
    );

    let hash = hex!("4518012e1b365e504001dbc94120624f15b8bbd5");
    assert_eq!(
        data.digest_alg.oid,
        ObjectIdentifier::new_unwrap("1.3.14.3.2.26")
    );
    assert_eq!(None, data.digest_alg.parameters);
    assert_eq!(data.digest.as_bytes(), hash);

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
