use crmf::request::{CertReqMessages, CertReqMsg, CertRequest, CertTemplate};
use der::{Decode, Encode};

#[test]
fn certtemplate_test() {
    // read CertTemplate cracked from request object used in the cmpv2 req_message_test
    let header_01 = include_bytes!("examples/certtemplate.bin");
    let result = CertTemplate::from_der(header_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let cert_template = result.unwrap();

    assert!(cert_template.version.is_none());
    assert!(cert_template.serial_number.is_none());
    assert!(cert_template.signature.is_none());
    assert!(cert_template.issuer.is_none());
    assert!(cert_template.validity.is_none());
    assert!(cert_template.subject.is_some());
    assert!(cert_template.subject_public_key_info.is_some());
    assert!(cert_template.issuer_unique_id.is_none());
    assert!(cert_template.subject_unique_id.is_none());
    assert!(cert_template.extensions.is_none());

    let reencoded_header_01 = cert_template.to_der().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}

#[test]
fn certrequest_test() {
    // read CertRequest cracked from request object used in the cmpv2 req_message_test
    let header_01 = include_bytes!("examples/certrequest.bin");
    let result = CertRequest::from_der(header_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let header = result.unwrap();

    let reencoded_header_01 = header.to_der().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}

#[test]
fn certreqmsg_test() {
    // read CertReqMsg cracked from request object used in the cmpv2 req_message_test
    let header_01 = include_bytes!("examples/certreqmsg.bin");
    let result = CertReqMsg::from_der(header_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let header = result.unwrap();

    let reencoded_header_01 = header.to_der().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}

#[test]
fn certreqmsgs_test() {
    // read header cracked from request object used in the cmpv2 req_message_test
    let header_01 = include_bytes!("examples/certreqmsgs.bin");
    let result = CertReqMessages::from_der(header_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let header = result.unwrap();

    let reencoded_header_01 = header.to_der().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}
