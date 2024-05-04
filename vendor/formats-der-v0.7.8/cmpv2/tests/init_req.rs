use cmpv2::body::PkiBody;
use cmpv2::header::{PkiHeader, Pvno};
use cmpv2::message::PkiMessage;
use cmpv2::response::{CertRepMessage, CertResponse, CertResponses};
use cmpv2::status::PkiStatus;
use const_oid::ObjectIdentifier;
use crmf::pop::ProofOfPossession;
use der::{Decode, Encode};
use hex_literal::hex;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::Certificate;

#[test]
fn ir_req_header_test() {
    // read PkiHeader cracked from request object used in req_message_test
    let header_01 = include_bytes!("examples/ir_req_header_01.bin");
    let result = PkiHeader::from_der(header_01);
    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.pvno, Pvno::Cmp2000);

    let reencoded_header_01 = header.to_der().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}

#[test]
fn ir_req_body_test() {
    // read PkiBody cracked from request object used in ir_req_message_test
    let body_01 = include_bytes!("examples/ir_req_body_01.bin");
    let result = PkiBody::from_der(body_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let body = result.unwrap();

    let reencoded_body_01 = body.to_der().unwrap();
    println!("Original : {:02X?}", body_01);
    println!("Reencoded: {:02X?}", reencoded_body_01);
    assert_eq!(body_01, reencoded_body_01.as_slice());
}

#[test]
fn ir_req_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd ir -server 127.0.0.1:8888 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -newkey ec384-key-pair.pem -subject "/CN=MyName" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout req.bin -rspout rsp.bin
    let req_01 = include_bytes!("examples/ir_req_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let message = result.unwrap();

    let header = &message.header;
    match &header.sender {
        GeneralName::DirectoryName(name) => assert_eq!("CN=MyName", name.to_string()),
        _ => panic!(),
    }
    match &header.recipient {
        GeneralName::DirectoryName(name) => assert_eq!("CN=CMPserver", name.to_string()),
        _ => panic!(),
    }
    let m = header.message_time.unwrap();
    assert_eq!(1673871250000, m.to_unix_duration().as_millis());
    assert_eq!(
        const_oid::db::rfc5912::ID_PASSWORD_BASED_MAC,
        header.protection_alg.as_ref().unwrap().oid
    );
    //inspect params
    assert_eq!(
        "1234".as_bytes(),
        header.sender_kid.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("5D 8A 64 21 9A 32 53 B4 FE 86 73 BB 21 56 F0 4D"),
        header.trans_id.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("89 34 8B 3E 06 61 33 53 15 C8 A2 64 58 6F 0A 59"),
        header.sender_nonce.as_ref().unwrap().as_bytes()
    );

    match &message.body {
        PkiBody::Ir(irs) => {
            assert_eq!(1, irs.len());
            let ir = &irs[0];
            assert_eq!([0x00], ir.cert_req.cert_req_id.as_bytes());
            assert_eq!(
                "CN=MyName",
                ir.cert_req
                    .cert_template
                    .subject
                    .as_ref()
                    .unwrap()
                    .to_string()
            );
            let spki = ir
                .cert_req
                .cert_template
                .subject_public_key_info
                .as_ref()
                .unwrap();
            assert_eq!(
                ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                spki.algorithm.oid
            );
            assert_eq!(
                const_oid::db::rfc5912::SECP_384_R_1.as_bytes(),
                spki.algorithm.parameters.as_ref().unwrap().value()
            );
            match ir.popo.as_ref().unwrap() {
                ProofOfPossession::Signature(sig) => {
                    assert_eq!(const_oid::db::rfc5912::ECDSA_WITH_SHA_256, sig.alg_id.oid);
                }
                _ => panic!(),
            }
        }
        _ => panic!(),
    };

    let protection = message.protection.as_ref().unwrap();
    assert_eq!(
        hex!("76 7A 9C 5F 8A 35 EB 02 96 F4 07 6E 5C C8 9E 1A 61 83 7A 02"),
        protection.as_bytes().unwrap()
    );

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {:02X?}", req_01);
    println!("Reencoded: {:02X?}", reencoded_req_01);
    assert_eq!(req_01, reencoded_req_01.as_slice());
}

#[test]
fn ir_rsp_header_test() {
    // read PkiHeader cracked from request object used in ir_rsp_message_test
    let header_01 = include_bytes!("examples/ir_rsp_header_01.bin");
    let result = PkiHeader::from_der(header_01);
    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.pvno, Pvno::Cmp2000);

    let reencoded_header_01 = header.to_der().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}

#[test]
fn ir_rsp_body_test() {
    // read PkiBody cracked from request object used in ir_rsp_message_test
    let body_01 = &hex!("A10E300C300A30080201003003020100");
    let result = PkiBody::from_der(body_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let body = result.unwrap();

    let reencoded_body_01 = body.to_der().unwrap();
    println!("Original : {:02X?}", body_01);
    println!("Reencoded: {:02X?}", reencoded_body_01);
    assert_eq!(body_01, reencoded_body_01.as_slice());
}

#[test]
fn ir_certrepmessage_test() {
    // read CertRepMessage cracked from request object used in ir_rsp_message_test
    let orig_cert_response = &hex!("300C300A30080201003003020100");
    let result = CertRepMessage::from_der(orig_cert_response);
    println!("{:?}", result);
    assert!(result.is_ok());
    let cert_response = result.unwrap();

    let reencoded_cert_response = cert_response.to_der().unwrap();
    println!("Original : {:02X?}", orig_cert_response);
    println!("Reencoded: {:02X?}", reencoded_cert_response);
    assert_eq!(orig_cert_response, reencoded_cert_response.as_slice());
}

#[test]
fn ir_cert_responses_test() {
    // read CertResponses cracked from request object used in ir_rsp_message_test
    let orig_cert_responses = &hex!("300A30080201003003020100");
    let result = CertResponses::from_der(orig_cert_responses);
    println!("{:?}", result);
    assert!(result.is_ok());
    let cert_response = result.unwrap();

    let reencoded_cert_response = cert_response.to_der().unwrap();
    println!("Original : {:02X?}", orig_cert_responses);
    println!("Reencoded: {:02X?}", reencoded_cert_response);
    assert_eq!(orig_cert_responses, reencoded_cert_response.as_slice());
}

#[test]
fn ir_cert_response_test() {
    // read CertResponse cracked from request object used in ir_rsp_message_test
    let orig_cert_response = &hex!("30080201003003020100");
    let result = CertResponse::from_der(orig_cert_response);
    println!("{:?}", result);
    assert!(result.is_ok());
    let cert_response = result.unwrap();

    let reencoded_cert_response = cert_response.to_der().unwrap();
    println!("Original : {:02X?}", orig_cert_response);
    println!("Reencoded: {:02X?}", reencoded_cert_response);
    assert_eq!(orig_cert_response, reencoded_cert_response.as_slice());
}

#[test]
fn ir_rsp_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd ir -server 127.0.0.1:8888 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -newkey ec384-key-pair.pem -subject "/CN=MyName" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout req.bin -rspout rsp.bin
    let req_01 = include_bytes!("examples/ir_rsp_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let message = result.unwrap();

    let enc_server_cert = include_bytes!("examples/ec384-server-key.der");
    let server_cert = Certificate::from_der(enc_server_cert).unwrap();
    let header = &message.header;
    match &header.sender {
        GeneralName::DirectoryName(name) => assert_eq!(server_cert.tbs_certificate.subject, *name),
        _ => panic!(),
    }
    match &header.recipient {
        GeneralName::DirectoryName(name) => assert_eq!("CN=MyName", name.to_string()),
        _ => panic!(),
    }
    let m = header.message_time.unwrap();
    assert_eq!(1673871250000, m.to_unix_duration().as_millis());
    assert_eq!(
        const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
        header.protection_alg.as_ref().unwrap().oid
    );
    //inspect params
    assert_eq!(
        "ABCD".as_bytes(),
        header.sender_kid.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("5D 8A 64 21 9A 32 53 B4 FE 86 73 BB 21 56 F0 4D"),
        header.trans_id.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("35 E1 03 5B 67 90 9F DA 85 8F 7A 4D 01 33 B7 8B"),
        header.sender_nonce.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("89 34 8B 3E 06 61 33 53 15 C8 A2 64 58 6F 0A 59"),
        header.recip_nonce.as_ref().unwrap().as_bytes()
    );

    match &message.body {
        PkiBody::Ip(ip) => {
            assert_eq!(1, ip.response.len());
            let cr = &ip.response[0];
            assert_eq!([0x00], cr.cert_req_id.as_bytes());
            let status = &cr.status;
            assert_eq!(PkiStatus::Accepted, status.status);
        }
        _ => panic!(),
    };

    let protection = message.protection.as_ref().unwrap();
    assert_eq!(107u32, protection.encoded_len().unwrap().into());

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {:02X?}", req_01);
    println!("Reencoded: {:02X?}", reencoded_req_01);
    assert_eq!(req_01, reencoded_req_01.as_slice());
}
