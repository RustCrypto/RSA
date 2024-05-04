use cmpv2::body::PkiBody;
use cmpv2::message::PkiMessage;
use der::{Decode, Encode};
use hex_literal::hex;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::Certificate;

#[test]
fn p10cr_req_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd p10cr -server 127.0.0.1:8080 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -csr ec384-ee-key.csr -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout p10cr_req_01.bin -rspout p10cr_rsp_01.bin
    let req_01 = include_bytes!("examples/p10cr_req_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let message = result.unwrap();

    let header = &message.header;
    match &header.sender {
        GeneralName::DirectoryName(name) => assert_eq!("", name.to_string()),
        _ => panic!(),
    }
    match &header.recipient {
        GeneralName::DirectoryName(name) => assert_eq!("CN=CMPserver", name.to_string()),
        _ => panic!(),
    }
    let m = header.message_time.unwrap();
    assert_eq!(1674074939000, m.to_unix_duration().as_millis());
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
        hex!("F1 E8 88 1F D7 99 C2 7C 61 73 AE 31 71 FC D6 92"),
        header.trans_id.as_ref().unwrap().as_bytes()
    );
    assert_eq!(
        hex!("08 89 1F F4 4A DA D6 33 BB 4A 06 CA 55 54 50 24"),
        header.sender_nonce.as_ref().unwrap().as_bytes()
    );

    let enc_ee_cert = include_bytes!("examples/ec384-ee-key.der");
    let ee_cert = Certificate::from_der(enc_ee_cert).unwrap();

    match &message.body {
        PkiBody::P10cr(p10crs) => {
            assert_eq!(
                ee_cert.tbs_certificate.subject.to_string(),
                p10crs.info.subject.to_string()
            );
        }
        _ => panic!(),
    };

    let protection = message.protection.as_ref().unwrap();
    assert_eq!(
        hex!("CD 40 DF 57 71 9F 9F 0C 13 DE 41 46 17 7B E0 20 D3 2A 6D 9C"),
        protection.as_bytes().unwrap()
    );

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {:02X?}", req_01);
    println!("Reencoded: {:02X?}", reencoded_req_01);
    assert_eq!(req_01, reencoded_req_01.as_slice());
}

#[test]
fn p10cr_rsp_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd p10cr -server 127.0.0.1:8080 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -csr ec384-ee-key.csr -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout p10cr_req_01.bin -rspout p10cr_rsp_01.bin
    let req_01 = include_bytes!("examples/p10cr_rsp_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let message = result.unwrap();

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {:02X?}", req_01);
    println!("Reencoded: {:02X?}", reencoded_req_01);
    assert_eq!(req_01, reencoded_req_01.as_slice());
}
