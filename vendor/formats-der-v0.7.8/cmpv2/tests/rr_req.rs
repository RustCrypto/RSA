use cmpv2::body::PkiBody;
use cmpv2::header::{PkiHeader, Pvno};
use cmpv2::message::PkiMessage;
use der::{Decode, Encode};

#[test]
fn rr_rsp_header_test() {
    // read PkiHeader cracked from request object used in rr_rsp_message_test
    let header_01 = include_bytes!("examples/rr_rsp_header_01.bin");
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
fn rr_rsp_body_test() {
    // read PkiBody cracked from request object used in rr_rsp_message_test
    let body_01 = include_bytes!("examples/rr_rsp_body_01.bin");
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
fn rr_req_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd rr -server 127.0.0.1:8080 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout rr_req_01.bin -rspout rr_rsp_01.bin -oldcert ec384-ee-key.crt
    let req_01 = include_bytes!("examples/rr_req_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let message = result.unwrap();

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {:02X?}", req_01);
    println!("Reencoded: {:02X?}", reencoded_req_01);
    assert_eq!(req_01, reencoded_req_01.as_slice());
}

#[test]
fn rr_rsp_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd rr -server 127.0.0.1:8080 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout rr_req_01.bin -rspout rr_rsp_01.bin -oldcert ec384-ee-key.crt
    let req_01 = include_bytes!("examples/rr_rsp_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let message = result.unwrap();

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {:02X?}", req_01);
    println!("Reencoded: {:02X?}", reencoded_req_01);
    assert_eq!(req_01, reencoded_req_01.as_slice());
}
