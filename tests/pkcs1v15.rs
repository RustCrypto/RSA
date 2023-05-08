use rsa::pkcs1v15::Signature;

// simple but prevent regression - see https://github.com/RustCrypto/RSA/issues/329
#[test]
fn signature_stringify() {
        let bytes: &[u8] = &[0x03u8, 0x0Fu8];
        let signature = Signature::try_from(bytes).unwrap();
        assert_eq!(format!("{}", signature), "030F");
        assert_eq!(format!("{:x}", signature), "030f");
        assert_eq!(format!("{:X}", signature), "030F");
        assert_eq!(signature.to_string(), "030F");
}
