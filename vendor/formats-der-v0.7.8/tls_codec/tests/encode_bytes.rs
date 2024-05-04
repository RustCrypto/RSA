use tls_codec::SerializeBytes;

#[test]
fn serialize_primitives() {
    let mut v = Vec::new();
    v.append(&mut 77u8.tls_serialize().expect("Error encoding u8"));
    v.append(&mut 88u8.tls_serialize().expect("Error encoding u8"));
    v.append(&mut 355u16.tls_serialize().expect("Error encoding u16"));
    let b = [77u8, 88, 1, 99];
    assert_eq!(&b[..], &v[..]);
}

#[test]
fn serialize_var_len_vec() {
    let v = vec![9u8, 2, 98, 34, 55, 90, 54];
    let serialized = v.tls_serialize().expect("Error encoding vector");
    assert_eq!(serialized, vec![7, 9, 2, 98, 34, 55, 90, 54]);

    let serialized = Vec::<u8>::new()
        .tls_serialize()
        .expect("Error encoding vector");
    assert_eq!(serialized, vec![0x00]);
}

#[test]
fn serialize_var_len_boundaries() {
    let v = vec![99u8; 63];
    let serialized = v.tls_serialize().expect("Error encoding vector");
    assert_eq!(&serialized[0..5], &[63, 99, 99, 99, 99]);

    let v = vec![99u8; 64];
    let serialized = v.tls_serialize().expect("Error encoding vector");
    assert_eq!(&serialized[0..5], &[0x40, 64, 99, 99, 99]);

    let v = vec![99u8; 16383];
    let serialized = v.tls_serialize().expect("Error encoding vector");
    assert_eq!(&serialized[0..5], &[0x7f, 0xff, 99, 99, 99]);

    let v = vec![99u8; 16384];
    let serialized = v.tls_serialize().expect("Error encoding vector");
    assert_eq!(&serialized[0..5], &[0x80, 0, 0x40, 0, 99]);
}
