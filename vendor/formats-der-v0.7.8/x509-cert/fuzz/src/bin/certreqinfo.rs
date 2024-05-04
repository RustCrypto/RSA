#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_cert::der::Decode;
use x509_cert::request::CertReqInfo;

fuzz_target!(|input: &[u8]| {
    let _ = CertReqInfo::from_der(input);
});
