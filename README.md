# RSA
[![crates.io](https://img.shields.io/crates/v/rsa.svg)](https://crates.io/crates/rsa) [![Documentation](https://docs.rs/rsa/badge.svg)](https://docs.rs/rsa) [![Build Status](https://travis-ci.org/RustCrypto/rsa.svg?branch=master)](https://travis-ci.org/RustCrypto/rsa) [![dependency status](https://deps.rs/repo/github/RustCrypto/rsa/status.svg)](https://deps.rs/repo/github/RustCrypto/rsa)

A portable RSA implementation in pure Rust.

:warning: **WARNING:** This library has __not__ been audited, so please do not use for production code.

## Status

Currently at Phase 1 (v) :construction:.

There will be three phases before `1.0` :ship: can be released.

1. :construction:  Make it work
    1. Prime generation :white_check_mark:
    2. Key generation :white_check_mark:
    3. PKCS1v1.5: Encryption & Decryption :white_check_mark:
    4. PKCS1v1.5: Sign & Verify :white_check_mark:
    5. PKCS1v1.5 (session key): Encryption & Decryption
    6. OAEP: Encryption & Decryption
    7. PSS: Sign & Verify
    8. Key import & export
2. :rocket: Make it fast
    1. Benchmarks :white_check_mark:
    2. compare to other implementations :construction:
    3. optimize :construction:
3. :lock: Make it secure
    1. Fuzz testing
    2. Security Audits
    3. Fix all bugs found through the above


## License

MIT or Apache 2.0
