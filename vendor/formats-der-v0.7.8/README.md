# [RustCrypto]: Formats [![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link]

Cryptography-related format encoders/decoders (e.g. PKCS, PKIX)

## Crates

| Name          | crates.io                                                                                             | Docs                                                                                   | Description                                                                                                                                |
|---------------|-------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| `base16ct`    | [![crates.io](https://img.shields.io/crates/v/base16ct.svg)](https://crates.io/crates/base16ct)       | [![Documentation](https://docs.rs/base16ct/badge.svg)](https://docs.rs/base16ct)       | Constant-time hexadecimal encoder/decoder                                                                                                  |
| `base32ct`    | [![crates.io](https://img.shields.io/crates/v/base32ct.svg)](https://crates.io/crates/base32ct)       | [![Documentation](https://docs.rs/base32ct/badge.svg)](https://docs.rs/base32ct)       | Constant-time Base32 encoder/decoder                                                                                                       |
| `base64ct`    | [![crates.io](https://img.shields.io/crates/v/base64ct.svg)](https://crates.io/crates/base64ct)       | [![Documentation](https://docs.rs/base64ct/badge.svg)](https://docs.rs/base64ct)       | Constant-time Base64 encoder/decoder with support for several variants                                                                     |
| `cms`         | [![crates.io](https://img.shields.io/crates/v/cms.svg)](https://crates.io/crates/cms)                 | [![Documentation](https://docs.rs/cms/badge.svg)](https://docs.rs/cms)                 | Implementation of the Cryptographic Message Syntax (CMS) as described in [RFC 5652], [RFC 5911], and in [RFC 3274].                        |
| `const‑oid`   | [![crates.io](https://img.shields.io/crates/v/const-oid.svg)](https://crates.io/crates/const-oid)     | [![Documentation](https://docs.rs/const-oid/badge.svg)](https://docs.rs/const-oid)     | Const-friendly implementation of the ISO/IEC Object Identifier (OID) standard as defined in [ITU X.660]                                    |
| `der`         | [![crates.io](https://img.shields.io/crates/v/der.svg)](https://crates.io/crates/der)                 | [![Documentation](https://docs.rs/der/badge.svg)](https://docs.rs/der)                 | Decoder and encoder of the Distinguished Encoding Rules (DER) for Abstract Syntax Notation One (ASN.1) as described in [ITU X.690]         |
| `pem‑rfc7468` | [![crates.io](https://img.shields.io/crates/v/pem-rfc7468.svg)](https://crates.io/crates/pem-rfc7468) | [![Documentation](https://docs.rs/pem-rfc7468/badge.svg)](https://docs.rs/pem-rfc7468) | Strict PEM encoding for PKIX/PKCS/CMS objects                                                                                              |
| `pkcs1`       | [![crates.io](https://img.shields.io/crates/v/pkcs1.svg)](https://crates.io/crates/pkcs1)             | [![Documentation](https://docs.rs/pkcs1/badge.svg)](https://docs.rs/pkcs1)             | Implementation of PKCS#1: RSA Cryptography Specifications Version 2.2 ([RFC 8017])                                                         |
| `pkcs5`       | [![crates.io](https://img.shields.io/crates/v/pkcs5.svg)](https://crates.io/crates/pkcs5)             | [![Documentation](https://docs.rs/pkcs5/badge.svg)](https://docs.rs/pkcs5)             | Implementation of PKCS#5: Password-Based Cryptography Specification Version 2.1 ([RFC 8018])                                               |
| `pkcs7`       | [![crates.io](https://img.shields.io/crates/v/pkcs7.svg)](https://crates.io/crates/pkcs7)             | [![Documentation](https://docs.rs/pkcs7/badge.svg)](https://docs.rs/pkcs7)             | Implementation of PKCS#7: Cryptographic Message Syntax v1.5 ([RFC 5652] and [RFC 8933]) 🚨 Deprecated in favor of `cms`                    |
| `pkcs8`       | [![crates.io](https://img.shields.io/crates/v/pkcs8.svg)](https://crates.io/crates/pkcs8)             | [![Documentation](https://docs.rs/pkcs8/badge.svg)](https://docs.rs/pkcs8)             | Implementation of PKCS#8(v2): Private-Key Information Syntax Specification ([RFC 5208]) and asymmetric key packages ([RFC 5958])           |
| `pkcs10`      | [![crates.io](https://img.shields.io/crates/v/pkcs10.svg)](https://crates.io/crates/pkcs10)           | [![Documentation](https://docs.rs/pkcs10/badge.svg)](https://docs.rs/pkcs10)           | Implementation of PKCS#10: Certification Request Syntax Specification ([RFC 2986])                                                         |
| `sec1`        | [![crates.io](https://img.shields.io/crates/v/sec1.svg)](https://crates.io/crates/sec1)               | [![Documentation](https://docs.rs/sec1/badge.svg)](https://docs.rs/sec1)               | [SEC1: Elliptic Curve Cryptography] encoding formats                                                                                       |
| `spki`        | [![crates.io](https://img.shields.io/crates/v/spki.svg)](https://crates.io/crates/spki)               | [![Documentation](https://docs.rs/spki/badge.svg)](https://docs.rs/spki)               | X.509 Subject Public Key Info ([RFC 5280 Section 4.1]) describing public keys as well as their associated AlgorithmIdentifiers (i.e. OIDs) |
| `tai64`       | [![crates.io](https://img.shields.io/crates/v/tai64.svg)](https://crates.io/crates/tai64)             | [![Documentation](https://docs.rs/tai64/badge.svg)](https://docs.rs/tai64)             | TAI64(N) Timestamps                                                                                                                        |
| `tls_codec`   | [![crates.io](https://img.shields.io/crates/v/tls_codec.svg)](https://crates.io/crates/tls_codec)     | [![Documentation](https://docs.rs/tls_codec/badge.svg)](https://docs.rs/tls_codec)     | TLS codec as defined in [RFC 8446 Section 3] as well as some extensions required by MLS.                                                   |
| `x509-cert`   | [![crates.io](https://img.shields.io/crates/v/x509-cert.svg)](https://crates.io/crates/x509-cert)     | [![Documentation](https://docs.rs/x509-cert/badge.svg)](https://docs.rs/x509-cert)     | X.509 Public Key Infrastructure Certificate format as described in [RFC 5280]                                                              |

## License

All crates licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # "badges"
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[deps-image]: https://deps.rs/repo/github/RustCrypto/formats/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/formats

[//]: # "links"
[rustcrypto]: https://github.com/rustcrypto
[itu x.660]: https://www.itu.int/rec/T-REC-X.660
[itu x.690]: https://www.itu.int/rec/T-REC-X.690
[rfc 2986]: https://datatracker.ietf.org/doc/html/rfc2986
[rfc 3274]: https://datatracker.ietf.org/doc/html/rfc3274
[rfc 4251]: https://datatracker.ietf.org/doc/html/rfc4251
[rfc 4253]: https://datatracker.ietf.org/doc/html/rfc4253
[rfc 5208]: https://datatracker.ietf.org/doc/html/rfc5208
[rfc 5280 section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
[rfc 5280]: https://datatracker.ietf.org/doc/html/rfc5280
[rfc 5652]: https://datatracker.ietf.org/doc/html/rfc5652
[rfc 5911]: https://datatracker.ietf.org/doc/html/rfc5911
[rfc 5958]: https://datatracker.ietf.org/doc/html/rfc5958
[rfc 8017]: https://datatracker.ietf.org/doc/html/rfc8017
[rfc 8018]: https://datatracker.ietf.org/doc/html/rfc8018
[rfc 8933]: https://datatracker.ietf.org/doc/html/rfc8933
[rfc 8446 section 3]: https://datatracker.ietf.org/doc/html/rfc8446#section-3
[sec1: elliptic curve cryptography]: https://www.secg.org/sec1-v2.pdf
