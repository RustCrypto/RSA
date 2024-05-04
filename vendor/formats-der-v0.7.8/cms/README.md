# [RustCrypto]: Cryptographic Message Syntax (CMS)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the Cryptographic Message Syntax (CMS) as described
in [RFC 5652], [RFC 5911], and in [RFC 3274].

[Documentation][docs-link]

## About

Cryptographic Message Syntax (CMS) is an IETF standard for encrypted messages,
and can be used to sign and/or encrypt data.  It uses a certificate-based
architecture for authenticating principals who can exchange encrypted and/or
signed messages.

CMS is based on the syntax of PKCS #7, itself based on the Privacy-Enhanced
Mail (PEM) standard.

It's used in many cryptographic standards, such as S/MIME, PKCS#12 and the
RFC 3161 digital timestamping protocol.

## Minimum Supported Rust Version

This crate requires **Rust 1.65** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/cms
[crate-link]: https://crates.io/crates/cms
[docs-image]: https://docs.rs/cms/badge.svg
[docs-link]: https://docs.rs/cms/
[build-image]: https://github.com/RustCrypto/formats/actions/workflows/cms.yml/badge.svg
[build-link]: https://github.com/RustCrypto/formats/actions/workflows/cms.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC 3274]: https://datatracker.ietf.org/doc/html/rfc3274
[RFC 5652]: https://datatracker.ietf.org/doc/html/rfc5652
[RFC 5911]: https://datatracker.ietf.org/doc/html/rfc5652
