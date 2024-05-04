# [RustCrypto]: PKCS#7 (Cryptographic Messages)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of Public-Key Cryptography Standards (PKCS) #7:
Cryptographic Message Syntax v1.5 ([RFC 5652] and [RFC 8933]).

[Documentation][docs-link]

## 🚨 DEPRECATED! 🚨

The `pkcs7` crate is deprecated and will not receive further releases.

Please migrate to the following instead:

- For Cryptographic Message Syntax (CMS): use the [`cms` crate](https://github.com/RustCrypto/formats/tree/master/cms).
- For PKCS#7 block padding: use [`block_padding::Pkcs7`](https://docs.rs/block-padding/latest/block_padding/struct.Pkcs7.html)

See [#1045] for more information.

## Minimum Supported Rust Version

This crate requires **Rust 1.65** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/pkcs7
[crate-link]: https://crates.io/crates/pkcs7
[docs-image]: https://docs.rs/pkcs7/badge.svg
[docs-link]: https://docs.rs/pkcs7/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[build-image]: https://github.com/RustCrypto/formats/workflows/pkcs7/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/formats/actions

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC 5652]: https://datatracker.ietf.org/doc/html/rfc5652
[RFC 8933]: https://datatracker.ietf.org/doc/html/rfc8933
[#1045]: https://github.com/RustCrypto/formats/issues/1045
