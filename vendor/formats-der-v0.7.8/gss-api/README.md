# [RustCrypto]: GSS-API

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of Generic Security Service Application Program Interface ([RFC1509], [RFC2478], [RFC4178], [MS-SPNG]).

[Documentation][docs-link]

## About

The Generic Security Service Application Program Interface (abbreviated GSS-API
or GSSAPI) enables programs to access system security services. One of the
foremost security protocols used in conjunction with GSS-API is [Kerberos].

GSS-API is an IETF standard designed to address the problem of many
incompatible security services which provide similar functionality.
By itself, does not provide any security, but instead provides a common API
implemented by security-service vendors, usually in the form of libraries
installed with their security software.

These libraries implement the GSS-API which can be called from
application-level code, allowing the security implementation to be replaced
without application-level changes.

GSS-API applications exchange opaque messages, i.e. tokens, which hide the
security implementation detail from the higher-level application. The client
and server sides of the application are written to convey the tokens given to
them by their respective GSS-API implementations. GSS-API tokens can usually
travel over an insecure network as the mechanisms provide inherent message
security.

After the exchange of some number of tokens, the GSS-API implementations at
both ends inform their local application that a security context is
established.  Once a security context is established, sensitive application
messages can be wrapped (i.e. encrypted) by the GSS-API for secure
communication between client and server.

Typical protections guaranteed by GSS-API wrapping include confidentiality
(secrecy) and integrity (authenticity). GSS-API can also provide local
guarantees about the identity of the remote user or remote host.

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

[crate-image]: https://buildstats.info/crate/gss-api
[crate-link]: https://crates.io/crates/gss-api
[docs-image]: https://docs.rs/gss-api/badge.svg
[docs-link]: https://docs.rs/gss-api/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[build-image]: https://github.com/RustCrypto/formats/actions/workflows/gss-api.yml/badge.svg
[build-link]: https://github.com/RustCrypto/formats/actions/workflows/gss-api.yml

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[MS-SPNG]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng
[RFC1509]: https://datatracker.ietf.org/doc/html/rfc1509
[RFC2478]: https://datatracker.ietf.org/doc/html/rfc2478
[RFC4178]: https://datatracker.ietf.org/doc/html/rfc4178
[Kerberos]: https://en.wikipedia.org/wiki/Kerberos_(protocol)
