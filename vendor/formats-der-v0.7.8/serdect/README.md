# [RustCrypto]: Constant-Time Serde Helpers

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache 2.0/MIT Licensed][license-image]
![MSRV][msrv-image]

Constant-time serde serializer/deserializer helpers for data that potentially
contains secrets (e.g. cryptographic keys)

[Documentation][docs-link]

## About

[Serialization is a potential sidechannel for leaking sensitive secrets][Util::Lookup]
such as cryptographic keys.

This crate provides "best effort" constant-time helper methods for reducing
the amount of timing variability involved in serializing/deserializing data
when using `serde`, Rust's standard serialization framework.

These helper methods conditionally serialize data as hexadecimal using the
constant-time [`base16ct`] crate when using human-readable formats such as
JSON or TOML. When using a binary format, the data is serialized as-is into
binary.

While this crate can't ensure that format implementations don't perform
other kinds of data-dependent branching on the contents of the serialized data,
using a constant-time hex serialization with human-readable formats should
help reduce the overall timing variability.

## Minimum Supported Rust Version

Rust **1.60** or newer.

In the future, we reserve the right to change MSRV (i.e. MSRV is out-of-scope
for this crate's SemVer guarantees), however when we do it will be accompanied by
a minor version bump.

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

[crate-image]: https://buildstats.info/crate/serdect
[crate-link]: https://crates.io/crates/serdect
[docs-image]: https://docs.rs/serdect/badge.svg
[docs-link]: https://docs.rs/serdect/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg
[build-image]: https://github.com/RustCrypto/formats/actions/workflows/serdect.yml/badge.svg
[build-link]: https://github.com/RustCrypto/formats/actions/workflows/serdect.yml

[//]: # (general links)

[RustCrypto]: https://github.com/RustCrypto
[Util::Lookup]: https://arxiv.org/pdf/2108.04600.pdf
[`base16ct`]: https://github.com/RustCrypto/formats/tree/master/base16ct
