# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.1 (2023-05-13)

🚨 DEPRECATED! 🚨

Use the [`cms` crate](https://github.com/RustCrypto/formats/tree/master/cms) instead ([#1062])

[#1062]: https://github.com/RustCrypto/formats/pull/1062

## 0.4.0 (2023-03-18)
### Added
- `SignedData` type to ([#813])
- `ValueOrd` impls ([#825])

### Changed
- MSRV 1.65 ([#805])
- Bump `der` to v0.7 ([#899])
- Bump `spki` to v0.7 ([#900])
- Make `ContentInfo`'s `contentType` mandatory ([#924])
- Bump `x509-cert` to v0.2 ([#934])

[#805]: https://github.com/RustCrypto/formats/pull/805
[#813]: https://github.com/RustCrypto/formats/pull/813
[#825]: https://github.com/RustCrypto/formats/pull/825
[#899]: https://github.com/RustCrypto/formats/pull/899
[#900]: https://github.com/RustCrypto/formats/pull/900
[#924]: https://github.com/RustCrypto/formats/pull/924
[#934]: https://github.com/RustCrypto/formats/pull/934

## 0.3.0 (2021-11-15)
- Initial release: older versions are a pre-RustCrypto crate.

## 0.2.0 (2016-08-16)

## 0.1.0 (2016-08-15)
