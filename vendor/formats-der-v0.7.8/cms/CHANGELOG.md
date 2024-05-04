# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.2 (2023-07-14)
### Added
- `SignedData` builder ([#1051])

### Changed
- Deprecate `pkcs7` in favor of `cms` ([#1062])
- der: add `SetOf(Vec)::insert(_ordered)`; deprecate `add` ([#1067])
- Re-enable all minimal-versions checks ([#1071])

### Fixed
- Don't insert signing time attribute by default ([#1148])
- Fixed encoding of `SubjectKeyIdentifier` ([#1152])

[#1051]: https://github.com/RustCrypto/formats/pull/1051
[#1062]: https://github.com/RustCrypto/formats/pull/1062
[#1067]: https://github.com/RustCrypto/formats/pull/1067
[#1071]: https://github.com/RustCrypto/formats/pull/1071
[#1148]: https://github.com/RustCrypto/formats/pull/1148
[#1152]: https://github.com/RustCrypto/formats/pull/1152

## 0.2.1 (2023-05-04)
### Added
- Convenience functions for converting cert(s) to certs-only `SignedData` message ([#1032])

[#1032]: https://github.com/RustCrypto/formats/pull/1032

## 0.2.0 (2023-03-18)
- Initial RustCrypto release

## 0.1.0 (2019-05-08)
