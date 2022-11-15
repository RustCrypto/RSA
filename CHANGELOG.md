# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.2 (2022-11-14)
### Added
- Public accessor methods for `PrecomputedValues` ([#221])
- Re-export `signature` crate ([#223])

[#221]: https://github.com/RustCrypto/RSA/pull/221
[#223]: https://github.com/RustCrypto/RSA/pull/223


## 0.7.1 (2022-10-31)
### Added
- Documentation improvements ([#216])

### Changed
- Ensure `PaddingScheme` is `Send` and `Sync` ([#215])

[#215]: https://github.com/RustCrypto/RSA/pull/215
[#216]: https://github.com/RustCrypto/RSA/pull/216


## 0.7.0 (2022-10-10) [YANKED]

NOTE: when computing signatures with this release, make sure to enable the
`oid` crate feature of the digest crate you are using when computing the
signature (e.g. `sha2`, `sha3`). If the `oid` feature doesn't exist, make sure
you're using the latest versions.

### Added
- `pkcs1v15` and `pss` modules with `SigningKey`/`VerifyingKey` types
  ([#174], [#195], [#202], [#207], [#208])
- 4096-bit default max `RsaPublicKey` size ([#176])
- `RsaPublicKey::new_with_max_size` ([#176])
- `RsaPublicKey::new_unchecked` ([#206])

### Changed
- MSRV 1.57 ([#162])
- Bump `pkcs1` to 0.4 ([#162])
- Bump `pkcs8` to 0.9 ([#162])
- `RsaPrivateKey::from_components` is now fallible ([#167])
- pkcs1v15: use `AssociatedOid` for getting the RSA prefix ([#183])

### Removed
- `rng` member from PSS padding scheme ([#173])
- `Hash` removed in favor of using OIDs defined in digest crates ([#183])

[#162]: https://github.com/RustCrypto/RSA/pull/162
[#167]: https://github.com/RustCrypto/RSA/pull/167
[#173]: https://github.com/RustCrypto/RSA/pull/173
[#174]: https://github.com/RustCrypto/RSA/pull/174
[#176]: https://github.com/RustCrypto/RSA/pull/176
[#183]: https://github.com/RustCrypto/RSA/pull/183
[#195]: https://github.com/RustCrypto/RSA/pull/195
[#202]: https://github.com/RustCrypto/RSA/pull/202
[#206]: https://github.com/RustCrypto/RSA/pull/206
[#207]: https://github.com/RustCrypto/RSA/pull/207
[#208]: https://github.com/RustCrypto/RSA/pull/208


## 0.6.1 (2022-04-11)

## 0.6.0 (2022-04-08)

## 0.5.0 (2021-07-27)

## 0.4.1 (2021-07-26)

## 0.4.0 (2021-03-28)

## 0.3.0 (2020-06-11)

## 0.2.0 (2019-12-11)

## 0.1.4 (2019-10-13)

## 0.1.3 (2019-03-26)

## 0.1.2 (2019-02-25)

## 0.1.1 (2019-02-20)

## 0.1.0 (2018-12-05)
