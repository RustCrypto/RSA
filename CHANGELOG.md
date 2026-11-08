# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.10.0 (2026-11-08)
### Security
- Replace `num-bigint-dig` with `crypto-bigint` for constant-time modular exponentiation ([#394])
- Redact private-key components from `Debug` output ([#480])
- Harden private-key operations following `draft-irtf-cfrg-rsa-guidance` ([#710], [#715], [#739],
  [#751], [#752], [#755], [#756], [#758], [#770], [#771], [#773])
- Zeroize stored secret-prime Montgomery parameters in `PrecomputedValues` ([#716])
- Implement PKCS#1 v1.5 implicit rejection: return deterministic synthetic plaintext on invalid
  padding instead of exposing a padding error and with it a sidechannel ([#726], [#729], [#749])

### Added
- PKCS#8/SPKI decoding for PSS keys, including `id-RSASSA-PSS` algorithm identifiers ([#424])
- `pss::VerifyingKey::salt_len` and opt-in automatic salt-length detection via
  `new_with_auto_salt_len` ([#448], [#546])
- Wycheproof test coverage for PKCS#1 v1.5, PSS, and OAEP ([#477], [#740])
- `PublicKeyParts::n_bytes` and `e_bytes` serialization helpers ([#519])
- Multipart signing trait implementations for PKCS#1 v1.5 and PSS ([#525])
- `Clone` and `core::error::Error` implementations for `Error` ([#530], [#694])
- `PrivateKey::as_public_key` accessor ([#592])
- Algorithm-specific inherent methods on `PrivateKey` and `PublicKey` for OAEP encryption/decryption
  and PKCS#1 v1.5/PSS signing/verification, including prehash and explicit-RNG variants ([#638])
- `PrivateKey::from_components_with_large_exponent`, gated on `hazmat` ([#648])
- Constant-time validation harness using `cargo checkct`/BINSEC ([#732], [#733], [#749], [#756],
  [#771], [#773])
- `PrivateKey::from_components_with_wide_primes` for unbalanced two-prime keys, which ordinary
  constructors now reject ([#755])
- `TryFrom<BitStringRef<'_>>` for PKCS#1 v1.5 and PSS signatures ([#764])
- `crypto_common::Generate` implementation and `Generate` re-export for generating 3072-bit keys
  with public exponent 65537 ([#780])

### Changed
- Replace `BigUint` in the public API with `BoxedUint`; return `NonZero<BoxedUint>` for the modulus
  and `Odd<BoxedUint>` for prime factors ([#394], [#735])
- Use `crypto-primes` for prime generation ([#394])
- Use DER-based key encodings and hex-or-binary serde representations via `serdect`; extend serde
  support to OAEP, PKCS#1 v1.5, and PSS wrapper types ([#420])
- Accept arbitrary byte strings as OAEP labels ([#467])
- Gate PKCS#1/PKCS#8/SPKI support on the default-enabled `encoding` feature; `std` no longer
  implicitly enables encoding dependencies ([#537], [#543])
- Enforce a 1024-bit minimum for key generation and default public-key construction/decoding; add
  `PublicKey::new_with_size_limits` and `hazmat`-gated unchecked key generation ([#576], [#760])
- Bump `pkcs1` to v0.8; `pkcs8` to v0.11; `spki` to v0.8; `serdect` to v0.4 ([#584], [#684], [#688],
  [#766])
- Make `Oaep` and `Pss` generic over their digest types instead of using `DynDigest` ([#593])
- Bump `rand_core` to v0.10, `crypto-common` to v0.2, `digest` to v0.11, and `signature` to v3
  ([#650], [#671], [#693])
- Remove a redundant allocation during OAEP decryption ([#659])
- Improve encryption and verification performance by bounding exponentiation to the public
  exponent's bit length ([#662])
- Bump `crypto-bigint` to v0.7.10 and `crypto-primes` to v0.7 ([#673], [#766])
- Raise the default maximum public-key modulus size to 8192 bits ([#681])
- Bump `sha1` and `sha2` to v0.11 ([#683])
- Store PKCS#1 v1.5 and PSS signatures as byte strings, preserving their encoded width ([#722],
  [#723])
- MSRV 1.87; Rust 2024 edition ([#731], [#757])
- Enable `getrandom` by default and use the system RNG for blinding in default decryption and
  signing paths ([#739], [#758])
- Limit signature decoding to 1024 bytes by default; add `Signature::from_bytes_with_max_len` for
  explicit limits ([#767])
- Require the opt-in `pkcs1v15` feature for PKCS#1 v1.5 encryption and signatures ([#778])
- Accept fallible RNGs through `TryCryptoRng` and propagate RNG failures as errors ([#779])
- Rename `RsaPrivateKey` and `RsaPublicKey` to `PrivateKey` and `PublicKey`, retaining the old names
  as deprecated aliases ([#781])

### Deprecated
- `pss::BlindedSigningKey` in favor of `pss::SigningKey`, which now applies blinding by
  default ([#758])
- `PublicKey::new_with_max_size` in favor of `PublicKey::new_with_size_limits` ([#760])

### Removed
- `nightly` and `u64_digit` features associated with `num-bigint-dig` ([#394])
- Deprecated `Pkcs1v15Sign::new_raw` and `pkcs1v15` `*_with_prefix` constructors ([#524])
- Separate `pem` feature; PEM support is included with `encoding` ([#537])
- Optional `sha2` feature; SHA-2 support is now always enabled ([#749])

### Fixed
- Honor explicit larger-key construction limits during cryptographic operations, including OAEP
  decryption ([#441], [#595])
- PKCS#1 v1.5 `SigningKey::from` and `VerifyingKey::from` now use the digest prefix consistently
  with `new` ([#472], [#498])
- Check the modulus's actual bit length instead of its storage precision when enforcing size limits
  ([#529])
- Retry zero blinding factors instead of replacing them with one ([#653])
- Reject private-key factors less than or equal to one, even or repeated factors, and private 
  exponents greater than or equal to the modulus ([#655], [#738], [#772], [#774])
- Reject PSS salt lengths that cannot be represented by the `AlgorithmIdentifier` encoder instead of
  truncating them ([#704])
- Apply RFC 8017 encoded-message width rules for PSS, including moduli whose bit length is congruent
  to 1 modulo 8 ([#725])
- Return verification errors instead of panicking for undersized PSS encoded messages and
  overflowing salt lengths ([#769])
- Propagate CRT precomputation errors from private-key constructors ([#782])

[#394]: https://github.com/RustCrypto/RSA/pull/394
[#420]: https://github.com/RustCrypto/RSA/pull/420
[#424]: https://github.com/RustCrypto/RSA/pull/424
[#441]: https://github.com/RustCrypto/RSA/pull/441
[#448]: https://github.com/RustCrypto/RSA/pull/448
[#467]: https://github.com/RustCrypto/RSA/pull/467
[#472]: https://github.com/RustCrypto/RSA/pull/472
[#477]: https://github.com/RustCrypto/RSA/pull/477
[#480]: https://github.com/RustCrypto/RSA/pull/480
[#498]: https://github.com/RustCrypto/RSA/pull/498
[#519]: https://github.com/RustCrypto/RSA/pull/519
[#524]: https://github.com/RustCrypto/RSA/pull/524
[#525]: https://github.com/RustCrypto/RSA/pull/525
[#529]: https://github.com/RustCrypto/RSA/pull/529
[#530]: https://github.com/RustCrypto/RSA/pull/530
[#537]: https://github.com/RustCrypto/RSA/pull/537
[#543]: https://github.com/RustCrypto/RSA/pull/543
[#546]: https://github.com/RustCrypto/RSA/pull/546
[#576]: https://github.com/RustCrypto/RSA/pull/576
[#584]: https://github.com/RustCrypto/RSA/pull/584
[#592]: https://github.com/RustCrypto/RSA/pull/592
[#593]: https://github.com/RustCrypto/RSA/pull/593
[#595]: https://github.com/RustCrypto/RSA/pull/595
[#638]: https://github.com/RustCrypto/RSA/pull/638
[#648]: https://github.com/RustCrypto/RSA/pull/648
[#650]: https://github.com/RustCrypto/RSA/pull/650
[#653]: https://github.com/RustCrypto/RSA/pull/653
[#655]: https://github.com/RustCrypto/RSA/pull/655
[#659]: https://github.com/RustCrypto/RSA/pull/659
[#662]: https://github.com/RustCrypto/RSA/pull/662
[#671]: https://github.com/RustCrypto/RSA/pull/671
[#673]: https://github.com/RustCrypto/RSA/pull/673
[#681]: https://github.com/RustCrypto/RSA/pull/681
[#683]: https://github.com/RustCrypto/RSA/pull/683
[#684]: https://github.com/RustCrypto/RSA/pull/684
[#688]: https://github.com/RustCrypto/RSA/pull/688
[#693]: https://github.com/RustCrypto/RSA/pull/693
[#694]: https://github.com/RustCrypto/RSA/pull/694
[#704]: https://github.com/RustCrypto/RSA/pull/704
[#710]: https://github.com/RustCrypto/RSA/pull/710
[#715]: https://github.com/RustCrypto/RSA/pull/715
[#716]: https://github.com/RustCrypto/RSA/pull/716
[#722]: https://github.com/RustCrypto/RSA/pull/722
[#723]: https://github.com/RustCrypto/RSA/pull/723
[#725]: https://github.com/RustCrypto/RSA/pull/725
[#726]: https://github.com/RustCrypto/RSA/pull/726
[#729]: https://github.com/RustCrypto/RSA/pull/729
[#731]: https://github.com/RustCrypto/RSA/pull/731
[#732]: https://github.com/RustCrypto/RSA/pull/732
[#733]: https://github.com/RustCrypto/RSA/pull/733
[#735]: https://github.com/RustCrypto/RSA/pull/735
[#738]: https://github.com/RustCrypto/RSA/pull/738
[#739]: https://github.com/RustCrypto/RSA/pull/739
[#740]: https://github.com/RustCrypto/RSA/pull/740
[#749]: https://github.com/RustCrypto/RSA/pull/749
[#751]: https://github.com/RustCrypto/RSA/pull/751
[#752]: https://github.com/RustCrypto/RSA/pull/752
[#755]: https://github.com/RustCrypto/RSA/pull/755
[#756]: https://github.com/RustCrypto/RSA/pull/756
[#757]: https://github.com/RustCrypto/RSA/pull/757
[#758]: https://github.com/RustCrypto/RSA/pull/758
[#760]: https://github.com/RustCrypto/RSA/pull/760
[#764]: https://github.com/RustCrypto/RSA/pull/764
[#766]: https://github.com/RustCrypto/RSA/pull/766
[#767]: https://github.com/RustCrypto/RSA/pull/767
[#769]: https://github.com/RustCrypto/RSA/pull/769
[#770]: https://github.com/RustCrypto/RSA/pull/770
[#771]: https://github.com/RustCrypto/RSA/pull/771
[#772]: https://github.com/RustCrypto/RSA/pull/772
[#773]: https://github.com/RustCrypto/RSA/pull/773
[#774]: https://github.com/RustCrypto/RSA/pull/774
[#778]: https://github.com/RustCrypto/RSA/pull/778
[#779]: https://github.com/RustCrypto/RSA/pull/779
[#780]: https://github.com/RustCrypto/RSA/pull/780
[#781]: https://github.com/RustCrypto/RSA/pull/781
[#782]: https://github.com/RustCrypto/RSA/pull/782

## 0.9.8 (2025-03-12)
### Added
- Doc comments to specify the `rand` version ([#473])

[#473]: https://github.com/RustCrypto/RSA/pull/473

## 0.9.7 (2024-11-26)
### Fixed
- Always validate keys in `RsaPrivateKey::from_components` ([#459])
- Do not crash when handling tiny keys in PKCS1v15 ([#459])

[#459]: https://github.com/RustCrypto/RSA/pull/459

## 0.9.6 (2023-12-01)
### Added
- expose a `pss::get_default_pss_signature_algo_id` helper ([#393])
- expose `pkcs1v15::RsaSignatureAssociatedOid` ([#392])

[#392]: https://github.com/RustCrypto/RSA/pull/392
[#393]: https://github.com/RustCrypto/RSA/pull/393

## 0.9.5 (2023-11-27)
### Added
- Adds `RsaPrivateKey::from_primes` and `RsaPrivateKey::from_p_q` methods ([#386])

[#386]: https://github.com/RustCrypto/RSA/pull/386

## 0.9.4 (2023-11-20)
### Added
- Deterministic implementation of prime factors recovery ([#380])

[#380]: https://github.com/RustCrypto/RSA/pull/380

## 0.9.3 (2023-10-26)
### Added
- PKCS#8/SPKI decoding trait impls for `pkcs1v15` keys ([#346])
- `hazmat` feature as a replacement for `expose-internals` ([#352])

### Changed
- Bump `serde` dependency to 1.0.184 ([#360])

### Removed
- Unused dependencies ([#357])

[#346]: https://github.com/RustCrypto/RSA/pull/346
[#352]: https://github.com/RustCrypto/RSA/pull/352
[#357]: https://github.com/RustCrypto/RSA/pull/357
[#360]: https://github.com/RustCrypto/RSA/pull/360

## 0.9.2 (2023-05-08)
### Fixed
- pkcs1v15: have `fmt` impls call `SignatureEncoding::to_bytes` ([#330])

[#330]: https://github.com/RustCrypto/RSA/pull/330

## 0.9.1 (2023-05-03)
### Fixed
- Left pad signatures when encoding ([#325])

[#325]: https://github.com/RustCrypto/RSA/pull/325

## 0.9.0 (2023-04-27)
### Added
- Function to get salt length from RSA PSS keys ([#277])
- `AssociatedAlgorithmIdentifier` implementation ([#278])
- Random key generation for `pss::BlindedSigningKey` ([#295])
- Impl `Signer` for `pss::SigningKey` ([#297])
- Impl `core::hash::Hash` for `RsaPrivateKey` ([#308])
- Impl `ZeroizeOnDrop` for `RsaPrivateKey`, `SigningKey`, `DecryptingKey` ([#311])
- `u64_digit` feature; on-by-default ([#313])
- `AsRef<RsaPublicKey>` impl on `RsaPrivateKey` ([#317])

### Changed
- Use namespaced features for `serde` ([#268])
- Bump `pkcs1` to v0.7, `pkcs8` to v0.10; MSRV 1.65 ([#270])
- Rename PKCS#1v1.5 `*_with_prefix` methods ([#290])
  - `SigningKey::new` => `SigningKey::new_unprefixed`
  - `SigningKey::new_with_prefix` => `SigningKey::new`
  - `VerifyingKey::new` => `VerifyingKey::new_unprefixed`
  - `VerifyingKey::new_with_prefix` => `VerifyingKey::new`
- Rename `Pkcs1v15Sign::new_raw` to `Pkcs1v15Sign::new_unprefixed` ([#293])
- Use digest output size as default PSS salt length ([#294])
- Specify `salt_len` when verifying PSS signatures ([#294])
- Ensure signatures have the expected length and don't overflow the modulus ([#306])
- Improved public key checks ([#307])
- Rename `CRTValue` => `CrtValue` ([#314])
- Traits under `padding` module now located under `traits` module ([#315])
- `PublicKeyParts`/`PrivateKeyParts` now located under `traits` module ([#315])

### Removed
- "Unsalted" PSS support ([#294])
- `EncryptionPrimitive`/`DescriptionPrimitive` traits ([#300])
- `PublicKey`/`PrivateKey` traits ([#300])
- `Zeroize` impl on `RsaPrivateKey`; automatically zeroized on drop ([#311])
- `Deref<Target=RsaPublicKey>` impl on `RsaPrivateKey`; use `AsRef` instead ([#317])
- `expose-internals` feature and public access to all functions it gated ([#304])

[#268]: https://github.com/RustCrypto/RSA/pull/268
[#270]: https://github.com/RustCrypto/RSA/pull/270
[#277]: https://github.com/RustCrypto/RSA/pull/277
[#278]: https://github.com/RustCrypto/RSA/pull/278
[#290]: https://github.com/RustCrypto/RSA/pull/290
[#293]: https://github.com/RustCrypto/RSA/pull/293
[#294]: https://github.com/RustCrypto/RSA/pull/294
[#295]: https://github.com/RustCrypto/RSA/pull/295
[#297]: https://github.com/RustCrypto/RSA/pull/297
[#300]: https://github.com/RustCrypto/RSA/pull/300
[#306]: https://github.com/RustCrypto/RSA/pull/306
[#307]: https://github.com/RustCrypto/RSA/pull/307
[#308]: https://github.com/RustCrypto/RSA/pull/308
[#311]: https://github.com/RustCrypto/RSA/pull/311
[#313]: https://github.com/RustCrypto/RSA/pull/313
[#314]: https://github.com/RustCrypto/RSA/pull/314
[#315]: https://github.com/RustCrypto/RSA/pull/315
[#317]: https://github.com/RustCrypto/RSA/pull/317

## 0.8.2 (2023-03-01)
### Added
- Encryption-related traits ([#259])

### Fixed
- Possible panic in `internals::left_pad` ([#262])
- Correct PSS sign/verify when key length is multiple of 8+1 bits ([#263])

[#259]: https://github.com/RustCrypto/RSA/pull/259
[#262]: https://github.com/RustCrypto/RSA/pull/262
[#263]: https://github.com/RustCrypto/RSA/pull/263

## 0.8.1 (2023-01-20)
### Added
- `sha2` feature with `oid` subfeature enabled ([#255])

[#255]: https://github.com/RustCrypto/RSA/pull/255

## 0.8.0 (2023-01-17)
### Changed
- Bump `signature` crate dependency to v2 ([#217], [#249])
- Switch to `CryptoRngCore` marker trait ([#237])
- Make `padding` module private ([#243])
- Refactor `PaddingScheme` into a trait ([#244])

### Fixed
- Benchmark build ([#225])

[#217]: https://github.com/RustCrypto/RSA/pull/217
[#225]: https://github.com/RustCrypto/RSA/pull/225
[#237]: https://github.com/RustCrypto/RSA/pull/237
[#243]: https://github.com/RustCrypto/RSA/pull/243
[#244]: https://github.com/RustCrypto/RSA/pull/244
[#249]: https://github.com/RustCrypto/RSA/pull/249

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
