# [RustCrypto]: RSA

[![crates.io][crate-image]][crate-link]
[![Documentation][doc-image]][doc-link]
[![Build Status][build-image]][build-link]
[![Dependency Status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]
![MSRV][msrv-image]
[![Project Chat][chat-image]][chat-link]

A portable RSA implementation in pure Rust, with encryption and signature schemes
specified in [PKCS#1 v2.2 (RFC8017)][RFC8017].

| Scheme | Purpose | Specification |
| --- | --- | --- |
| RSAES-OAEP | Encryption | [RFC8017 §7.1][RSAES-OAEP] |
| RSAES-PKCS1-v1_5 | Encryption | [RFC8017 §7.2][RSAES-PKCS1-v1_5] |
| RSASSA-PSS | Signatures | [RFC8017 §8.1][RSASSA-PSS] |
| RSASSA-PKCS1-v1_5 | Signatures | [RFC8017 §8.2][RSASSA-PKCS1-v1_5] |

PKCS#1 v1.5 encryption is provided for compatibility with legacy applications only.
Prefer OAEP and PSS for new encryption applications.

See the security warning below for known implementation vulnerabilities.

## Example

```rust
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

let mut rng = rand::rng();
let bits = 2048;
let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
let pub_key = RsaPublicKey::from(&priv_key);

// Encrypt
let data = b"hello world";
let enc_data = pub_key.encrypt(&mut rng, Oaep::<Sha256>::new(), &data[..]).expect("failed to encrypt");
assert_ne!(&data[..], &enc_data[..]);

// Decrypt
let dec_data = priv_key.decrypt_blinded(&mut rng, Oaep::<Sha256>::new(), &enc_data).expect("failed to decrypt");
assert_eq!(&data[..], &dec_data[..]);
```

> **Note:** If you encounter unusually slow key generation time while using `RsaPrivateKey::new` you can try to compile in release mode or add the following to your `Cargo.toml`. Key generation is much faster when building with higher optimization levels, but this will increase the compile time a bit.
> ```toml
> [profile.debug]
> opt-level = 3
> ```

## Status

Currently at Phase 1 (v) 🚧

There will be three phases before `1.0` 🚢 can be released.

1. 🚧  Make it work
    - [x] Prime generation ✅
    - [x] Key generation ✅
    - [x] PKCS1v1.5: Encryption & Decryption ✅
    - [x] PKCS1v1.5: Sign & Verify ✅
    - [ ] PKCS1v1.5 (session key): Encryption & Decryption
    - [x] OAEP: Encryption & Decryption
    - [x] PSS: Sign & Verify
    - [x] Key import & export
2. 🚀 Make it fast
    - [x] Benchmarks ✅
    - [ ] compare to other implementations 🚧
    - [ ] optimize 🚧
3. 🔐 Make it secure
    - [ ] Fuzz testing
    - [ ] Security Audits

## ⚠️Security Warning

This crate has received one [security audit by Include Security][audit], with
only one minor finding which has since been addressed.

See the [open security issues] on our issue tracker for other known problems.

~~Notably the implementation of [modular exponentiation is not constant time],
but timing variability is masked using [random blinding], a commonly used
technique.~~ This crate is vulnerable to the [Marvin Attack] which could enable
private key recovery by a network attacker (see [RUSTSEC-2023-0071]).

You can follow our work on mitigating this issue in [#390].

## Minimum Supported Rust Version (MSRV)

This crate supports Rust 1.85 or higher.

In the future MSRV can be changed, but it will be done with a minor version bump.

## License

Licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/rsa?logo=rust
[crate-link]: https://crates.io/crates/rsa
[doc-image]: https://docs.rs/rsa/badge.svg
[doc-link]: https://docs.rs/rsa
[build-image]: https://github.com/RustCrypto/RSA/actions/workflows/ci.yml/badge.svg
[build-link]: https://github.com/RustCrypto/RSA/actions/workflows/ci.yml
[build-image]: https://github.com/RustCrypto/RSA/actions/workflows/ci.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/RSA/actions/workflows/ci.yml?query=branch:master
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.87+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260047-RSA
[deps-image]: https://deps.rs/repo/github/RustCrypto/RSA/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/RSA

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto/
[audit]: https://public.opentech.fund/documents/1907_OTF_DeltaChat_RPGP_RustRSA_GB_Report_v1.pdf
[open security issues]: https://github.com/RustCrypto/RSA/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity
[modular exponentiation is not constant time]: https://github.com/RustCrypto/RSA/issues/19
[random blinding]: https://en.wikipedia.org/wiki/Blinding_(cryptography)
[Marvin Attack]: https://people.redhat.com/~hkario/marvin/
[RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
[#390]: https://github.com/RustCrypto/RSA/issues/390

[RFC8017]: https://www.rfc-editor.org/rfc/rfc8017.html
[RSAES-OAEP]: https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1
[RSAES-PKCS1-v1_5]: https://www.rfc-editor.org/rfc/rfc8017.html#section-7.2
[RSASSA-PSS]: https://www.rfc-editor.org/rfc/rfc8017.html#section-8.1
[RSASSA-PKCS1-v1_5]: https://www.rfc-editor.org/rfc/rfc8017.html#section-8.2
