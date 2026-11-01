# [`cargo checkct`] / [BINSEC] driver

This directory contains a test driver for ensuring that operations under test
operate in constant-time with respect to any secret inputs, using
multi-architecture static analysis of compiled binaries using [BINSEC].

It can be run using the following steps:

1. Install [BINSEC] and [`cargo checkct`]
2. Run `eval $(opam env)` to add BINSEC to your PATH
3. Run `cargo checkct run -t 10 -j 4` to perform the constant-time test

[BINSEC]: https://binsec.github.io/
[`cargo checkct`]: https://github.com/Ledger-Donjon/cargo-checkct
