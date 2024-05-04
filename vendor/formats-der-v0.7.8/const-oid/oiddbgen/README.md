# Welcome to oiddbgen!

This program is internal-only and is used to generate the OID database tree.

# How to Run

If you want to generate the database yourself, from the `const-oid` directory you can just run:

```
$ cargo run --manifest-path=oiddbgen/Cargo.toml | rustfmt > src/db/gen.rs
```
