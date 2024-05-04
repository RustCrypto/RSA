Object Identifiers (OID) for SHA-3
----------------------------------
This document lists the OIDs for
- SHA3-224,
- SHA3-256,
- SHA3-384,
- SHA3-512,
- SHAKE128, and
- SHAKE256.

This file was manually created, as there exists no offical document that is easily parsable.
The SHA-3 standard is specified in [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf).
It references [Computer Security Objects Register (CSOR)]
(https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration),
which publishes the following SHA-3 OIDs:

nistAlgorithms OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) }

hashAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 2 }

id-sha3-224 OBJECT IDENTIFIER ::= { hashAlgs 7 }

id-sha3-256 OBJECT IDENTIFIER ::= { hashAlgs 8 }

id-sha3-384 OBJECT IDENTIFIER ::= { hashAlgs 9 }

id-sha3-512 OBJECT IDENTIFIER ::= { hashAlgs 10 }

id-shake128 OBJECT IDENTIFIER ::= { hashAlgs 11 }

id-shake256 OBJECT IDENTIFIER ::= { hashAlgs 12 }
