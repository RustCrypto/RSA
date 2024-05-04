//! `Algorithm Identifier Types` [RFC 5652 § 10.1](https://datatracker.ietf.org/doc/html/rfc5652#section-10.1)

use der::asn1::SetOfVec;
use spki::AlgorithmIdentifierRef;

/// ```text
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
/// See [RFC 5652 10.1.1](https://datatracker.ietf.org/doc/html/rfc5652#section-10.1.1).
pub type DigestAlgorithmIdentifier<'a> = AlgorithmIdentifierRef<'a>;

/// ```text
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// ```
pub type DigestAlgorithmIdentifiers<'a> = SetOfVec<DigestAlgorithmIdentifier<'a>>;

/// ```text
/// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
/// See [RFC 5652 10.1.2](https://datatracker.ietf.org/doc/html/rfc5652#section-10.1.2).
pub type SignatureAlgorithmIdentifier<'a> = AlgorithmIdentifierRef<'a>;
