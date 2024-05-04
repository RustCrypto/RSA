//! `CMSVersion` [RFC 5652 § 10.2.5](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.5)

use core::cmp::Ordering;
use der::{Enumerated, ValueOrd};

/// The CMSVersion type gives a syntax version number, for compatibility
/// with future revisions of this specification.
/// ```text
/// CMSVersion ::= INTEGER
///     { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
///
/// See [RFC 5652 10.2.5](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.5).
#[derive(Clone, Copy, Debug, Enumerated, Eq, PartialEq, PartialOrd, Ord)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum CmsVersion {
    /// syntax version 0
    V0 = 0,
    /// syntax version 1
    V1 = 1,
    /// syntax version 2
    V2 = 2,
    /// syntax version 3
    V3 = 3,
    /// syntax version 4
    V4 = 4,
    /// syntax version 5
    V5 = 5,
}

impl From<CmsVersion> for u8 {
    fn from(version: CmsVersion) -> u8 {
        version as u8
    }
}

// TODO(tarcieri): fix `ValueOrd` derive for this case (`asn1` attribute is clashing)
impl ValueOrd for CmsVersion {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        Ok(self.cmp(other))
    }
}
