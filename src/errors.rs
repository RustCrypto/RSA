pub type Result<T> = ::std::result::Result<T, Error>;

/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "invalid padding scheme")]
    InvalidPaddingScheme,
    #[fail(display = "decryption error")]
    Decryption,
    #[fail(display = "verification error")]
    Verification,
    #[fail(display = "message too long")]
    MessageTooLong,
    #[fail(display = "input must be hashed")]
    InputNotHashed,
    #[fail(display = "nprimes must be >= 2")]
    NprimesTooSmall,
    #[fail(display = "too few primes of given length to generate an RSA key")]
    TooFewPrimes,
    #[fail(display = "invalid prime value")]
    InvalidPrime,
    #[fail(display = "invalid modulus")]
    InvalidModulus,
    #[fail(display = "invalid exponent")]
    InvalidExponent,
    #[fail(display = "invalid coefficient")]
    InvalidCoefficient,
    #[fail(display = "public exponent too small")]
    PublicExponentTooSmall,
    #[fail(display = "public exponent too large")]
    PublicExponentTooLarge,
    #[fail(display = "parse error: {}", reason)]
    ParseError { reason: String },
    #[fail(display = "internal error")]
    Internal,
}
