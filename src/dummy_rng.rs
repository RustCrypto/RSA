use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRngCore};

/// This is a dummy RNG for cases when we need a concrete RNG type
/// which does not get used.
#[derive(Copy, Clone)]
pub(crate) struct DummyRng;

impl TryRngCore for DummyRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!();
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!();
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        unimplemented!();
    }
}

impl TryCryptoRng for DummyRng {}
