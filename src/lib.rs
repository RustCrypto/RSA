extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate num_iter;
extern crate rand;

pub mod prime;
pub use prime_rand::RandPrime;
pub mod key;

mod math;
mod prime_rand;
