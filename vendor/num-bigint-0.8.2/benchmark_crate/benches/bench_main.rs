#[macro_use]
extern crate criterion;
extern crate num_bigint_dig as num_bigint;
extern crate num_integer;
extern crate num_traits;
extern crate rand;
extern crate rand_chacha;

mod benchmarks;

criterion_main! {
    benchmarks::prime_benches::benches,
    benchmarks::gcd::benches,
    benchmarks::egcd::benches,
    benchmarks::factorial::benches,
    benchmarks::bigint::benches,
    benchmarks::roots::benches,
}
