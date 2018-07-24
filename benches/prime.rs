#![feature(test)]

extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate rsa;
extern crate test;

use num_bigint::BigUint;
use rand::{SeedableRng, StdRng};
use test::Bencher;

use rsa::prime;
use rsa::RandPrime;

const NUM: &'static str = "203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123";

macro_rules! bench_probably_prime {
    ($name:ident, $n:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let x = test::black_box(BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap());

            b.iter(|| {
                let res = prime::probably_prime(&x, $n);
                test::black_box(res);
            });
        }
    };
}

bench_probably_prime!(probably_prime_0, 0);
bench_probably_prime!(probably_prime_1, 1);
bench_probably_prime!(probably_prime_5, 5);
bench_probably_prime!(probably_prime_10, 10);
bench_probably_prime!(probably_prime_20, 20);

#[bench]
fn bench_prime_lucas(b: &mut Bencher) {
    let x = test::black_box(BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap());

    b.iter(|| {
        let res = prime::probably_prime_lucas(&x);
        test::black_box(res);
    });
}

#[bench]
fn bench_prime_miller_rabin(b: &mut Bencher) {
    let x = test::black_box(BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap());

    b.iter(|| {
        let res = prime::probably_prime_miller_rabin(&x, 1, true);
        test::black_box(res);
    });
}

#[bench]
fn bench_gen_prime(b: &mut Bencher) {
    let mut rng = StdRng::from_seed([1u8; 32]);

    b.iter(|| {
        let res = rng.gen_prime(1024);
        test::black_box(res);
    });
}
