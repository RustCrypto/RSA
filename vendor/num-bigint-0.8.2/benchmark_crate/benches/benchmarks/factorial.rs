use criterion::Criterion;
use num_bigint::BigUint;
use num_traits::One;
use std::ops::{Div, Mul};

fn factorial_mul_biguint(c: &mut Criterion) {
    c.bench_function("factorial_mul_biguint", move |b| {
        b.iter(|| {
            (1u32..1000)
                .map(BigUint::from)
                .fold(BigUint::one(), Mul::mul)
        })
    });
}

fn factorial_mul_u32(c: &mut Criterion) {
    c.bench_function("factorial_mul_u32", move |b| {
        b.iter(|| (1u32..1000).fold(BigUint::one(), Mul::mul))
    });
}

// The division test is inspired by this blog comparison:
// <https://tiehuis.github.io/big-integers-in-zig#division-test-single-limb>

fn factorial_div_biguint(c: &mut Criterion) {
    let n: BigUint = (1u32..1000).fold(BigUint::one(), Mul::mul);

    c.bench_function("factorial_div_biguint", move |b| {
        b.iter(|| {
            (1u32..1000)
                .rev()
                .map(BigUint::from)
                .fold(n.clone(), Div::div)
        })
    });
}

fn factorial_div_u32(c: &mut Criterion) {
    let n: BigUint = (1u32..1000).fold(BigUint::one(), Mul::mul);

    c.bench_function("factorial_div_u32", move |b| {
        b.iter(|| (1u32..1000).rev().fold(n.clone(), Div::div))
    });
}

criterion_group! {
    name = benches;
    config = { let c = Criterion::default(); c.sample_size(5) };
    targets =
        factorial_mul_biguint,
        factorial_mul_u32,
        factorial_div_biguint,
        factorial_div_u32,
}
