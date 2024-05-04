use criterion::Criterion;
use num_bigint::{BigUint, RandBigInt};
use num_traits::Pow;
use rand::{rngs::StdRng, SeedableRng};

// The `big64` cases demonstrate the speed of cases where the value
// can be converted to a `u64` primitive for faster calculation.
//
// The `big1k` cases demonstrate those that can convert to `f64` for
// a better initial guess of the actual value.
//
// The `big2k` and `big4k` cases are too big for `f64`, and use a simpler guess.

fn get_rng() -> StdRng {
    let mut seed = [0; 32];
    for i in 1..32 {
        seed[usize::from(i)] = i;
    }
    SeedableRng::from_seed(seed)
}

fn check(x: &BigUint, n: u32) {
    let root = x.nth_root(n);
    if n == 2 {
        assert_eq!(root, x.sqrt())
    } else if n == 3 {
        assert_eq!(root, x.cbrt())
    }

    let lo = root.pow(n);
    assert!(lo <= *x);
    assert_eq!(lo.nth_root(n), root);
    assert_eq!((&lo - 1u32).nth_root(n), &root - 1u32);

    let hi = (&root + 1u32).pow(n);
    assert!(hi > *x);
    assert_eq!(hi.nth_root(n), &root + 1u32);
    assert_eq!((&hi - 1u32).nth_root(n), root);
}

fn bench_sqrt(c: &mut Criterion, bits: usize) {
    let x = get_rng().gen_biguint(bits);

    check(&x, 2);
    c.bench_function(&format!("bench_sqrt(bits={})", bits), move |b| {
        b.iter(|| x.sqrt())
    });
}

fn big64_sqrt(b: &mut Criterion) {
    bench_sqrt(b, 64);
}

fn big1k_sqrt(b: &mut Criterion) {
    bench_sqrt(b, 1024);
}

fn big2k_sqrt(b: &mut Criterion) {
    bench_sqrt(b, 2048);
}

fn big4k_sqrt(b: &mut Criterion) {
    bench_sqrt(b, 4096);
}

fn bench_cbrt(c: &mut Criterion, bits: usize) {
    let x = get_rng().gen_biguint(bits);

    check(&x, 3);
    c.bench_function(&format!("bench_cbrt(bits={})", bits), move |b| {
        b.iter(|| x.cbrt())
    });
}

fn big64_cbrt(b: &mut Criterion) {
    bench_cbrt(b, 64);
}

fn big1k_cbrt(b: &mut Criterion) {
    bench_cbrt(b, 1024);
}

fn big2k_cbrt(b: &mut Criterion) {
    bench_cbrt(b, 2048);
}

fn big4k_cbrt(b: &mut Criterion) {
    bench_cbrt(b, 4096);
}

fn bench_nth_root(c: &mut Criterion, bits: usize, n: u32) {
    let x = get_rng().gen_biguint(bits);

    check(&x, n);
    c.bench_function(&format!("bench_{}th_root(bits={})", n, bits), move |b| {
        b.iter(|| x.nth_root(n))
    });
}

fn big64_nth_10(b: &mut Criterion) {
    bench_nth_root(b, 64, 10);
}

fn big1k_nth_10(b: &mut Criterion) {
    bench_nth_root(b, 1024, 10);
}

fn big1k_nth_100(b: &mut Criterion) {
    bench_nth_root(b, 1024, 100);
}

fn big1k_nth_1000(b: &mut Criterion) {
    bench_nth_root(b, 1024, 1000);
}

fn big1k_nth_10000(b: &mut Criterion) {
    bench_nth_root(b, 1024, 10000);
}

fn big2k_nth_10(b: &mut Criterion) {
    bench_nth_root(b, 2048, 10);
}

fn big2k_nth_100(b: &mut Criterion) {
    bench_nth_root(b, 2048, 100);
}

fn big2k_nth_1000(b: &mut Criterion) {
    bench_nth_root(b, 2048, 1000);
}

fn big2k_nth_10000(b: &mut Criterion) {
    bench_nth_root(b, 2048, 10000);
}

fn big4k_nth_10(b: &mut Criterion) {
    bench_nth_root(b, 4096, 10);
}

fn big4k_nth_100(b: &mut Criterion) {
    bench_nth_root(b, 4096, 100);
}

fn big4k_nth_1000(b: &mut Criterion) {
    bench_nth_root(b, 4096, 1000);
}

fn big4k_nth_10000(b: &mut Criterion) {
    bench_nth_root(b, 4096, 10000);
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets =
        big64_sqrt,
        big1k_sqrt,
        big2k_sqrt,
        big4k_sqrt,
        big64_cbrt,
        big1k_cbrt,
        big2k_cbrt,
        big4k_cbrt,
        big64_nth_10,
        big1k_nth_10,
        big1k_nth_100,
        big1k_nth_1000,
        big1k_nth_10000,
        big2k_nth_10,
        big2k_nth_100,
        big2k_nth_1000,
        big2k_nth_10000,
        big4k_nth_10,
        big4k_nth_100,
        big4k_nth_1000,
        big4k_nth_10000,
}
