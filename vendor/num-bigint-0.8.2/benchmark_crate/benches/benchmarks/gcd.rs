use criterion::Criterion;
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::Zero;
use rand::{rngs::StdRng, SeedableRng};

fn get_rng() -> StdRng {
    let mut seed = [0; 32];
    for i in 1..32 {
        seed[usize::from(i)] = i;
    }
    SeedableRng::from_seed(seed)
}

fn bench(c: &mut Criterion, name: String, bits: usize, gcd: fn(&BigUint, &BigUint) -> BigUint) {
    let mut rng = get_rng();
    let x = rng.gen_biguint(bits);
    let y = rng.gen_biguint(bits);

    assert_eq!(euclid(&x, &y), x.gcd(&y));

    c.bench_function(&name, move |b| b.iter(|| gcd(&x, &y)));
}

fn euclid(x: &BigUint, y: &BigUint) -> BigUint {
    // Use Euclid's algorithm
    let mut m = x.clone();
    let mut n = y.clone();
    while !m.is_zero() {
        let temp = m;
        m = n % &temp;
        n = temp;
    }
    return n;
}

fn gcd_euclid_0064(c: &mut Criterion) {
    bench(c, "gcd_euclid_0064".to_string(), 64, euclid);
}

fn gcd_euclid_0256(c: &mut Criterion) {
    bench(c, "gcd_euclid_0256".to_string(), 256, euclid);
}

fn gcd_euclid_1024(c: &mut Criterion) {
    bench(c, "gcd_euclid_1024".to_string(), 1024, euclid);
}

fn gcd_euclid_4096(c: &mut Criterion) {
    bench(c, "gcd_euclid_4096".to_string(), 4096, euclid);
}

// Integer for BigUint now uses Lehmer for gcd

fn gcd_lehmer_0064(c: &mut Criterion) {
    bench(c, "gcd_lehmer_0064".to_string(), 64, BigUint::gcd);
}

fn gcd_lehmer_0256(c: &mut Criterion) {
    bench(c, "gcd_lehmer_0256".to_string(), 256, BigUint::gcd);
}

fn gcd_lehmer_1024(c: &mut Criterion) {
    bench(c, "gcd_lehmer_1024".to_string(), 1024, BigUint::gcd);
}

fn gcd_lehmer_4096(c: &mut Criterion) {
    bench(c, "gcd_lehmer_4096".to_string(), 4096, BigUint::gcd);
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets =
        gcd_euclid_0064,
        gcd_euclid_0256,
        gcd_euclid_1024,
        gcd_euclid_4096,
        gcd_lehmer_0064,
        gcd_lehmer_0256,
        gcd_lehmer_1024,
        gcd_lehmer_4096,
}
