use criterion::Criterion;
use num_bigint::prime;
use num_bigint::BigUint;
use num_bigint::RandPrime;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

const NUM: &'static str = "203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123";

fn probably_prime_0(c: &mut Criterion) {
    let x = BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap();

    c.bench_function("probably_prime_0", move |b| {
        b.iter(|| prime::probably_prime(&x, 0))
    });
}

fn probably_prime_1(c: &mut Criterion) {
    let x = BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap();

    c.bench_function("probably_prime_1", move |b| {
        b.iter(|| prime::probably_prime(&x, 1))
    });
}

fn probably_prime_5(c: &mut Criterion) {
    let x = BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap();

    c.bench_function("probably_prime_5", move |b| {
        b.iter(|| prime::probably_prime(&x, 5))
    });
}

fn probably_prime_10(c: &mut Criterion) {
    let x = BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap();

    c.bench_function("probably_prime_10", move |b| {
        b.iter(|| prime::probably_prime(&x, 10))
    });
}

fn probably_prime_20(c: &mut Criterion) {
    let x = BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap();

    c.bench_function("probably_prime_20", move |b| {
        b.iter(|| prime::probably_prime(&x, 20))
    });
}

fn bench_prime_lucas(c: &mut Criterion) {
    let x = BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap();

    c.bench_function("bench_prime_lucas", move |b| {
        b.iter(|| prime::probably_prime_lucas(&x))
    });
}

fn bench_prime_miller_rabin(c: &mut Criterion) {
    let x = BigUint::parse_bytes(NUM.as_bytes(), 10).unwrap();

    c.bench_function("bench_prime_miller_rabin", move |b| {
        b.iter(|| prime::probably_prime_miller_rabin(&x, 1, true))
    });
}

fn bench_gen_prime(c: &mut Criterion) {
    c.bench_function("bench_gen_prime", move |b| {
        let rng = &mut ChaChaRng::from_seed([0u8; 32]);
        b.iter(|| rng.gen_prime(1024))
    });
}

criterion_group! {
    name = benches;
    config = { let c = Criterion::default(); c.sample_size(5) };
    targets =
        probably_prime_0,
        probably_prime_1,
        probably_prime_5,
        probably_prime_10,
        probably_prime_20,
        bench_prime_lucas,
        bench_prime_miller_rabin,
        bench_gen_prime,
}
