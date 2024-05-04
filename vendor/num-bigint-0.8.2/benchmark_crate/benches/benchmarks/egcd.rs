use criterion::Criterion;
use num_bigint::{ExtendedGcd, RandBigInt};
use rand::{rngs::StdRng, SeedableRng};

fn get_rng() -> StdRng {
    let mut seed = [0; 32];
    for i in 1..32 {
        seed[usize::from(i)] = i;
    }
    SeedableRng::from_seed(seed)
}

fn bench(c: &mut Criterion, name: String, bits: usize) {
    let mut rng = get_rng();
    let x = rng.gen_biguint(bits);
    let y = rng.gen_biguint(bits);

    c.bench_function(&name, move |b| b.iter(|| (&x).extended_gcd(&y)));
}

fn egcd_0064(c: &mut Criterion) {
    bench(c, "egcd_0064".to_string(), 64);
}

fn egcd_0256(c: &mut Criterion) {
    bench(c, "egcd_0256".to_string(), 256);
}

fn egcd_1024(c: &mut Criterion) {
    bench(c, "egcd_1024".to_string(), 1024);
}

fn egcd_4096(c: &mut Criterion) {
    bench(c, "egcd_4096".to_string(), 4096);
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets =
        egcd_0064,
        egcd_0256,
        egcd_1024,
        egcd_4096,
}
