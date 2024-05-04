use criterion::Criterion;
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{FromPrimitive, Num, One, Pow, Zero};
use rand::{rngs::StdRng, SeedableRng};
use std::mem::replace;

fn get_rng() -> StdRng {
    let mut seed = [0; 32];
    for i in 1..32 {
        seed[usize::from(i)] = i;
    }
    SeedableRng::from_seed(seed)
}

fn multiply_bench(c: &mut Criterion, name: String, xbits: usize, ybits: usize) {
    let mut rng = get_rng();
    let x = rng.gen_bigint(xbits);
    let y = rng.gen_bigint(ybits);

    c.bench_function(&name, move |b| b.iter(|| &x * &y));
}

fn divide_bench(c: &mut Criterion, name: String, xbits: usize, ybits: usize) {
    let mut rng = get_rng();
    let x = rng.gen_bigint(xbits);
    let y = rng.gen_bigint(ybits);

    c.bench_function(&name, move |b| b.iter(|| &x / &y));
}

fn factorial(n: usize) -> BigUint {
    let mut f: BigUint = One::one();
    for i in 1..(n + 1) {
        let bu: BigUint = FromPrimitive::from_usize(i).unwrap();
        f = f * bu;
    }
    f
}

/// Compute Fibonacci numbers
fn fib(n: usize) -> BigUint {
    let mut f0: BigUint = Zero::zero();
    let mut f1: BigUint = One::one();
    for _ in 0..n {
        let f2 = f0 + &f1;
        f0 = replace(&mut f1, f2);
    }
    f0
}

/// Compute Fibonacci numbers with two ops per iteration
/// (add and subtract, like issue #200)
fn fib2(n: usize) -> BigUint {
    let mut f0: BigUint = Zero::zero();
    let mut f1: BigUint = One::one();
    for _ in 0..n {
        f1 = f1 + &f0;
        f0 = &f1 - f0;
    }
    f0
}

fn multiply_0(c: &mut Criterion) {
    multiply_bench(c, "multiply_0".to_string(), 1 << 8, 1 << 8);
}

fn multiply_1(c: &mut Criterion) {
    multiply_bench(c, "multiply_1".to_string(), 1 << 8, 1 << 16);
}

fn multiply_2(c: &mut Criterion) {
    multiply_bench(c, "multiply_2".to_string(), 1 << 16, 1 << 16);
}

fn multiply_3(c: &mut Criterion) {
    multiply_bench(c, "multiply_3".to_string(), 1 << 16, 1 << 17);
}

fn divide_0(c: &mut Criterion) {
    divide_bench(c, "divide_0".to_string(), 1 << 8, 1 << 6);
}

fn divide_1(c: &mut Criterion) {
    divide_bench(c, "divide_1".to_string(), 1 << 12, 1 << 8);
}

fn divide_2(c: &mut Criterion) {
    divide_bench(c, "divide_2".to_string(), 1 << 16, 1 << 12);
}

fn factorial_100(c: &mut Criterion) {
    c.bench_function("factorial_100", move |b| b.iter(|| factorial(100)));
}

fn fib_100(c: &mut Criterion) {
    c.bench_function("fib_100", move |b| b.iter(|| fib(100)));
}

fn fib_1000(c: &mut Criterion) {
    c.bench_function("fib_1000", move |b| b.iter(|| fib(1000)));
}

fn fib_10000(c: &mut Criterion) {
    c.bench_function("fib_10000", move |b| b.iter(|| fib(10000)));
}

fn fib2_100(c: &mut Criterion) {
    c.bench_function("fib2_100", move |b| b.iter(|| fib2(100)));
}

fn fib2_1000(c: &mut Criterion) {
    c.bench_function("fib2_1000", move |b| b.iter(|| fib2(1000)));
}

fn fib2_10000(c: &mut Criterion) {
    c.bench_function("fib2_10000", move |b| b.iter(|| fib2(10000)));
}

fn fac_to_string(c: &mut Criterion) {
    let fac = factorial(100);
    c.bench_function("fac_to_string", move |b| b.iter(|| fac.to_string()));
}

fn fib_to_string(c: &mut Criterion) {
    let fib = fib(100);
    c.bench_function("fib_to_string", move |b| b.iter(|| fib.to_string()));
}

fn to_str_radix_bench(c: &mut Criterion, radix: u32) {
    let mut rng = get_rng();
    let x = rng.gen_bigint(1009);
    c.bench_function(&format!("to_str_radix_bench_{:?}", radix), move |b| {
        b.iter(|| x.to_str_radix(radix))
    });
}

fn to_str_radix_02(c: &mut Criterion) {
    to_str_radix_bench(c, 2);
}

fn to_str_radix_08(c: &mut Criterion) {
    to_str_radix_bench(c, 8);
}

fn to_str_radix_10(c: &mut Criterion) {
    to_str_radix_bench(c, 10);
}

fn to_str_radix_16(c: &mut Criterion) {
    to_str_radix_bench(c, 16);
}

fn to_str_radix_36(c: &mut Criterion) {
    to_str_radix_bench(c, 36);
}

fn from_str_radix_bench(c: &mut Criterion, radix: u32) {
    let mut rng = get_rng();
    let x = rng.gen_bigint(1009);
    let s = x.to_str_radix(radix);
    assert_eq!(x, BigInt::from_str_radix(&s, radix).unwrap());

    c.bench_function(&format!("from_str_radix_bench{:?}", radix), move |b| {
        b.iter(|| BigInt::from_str_radix(&s, radix))
    });
}

fn from_str_radix_02(c: &mut Criterion) {
    from_str_radix_bench(c, 2);
}

fn from_str_radix_08(c: &mut Criterion) {
    from_str_radix_bench(c, 8);
}

fn from_str_radix_10(c: &mut Criterion) {
    from_str_radix_bench(c, 10);
}

fn from_str_radix_16(c: &mut Criterion) {
    from_str_radix_bench(c, 16);
}

fn from_str_radix_36(c: &mut Criterion) {
    from_str_radix_bench(c, 36);
}

fn rand_bench(c: &mut Criterion, bits: usize) {
    let mut rng = get_rng();
    c.bench_function(&format!("rand_bench_{:?}", bits), move |b| {
        b.iter(|| rng.gen_bigint(bits))
    });
}

fn rand_64(c: &mut Criterion) {
    rand_bench(c, 1 << 6);
}

fn rand_256(c: &mut Criterion) {
    rand_bench(c, 1 << 8);
}

fn rand_1009(c: &mut Criterion) {
    rand_bench(c, 1009);
}

fn rand_2048(c: &mut Criterion) {
    rand_bench(c, 1 << 11);
}

fn rand_4096(c: &mut Criterion) {
    rand_bench(c, 1 << 12);
}

fn rand_8192(c: &mut Criterion) {
    rand_bench(c, 1 << 13);
}

fn rand_65536(c: &mut Criterion) {
    rand_bench(c, 1 << 16);
}

fn rand_131072(c: &mut Criterion) {
    rand_bench(c, 1 << 17);
}

fn shl(c: &mut Criterion) {
    let n = BigUint::one() << 1000;

    c.bench_function("shl", move |b| {
        b.iter(|| {
            let mut m = n.clone();
            for i in 0..50 {
                m = m << i;
            }
        })
    });
}

fn shr(c: &mut Criterion) {
    let n = BigUint::one() << 2000;

    c.bench_function("shr", move |b| {
        b.iter(|| {
            let mut m = n.clone();
            for i in 0..50 {
                m = m << i;
            }
        })
    });
}

fn hash(c: &mut Criterion) {
    use std::collections::HashSet;
    let mut rng = get_rng();
    let v: Vec<BigInt> = (1000..2000).map(|bits| rng.gen_bigint(bits)).collect();
    c.bench_function("hash", move |b| {
        b.iter(|| {
            let h: HashSet<&BigInt> = v.iter().collect();
            assert_eq!(h.len(), v.len());
        })
    });
}

fn pow_bench(c: &mut Criterion) {
    c.bench_function("pow_bench", move |b| {
        b.iter(|| {
            let upper = 100_usize;
            for i in 2..upper + 1 {
                for j in 2..upper + 1 {
                    let i_big = BigUint::from_usize(i).unwrap();
                    i_big.pow(j);
                }
            }
        })
    });
}

/// This modulus is the prime from the 2048-bit MODP DH group:
/// https://tools.ietf.org/html/rfc3526#section-3
const RFC3526_2048BIT_MODP_GROUP: &'static str =
    "\
     FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1\
     29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD\
     EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245\
     E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED\
     EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D\
     C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F\
     83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D\
     670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B\
     E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9\
     DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510\
     15728E5A_8AACAA68_FFFFFFFF_FFFFFFFF";

fn modpow(c: &mut Criterion) {
    let mut rng = get_rng();
    let base = rng.gen_biguint(2048);
    let e = rng.gen_biguint(2048);
    let m = BigUint::from_str_radix(RFC3526_2048BIT_MODP_GROUP, 16).unwrap();

    c.bench_function("modpow", move |b| b.iter(|| base.modpow(&e, &m)));
}

fn modpow_even(c: &mut Criterion) {
    let mut rng = get_rng();
    let base = rng.gen_biguint(2048);
    let e = rng.gen_biguint(2048);
    // Make the modulus even, so monty (base-2^32) doesn't apply.
    let m = BigUint::from_str_radix(RFC3526_2048BIT_MODP_GROUP, 16).unwrap() - 1u32;

    c.bench_function("modpow_even", move |b| {
        b.iter(|| base.modpow(&e, &m));
    });
}

fn roots_sqrt(c: &mut Criterion) {
    let mut rng = get_rng();
    let x = rng.gen_biguint(2048);
    c.bench_function("roots_sqrt", move |b| b.iter(|| x.sqrt()));
}

fn roots_cbrt(c: &mut Criterion) {
    let mut rng = get_rng();
    let x = rng.gen_biguint(2048);
    c.bench_function("roots_cbrt", move |b| b.iter(|| x.cbrt()));
}

fn roots_nth_100(c: &mut Criterion) {
    let mut rng = get_rng();
    let x = rng.gen_biguint(2048);
    c.bench_function("roots_nth_100", move |b| b.iter(|| x.nth_root(100)));
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets =
        multiply_0,
        multiply_1,
        multiply_2,
        multiply_3,
        divide_0,
        divide_1,
        divide_2,
        factorial_100,
        fib_100,
        fib_1000,
        fib_10000,
        fib2_100,
        fib2_1000,
        fib2_10000,
        fac_to_string,
        fib_to_string,
        to_str_radix_02,
        to_str_radix_08,
        to_str_radix_10,
        to_str_radix_16,
        to_str_radix_36,
        from_str_radix_02,
        from_str_radix_08,
        from_str_radix_10,
        from_str_radix_16,
        from_str_radix_36,
        rand_64,
        rand_256,
        rand_1009,
        rand_2048,
        rand_4096,
        rand_8192,
        rand_65536,
        rand_131072,
        shl,
        shr,
        hash,
        pow_bench,
        modpow,
        modpow_even,
        roots_sqrt,
        roots_cbrt,
        roots_nth_100,
}
