use num_bigint::Sign::Plus;
///! Prime implements probabilistic prime checkers.
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use rand::{SeedableRng, StdRng};

use math::jacobi;

lazy_static! {
    static ref BIG_64: BigUint = BigUint::from_u64(64).unwrap();
}

const PRIMES_A: u64 = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 37;
const PRIMES_B: u64 = 29 * 31 * 41 * 43 * 47 * 53;

/// Records the primes < 64.
const PRIME_BIT_MASK: u64 = 1 << 2
    | 1 << 3
    | 1 << 5
    | 1 << 7
    | 1 << 11
    | 1 << 13
    | 1 << 17
    | 1 << 19
    | 1 << 23
    | 1 << 29
    | 1 << 31
    | 1 << 37
    | 1 << 41
    | 1 << 43
    | 1 << 47
    | 1 << 53
    | 1 << 59
    | 1 << 61;

/// ProbablyPrime reports whether x is probably prime,
/// applying the Miller-Rabin test with n pseudorandomly chosen bases
/// as well as a Baillie-PSW test.
//
/// If x is prime, ProbablyPrime returns true.
/// If x is chosen randomly and not prime, ProbablyPrime probably returns false.
/// The probability of returning true for a randomly chosen non-prime is at most ¼ⁿ.
///
/// ProbablyPrime is 100% accurate for inputs less than 2⁶⁴.
/// See Menezes et al., Handbook of Applied Cryptography, 1997, pp. 145-149,
/// and FIPS 186-4 Appendix F for further discussion of the error probabilities.
///
/// ProbablyPrime is not suitable for judging primes that an adversary may
/// have crafted to fool the test.
///
/// This is a port of `ProbablyPrime` from the go std lib.
pub fn probably_prime(x: &BigUint, n: usize) -> bool {
    if x.is_zero() {
        return false;
    }

    if x < &BIG_64 {
        return (PRIME_BIT_MASK & (1 << x.to_u64().unwrap())) != 0;
    }

    if x.is_even() {
        return false;
    }

    let r_a = &(x % PRIMES_A);
    let r_b = &(x % PRIMES_B);

    if (r_a % 3u32).is_zero()
        || (r_a % 5u32).is_zero()
        || (r_a % 7u32).is_zero()
        || (r_a % 11u32).is_zero()
        || (r_a % 13u32).is_zero()
        || (r_a % 17u32).is_zero()
        || (r_a % 19u32).is_zero()
        || (r_a % 23u32).is_zero()
        || (r_a % 37u32).is_zero()
        || (r_b % 29u32).is_zero()
        || (r_b % 31u32).is_zero()
        || (r_b % 41u32).is_zero()
        || (r_b % 43u32).is_zero()
        || (r_b % 47u32).is_zero()
        || (r_b % 53u32).is_zero()
    {
        return false;
    }

    probably_prime_miller_rabin(x, n + 1, true) && probably_prime_lucas(x)
}

/// Reports whether n passes reps rounds of the
/// Miller-Rabin primality test, using pseudo-randomly chosen bases.
/// If `force2` is true, one of the rounds is forced to use base 2.
/// See Handbook of Applied Cryptography, p. 139, Algorithm 4.24.
fn probably_prime_miller_rabin(n: &BigUint, reps: usize, force2: bool) -> bool {
    let nm1 = n - &BigUint::one();
    // determine q, k such that nm1 = q << k
    let k = nm1.trailing_zeros().unwrap();
    let q = &nm1 << k;

    let nm3 = n - BigUint::from_u64(3).unwrap();
    // TODO: seed = n[0]
    let mut rng = StdRng::from_seed([1u8; 32]);

    let mut x: BigUint;
    let mut y: BigUint;
    let mut quotient = BigUint::zero();

    'next: loop {
        for i in 0..reps {
            if i == reps - 1 && force2 {
                x = BigUint::from_u64(2).unwrap();
            } else {
                x = rng.gen_biguint_below(&nm3);
                x += BigUint::from_u64(2).unwrap();
            }

            y = x.modpow(&q, n);
            if y.is_one() || &y == &nm1 {
                continue;
            }

            for _ in 1..k {
                y = y.modpow(&y, n);
                let (q_, y_) = quotient.div_mod_floor(&y);
                quotient = q_;
                y = y_;

                if &y == &nm1 {
                    continue 'next;
                }
                if y.is_one() {
                    return false;
                }
            }
            return false;
        }
        break;
    }

    true
}

// Reports whether n passes the "almost extra strong" Lucas probable prime test,
// using Baillie-OEIS parameter selection. This corresponds to "AESLPSP" on Jacobsen's tables (link below).
// The combination of this test and a Miller-Rabin/Fermat test with base 2 gives a Baillie-PSW test.
//
// References:
//
// Baillie and Wagstaff, "Lucas Pseudoprimes", Mathematics of Computation 35(152),
// October 1980, pp. 1391-1417, especially page 1401.
// http://www.ams.org/journals/mcom/1980-35-152/S0025-5718-1980-0583518-6/S0025-5718-1980-0583518-6.pdf
//
// Grantham, "Frobenius Pseudoprimes", Mathematics of Computation 70(234),
// March 2000, pp. 873-891.
// http://www.ams.org/journals/mcom/2001-70-234/S0025-5718-00-01197-2/S0025-5718-00-01197-2.pdf
//
// Baillie, "Extra strong Lucas pseudoprimes", OEIS A217719, https://oeis.org/A217719.
//
// Jacobsen, "Pseudoprime Statistics, Tables, and Data", http://ntheory.org/pseudoprimes.html.
//
// Nicely, "The Baillie-PSW Primality Test", http://www.trnicely.net/misc/bpsw.html.
// (Note that Nicely's definition of the "extra strong" test gives the wrong Jacobi condition,
// as pointed out by Jacobsen.)
//
// Crandall and Pomerance, Prime Numbers: A Computational Perspective, 2nd ed.
// Springer, 2005.
fn probably_prime_lucas(n: &BigUint) -> bool {
    if n.is_zero() || n.is_one() {
        return false;
    }

    // Two is the only even prime
    if let Some(n) = n.to_u64() {
        if n == 2 {
            return true;
        }
    }

    // Baillie-OEIS "method C" for choosing D, P, Q,
    // as in https://oeis.org/A217719/a217719.txt:
    // try increasing P ≥ 3 such that D = P² - 4 (so Q = 1)
    // until Jacobi(D, n) = -1.
    // The search is expected to succeed for non-square n after just a few trials.
    // After more than expected failures, check whether n is square
    // (which would cause Jacobi(D, n) = 1 for all D not dividing n).
    let mut p = 3;
    let mut d = BigInt::one();
    let n_int = BigInt::from_biguint(Plus, n.clone());

    loop {
        if p > 10000 {
            panic!("internal error: cannot find (D/n) = -1 for {:?}", n)
        }

        d += p * p - 4;
        let j = jacobi(&d, &n_int);
        if j == -1 {
            break;
        }
        if j == 0 {
            // d = p²-4 = (p-2)(p+2).
            // If (d/n) == 0 then d shares a prime factor with n.
            // Since the loop proceeds in increasing p and starts with p-2==1,
            // the shared prime factor must be p+2.
            // If p+2 == n, then n is prime; otherwise p+2 is a proper factor of n.
            if let Some(n_int) = n_int.to_i64() {
                return n_int == p + 2;
            } else {
                return false;
            }
        }

        if p == 40 {
            // We'll never find (d/n) = -1 if n is a square.
            // If n is a non-square we expect to find a d in just a few attempts on average.
            // After 40 attempts, take a moment to check if n is indeed a square.
            if &(&n_int * &n_int).sqrt() == &n_int {
                return false;
            }
        }

        p += 1;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    lazy_static! {
        static ref PRIMES: Vec<&'static str> = vec![
        "2",
        "3",
        "5",
        "7",
        "11",

        "13756265695458089029",
        "13496181268022124907",
        "10953742525620032441",
        "17908251027575790097",

        // https://golang.org/issue/638
        "18699199384836356663",

        "98920366548084643601728869055592650835572950932266967461790948584315647051443",
        "94560208308847015747498523884063394671606671904944666360068158221458669711639",

        // http://primes.utm.edu/lists/small/small3.html
        "449417999055441493994709297093108513015373787049558499205492347871729927573118262811508386655998299074566974373711472560655026288668094291699357843464363003144674940345912431129144354948751003607115263071543163",
        "230975859993204150666423538988557839555560243929065415434980904258310530753006723857139742334640122533598517597674807096648905501653461687601339782814316124971547968912893214002992086353183070342498989426570593",
        "5521712099665906221540423207019333379125265462121169655563495403888449493493629943498064604536961775110765377745550377067893607246020694972959780839151452457728855382113555867743022746090187341871655890805971735385789993",
        "203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123",
        // ECC primes: http://tools.ietf.org/html/draft-ladd-safecurves-02
        "3618502788666131106986593281521497120414687020801267626233049500247285301239",                                                                                  // Curve1174: 2^251-9
        "57896044618658097711785492504343953926634992332820282019728792003956564819949",                                                                                 // Curve25519: 2^255-19
        "9850501549098619803069760025035903451269934817616361666987073351061430442874302652853566563721228910201656997576599",                                           // E-382: 2^382-105
        "42307582002575910332922579714097346549017899709713998034217522897561970639123926132812109468141778230245837569601494931472367",                                 // Curve41417: 2^414-17
        "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", // E-521: 2^521-1
        ];

        static ref COMPOSITES: Vec<&'static str> = vec![
            "0",
            "1",

            "21284175091214687912771199898307297748211672914763848041968395774954376176754",
            "6084766654921918907427900243509372380954290099172559290432744450051395395951",
            "84594350493221918389213352992032324280367711247940675652888030554255915464401",
            "82793403787388584738507275144194252681",

            // Arnault, "Rabin-Miller Primality Test: Composite Numbers Which Pass It",
            // Mathematics of Computation, 64(209) (January 1995), pp. 335-361.
            "1195068768795265792518361315725116351898245581", // strong pseudoprime to prime bases 2 through 29
            // strong pseudoprime to all prime bases up to 200
            "8038374574536394912570796143419421081388376882875581458374889175222974273765333652186502336163960045457915042023603208766569966760987284043965408232928738791850869166857328267761771029389697739470167082304286871099974399765441448453411558724506334092790222752962294149842306881685404326457534018329786111298960644845216191652872597534901",

            // Extra-strong Lucas pseudoprimes. https://oeis.org/A217719
            "989",
            "3239",
            "5777",
            "10877",
            "27971",
            "29681",
            "30739",
            "31631",
            "39059",
            "72389",
            "73919",
            "75077",
            "100127",
            "113573",
            "125249",
            "137549",
            "137801",
            "153931",
            "155819",
            "161027",
            "162133",
            "189419",
            "218321",
            "231703",
            "249331",
            "370229",
            "429479",
            "430127",
            "459191",
            "473891",
            "480689",
            "600059",
            "621781",
            "632249",
            "635627",

            "3673744903",
            "3281593591",
            "2385076987",
            "2738053141",
            "2009621503",
            "1502682721",
            "255866131",
            "117987841",
            "587861",

            "6368689",
            "8725753",
            "80579735209",
            "105919633",
        ];
    }

    #[test]
    fn test_primes() {
        for prime in PRIMES.iter() {
            let p = BigUint::parse_bytes(prime.as_bytes(), 10).unwrap();
            for i in [0, 1, 20].iter() {
                assert!(
                    probably_prime(&p, *i as usize),
                    "{} is a prime ({})",
                    prime,
                    i,
                );
            }
        }
    }

    #[test]
    fn test_composites() {
        for comp in COMPOSITES.iter() {
            let p = BigUint::parse_bytes(comp.as_bytes(), 10).unwrap();
            for i in [0, 1, 20].iter() {
                assert!(
                    !probably_prime(&p, *i as usize),
                    "{} is a composite ({})",
                    comp,
                    i,
                );
            }
        }
    }

    macro_rules! test_pseudo_primes {
        ($name:ident, $cond:expr, $want:expr) => {
            #[test]
            fn $name() {
                let mut i = 3;
                let mut want = $want;
                while i < 100000 {
                    i += 1;
                    let n = BigUint::from_u64(i).unwrap();
                    let pseudo = $cond(&n);
                    if pseudo && (want.is_empty() || i != want[0]) {
                        panic!("cond({}) = true, want false", i);
                    } else if !pseudo && !want.is_empty() && i == want[0] {
                        panic!("cond({}) = false, want true", i);
                    }
                    if !want.is_empty() && i == want[0] {
                        want = want[1..].to_vec();
                    }
                }

                if !want.is_empty() {
                    panic!("forgot to test: {:?}", want);
                }
            }
        };
    }

    test_pseudo_primes!(
        test_probably_prime_miller_rabin,
        |n| probably_prime_miller_rabin(n, 1, true) && !probably_prime_lucas(n),
        vec![
            2047, 3277, 4033, 4681, 8321, 15841, 29341, 42799, 49141, 52633, 65281, 74665, 80581,
            85489, 88357, 90751,
        ]
    );

    test_pseudo_primes!(
        test_probably_prime_lucas,
        |n| !probably_prime_lucas(n) && !probably_prime_miller_rabin(n, 1, true),
        vec![
            989, 3239, 5777, 10877, 27971, 29681, 30739, 31631, 39059, 72389, 73919, 75077,
        ]
    );
}
