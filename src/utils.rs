//! Utilities for random sampling, primality checks, coprimality checks and
//! misc helpers, implemented with `malachite` instead of `rug`.

use rand_core::RngCore;
use malachite::Integer;
use malachite_base::num::arithmetic::traits::{Gcd, Parity};
use malachite_base::num::logic::traits::SignificantBits;
use malachite_base::num::basic::traits::{Zero, One};
use malachite_base::num::logic::traits::BitAccess;
mod serde_wrapper;
pub use serde_wrapper::*;
/// Returns `true` iff `x` (taken modulo `n`) is in the multiplicative group
/// `Z*_n` (i.e. `gcd(x, n) == 1`).
#[inline]
pub fn in_mult_group(x: &Integer, n: &Integer) -> bool {
    x >= &Integer::ZERO && in_mult_group_abs(x, n)
}

/// CrtExp is a struct that contains the CRT exponentiation parameters.
/// It is used to speed up the CRT exponentiation.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CrtExp {
    #[serde(with = "serializable_bigint")]
    n: Integer,
    #[serde(with = "serializable_bigint")]
    n1: Integer,
    #[serde(with = "serializable_bigint")]
    phi_n1: Integer,
    #[serde(with = "serializable_bigint")]
    n2: Integer,
    #[serde(with = "serializable_bigint")]
    phi_n2: Integer,
    #[serde(with = "serializable_bigint")]
    beta: Integer,
}

/// Same as [`in_mult_group`] but `x` is treated as an unsigned value (absolute
/// value is taken).
#[inline]
pub fn in_mult_group_abs(x: &Integer, n: &Integer) -> bool {
    x
        .unsigned_abs_ref()
        .gcd(n.unsigned_abs_ref())
        .significant_bits()
        == 1 // gcd == 1
}

/// Generate a random positive `Integer` strictly less than `n`.
fn random_below(rng: &mut impl RngCore, n: &Integer) -> Integer {
    let bits = n.significant_bits();
    loop {
        let candidate = sample_with_size(rng, bits as u32) % n;
        if candidate > 0 {
            return candidate;
        }
    }
}

/// Samples a random element from `Z*_n` (uniform rejection sampling).
pub fn sample_in_mult_group(rng: &mut impl RngCore, n: &Integer) -> Integer {
    loop {
        let x = random_below(rng, n);
        if in_mult_group(&x, n) {
            return x;
        }
    }
}

/// Returns a random non-negative `Integer` with exactly `bits` significant
/// bits (the top bit is set).
pub fn sample_with_size(rng: &mut impl RngCore, bits: u32) -> Integer {
    debug_assert!(bits > 0);

    // Ensure the highest bit (bits - 1) is set so that the resulting number has exactly
    // `bits` significant bits. Fill the remaining lower bits with random data.
    let mut x = Integer::ZERO;

    // Set the most-significant bit first.
    x.set_bit((bits - 1) as u64);

    // Populate the remaining bits with randomness.
    for i in 0..(bits - 1) {
        if rng.next_u32() & 1 == 1 {
            x.set_bit(i as u64);
        }
    }

    x
}

/// Same as [`sample_with_size`] but forces the result to be odd.
#[inline]
pub fn sample_odd_with_size(rng: &mut impl RngCore, bits: u32) -> Integer {
    let mut x = sample_with_size(rng, bits);
    if x.even() {
        x += &Integer::ONE;
    }
    x
}

/// Very simple (non-cryptographic) primality test: trial division by a list of
/// small primes and a deterministic Miller-Rabin for 64-bit bases.  **Not
/// suitable for production cryptography**, but good enough for unit tests.
pub fn is_prime(n: &Integer) -> bool {
    // handle small numbers quickly
    if *n <= 1u32 {
        return false;
    }
    if n == &Integer::from(2u32) {
        return true;
    }
    if n.even() {
        return false;
    }

    const SMALL_PRIMES: &[u32] = &[
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
        401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
        509, 521, 523, 541,
    ];

    for &p in SMALL_PRIMES {
        if n == &Integer::from(p) {
            return true;
        }
        let rem = n % &Integer::from(p);
        if rem == Integer::ZERO {
            return false;
        }
    }

    // simple deterministic Miller–Rabin bases for 64-bit range; for larger n it
    // is only a probable prime check.
    const MR_BASES: &[u32] = &[2, 3, 5, 7, 11];

    let d = {
        let mut d = n - &Integer::ONE;
        let mut s = 0u32;
        while d.even() {
            d >>= 1u32;
            s += 1;
        }
        (d, s)
    };

    let (d, s) = d;
    'outer: for &a in MR_BASES {
        if Integer::from(a) >= *n {
            continue;
        }
        let mut x = super::integer_ext::mod_pow_int(&Integer::from(a), &d, n);
        if x == Integer::ONE || x == n - &Integer::ONE {
            continue 'outer;
        }
        let mut r = 1;
        while r < s {
            x = (&x * &x) % n;
            if x == n - &Integer::ONE {
                continue 'outer;
            }
            r += 1;
        }
        return false;
    }
    true
}

/// Returns `true` if every pair in `v` is coprime.
pub fn check_coprime(v: &[&Integer]) -> bool {
    for i in 0..v.len() {
        for j in (i + 1)..v.len() {
            if v[i]
                .unsigned_abs_ref()
                .gcd(v[j].unsigned_abs_ref())
                .significant_bits()
                != 1
            {
                return false;
            }
        }
    }
    true
}

/// Generates a (probable) safe prime of size `bits`.
pub fn generate_safe_prime(rng: &mut impl RngCore, bits: u32) -> Integer {
    loop {
        let q = sample_odd_with_size(rng, bits - 1);
        if !is_prime(&q) {
            continue;
        }
        let p = Integer::from(2u32) * &q + &Integer::ONE;
        if is_prime(&p) {
            return p;
        }
    }
}

/// Same as [`generate_safe_prime`] but allows specifying a dummy sieve parameter
/// for compatibility. The parameter is ignored in this implementation.
#[inline]
pub fn sieve_generate_safe_primes(rng: &mut impl RngCore, bits: u32, _amount: usize) -> Integer {
    generate_safe_prime(rng, bits)
}


