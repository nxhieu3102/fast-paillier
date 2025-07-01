use fast_paillier::utils;
use fast_paillier::AnyEncryptionKey;
use malachite::Integer;
use malachite_base::num::logic::traits::SignificantBits;

fn encryption(c: &mut criterion::Criterion) {
    let mut rng = rand_dev::DevRng::new();

    let dk: fast_paillier::DecryptionKey = fast_paillier::DecryptionKey::sample_128();
    let ek = dk.encryption_key();
    let table = fast_paillier::precomputed_table::PrecomputeTable::new_dp(
        ek.h_pow_n().clone(),
        15,
        512,
        ek.nn().clone(),
    );
    let mut group = c.benchmark_group("Encrypt");

    let mut generate_inputs = || {
        let bits = ek.n_size();
        // Generate a random plaintext uniformly in (-N/2, N/2)
        let x_unsigned = utils::sample_with_size(&mut rng, bits) % ek.n();
        let x = x_unsigned - ek.half_n();
        let nonce = fast_paillier::utils::sample_in_mult_group(&mut rng, ek.n());
        (x, nonce)
    };

    group.bench_function("Encrypt", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(x, nonce)| ek.encrypt_with(&x, &nonce).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });

    let mut fresh_rng = rand_dev::DevRng::new();
    let mut precompute_inputs = || {
        let bits = ek.n_size();
        let x_unsigned = utils::sample_with_size(&mut fresh_rng, bits) % ek.n();
        x_unsigned - ek.half_n()
    };

    group.bench_function("Encrypt with precompute table", |b| {
        let mut bench_rng = rand_dev::DevRng::new();
        b.iter_batched(
            &mut precompute_inputs,
            |x| {
                ek.encrypt_with_precompute_table(&mut bench_rng, &table, &x)
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn decryption(c: &mut criterion::Criterion) {
    let mut rng = rand_dev::DevRng::new();
    let dk = fast_paillier::DecryptionKey::sample_128();
    let ek = dk.encryption_key();

    let mut group = c.benchmark_group("Decrypt");

    let mut generate_inputs = || utils::sample_in_mult_group(&mut rng, ek.nn());

    group.bench_function("Decrypt", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |enc_x| dk.decrypt(&enc_x).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn omul(c: &mut criterion::Criterion) {
    let mut rng = rand_dev::DevRng::new();

    let dk = fast_paillier::DecryptionKey::sample_128();
    let ek = dk.encryption_key();

    let mut group = c.benchmark_group("OMul");

    let mut generate_inputs = || {
        let scalar_bits = ek.nn().significant_bits() as u32;
        let scalar = utils::sample_with_size(&mut rng, scalar_bits) % ek.nn();
        let enc_x = utils::sample_in_mult_group(&mut rng, ek.nn());
        (scalar, enc_x)
    };

    group.bench_function("with CRT", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(scalar, enc_x)| dk.omul(&scalar, &enc_x).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
    group.bench_function("without CRT", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(scalar, enc_x)| ek.omul(&scalar, &enc_x).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

/// Naive safe-prime generation using utilities built on `malachite`.
/// This mirrors the older `rug` implementation but relies on the portable
/// helpers from `fast_paillier::utils`.
pub fn naive_safe_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Integer {
    loop {
        // Generate an odd candidate `q` with `bits-1` bits.
        let q = utils::sample_odd_with_size(rng, bits - 1);

        if !utils::is_prime(&q) {
            continue;
        }

        // p = 2q + 1 should also be prime.
        let p = Integer::from(2u32) * &q + Integer::from(1u32);
        if utils::is_prime(&p) {
            return p;
        }
    }
}

fn safe_primes(c: &mut criterion::Criterion) {
    let rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("Safe primes");
    for (bits, sample_size) in [(512, 200), (1024, 10), (1536, 10)] {
        let id = |s| format!("{}/{}", bits, s);
        group.sample_size(sample_size);

        group.bench_function(id("Original"), |b| {
            b.iter(|| naive_safe_prime(&mut rng.clone(), bits))
        });
        group.bench_function(id("Current"), |b| {
            b.iter(|| utils::generate_safe_prime(&mut rng.clone(), bits))
        });
        group.bench_function(id("Trial with sieve of 120 primes"), |b| {
            b.iter(|| utils::sieve_generate_safe_primes(&mut rng.clone(), bits, 120))
        });
        group.bench_function(id("Trial with sieve of 135 primes"), |b| {
            b.iter(|| utils::sieve_generate_safe_primes(&mut rng.clone(), bits, 135))
        });
        group.bench_function(id("Trial with sieve of 150 primes"), |b| {
            b.iter(|| utils::sieve_generate_safe_primes(&mut rng.clone(), bits, 150))
        });
    }
}

criterion::criterion_group!(benches, encryption, decryption, omul, safe_primes);
criterion::criterion_main!(benches);
