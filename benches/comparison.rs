use fast_paillier::utils;
use fast_paillier::AnyEncryptionKey;
use rug::Integer;

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
        let x = ek
            .n()
            .clone()
            .random_below(&mut fast_paillier::utils::external_rand(&mut rng))
            - ek.half_n();
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
        let x = ek
            .n()
            .clone()
            .random_below(&mut fast_paillier::utils::external_rand(&mut fresh_rng))
            - ek.half_n();
        x
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
        let scalar = ek
            .nn()
            .random_below_ref(&mut utils::external_rand(&mut rng))
            .into();
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

/// Old implementation of safe primes
pub fn naive_safe_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Integer {
    use rug::{integer::IsPrime, Assign};
    let mut rng = utils::external_rand(rng);
    let mut x = Integer::new();
    loop {
        x.assign(Integer::random_bits(bits - 1, &mut rng));
        x.set_bit(bits - 2, true);
        x.next_prime_mut();
        x <<= 1;
        x += 1;

        if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
            return x;
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

fn rng_covertion(c: &mut criterion::Criterion) {
    let mut rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("PRNG convertion");

    group.bench_function("into GMP", |b| {
        b.iter(|| {
            let mut gmp_rng = fast_paillier::utils::external_rand(std::hint::black_box(&mut rng));
            let dyn_rng: &mut dyn rug::rand::MutRandState = &mut gmp_rng;
            let _ = std::hint::black_box(dyn_rng);
        })
    });
}

criterion::criterion_group!(
    benches,
    encryption,
    decryption,
    omul,
    safe_primes,
    rng_covertion
);
criterion::criterion_main!(benches);

fn convert_integer_to_unknown_order(x: &Integer) -> libpaillier::unknown_order::BigNumber {
    let bytes = x.to_digits::<u8>(rug::integer::Order::Msf);
    libpaillier::unknown_order::BigNumber::from_slice(&bytes)
}
