use criterion::{criterion_group, criterion_main, Criterion};
use fast_paillier::EncryptionKey;
use rug::Integer;

fn encryption(c: &mut Criterion) {
    let ek = EncryptionKey::sample_112();

    c.bench_function("encryption", |b| {
        b.iter(|| {
            let m = Integer::from(10);
            let mut rng = rand_dev::DevRng::new();
            let _ = ek.encrypt_with_random(&mut rng, &m).unwrap();
        })
    });
}

criterion_group!(benches, encryption);
criterion_main!(benches);
