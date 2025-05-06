use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use fast_paillier::DecryptionKey;
use std::time::Duration;

fn keygen(c: &mut Criterion) {
    let n_size = 2048;
    let a_size = 448;
    let mut rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("keygen");
    group
        .sample_size(100)
        .measurement_time(Duration::from_secs(3077));
        // .warm_up_time(Duration::from_secs(3));

    group.bench_function(BenchmarkId::new("keygen", "2048bit"), |b| {
        b.iter(|| {
            let _ = DecryptionKey::generate(&mut rng, n_size, a_size).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, keygen);
criterion_main!(benches);
