use fast_paillier::{EncryptionKey};
use rug::Integer;
use bencher::{benchmark_group, benchmark_main, Bencher};

fn encryption(b: &mut Bencher) {;
    let ek = EncryptionKey::sample_112();
    
    b.iter(|| {
        let m = Integer::from(10);
        let mut rng = rand_dev::DevRng::new();
        let _ = ek.encrypt_with_random(&mut rng, &m).unwrap();
    });
}

benchmark_group!(benches, encryption);
benchmark_main!(benches);
