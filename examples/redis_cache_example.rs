use fast_paillier::DecryptionKey;
use fast_paillier::precomputed_table::PrecomputeTable;
use fast_paillier::AnyEncryptionKey;
use rug::Integer;
use std::time::Instant;

fn main() {
    // Check if redis-cache feature is enabled
    #[cfg(not(feature = "redis-cache"))]
    {
        println!("This example requires the 'redis-cache' feature.");
        println!("Run with: cargo run --example redis_cache_example --features redis-cache");
        return;
    }

    #[cfg(feature = "redis-cache")]
    {
        // Redis connection URL - modify as needed
        let redis_host = "redis://127.0.0.1/";
        
        println!("Fast Paillier with Redis Cache Example");
        println!("-------------------------------------");
        
        // Create sample keys
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 10;
        let pow_size = 512;
        let modulo = ek.nn().clone();
        
        // First run - should compute and store in Redis
        println!("First run (computing and caching):");
        let start = Instant::now();
        let _precompute = PrecomputeTable::new_dp(
            base.clone(), 
            block_size, 
            pow_size, 
            modulo.clone(), 
            Some(redis_host)
        );
        let duration = start.elapsed();
        println!("  Time: {:?}", duration);
        
        // Second run - should fetch from Redis
        println!("Second run (fetching from cache):");
        let start = Instant::now();
        let precompute = PrecomputeTable::new_dp(
            base.clone(), 
            block_size, 
            pow_size, 
            modulo.clone(), 
            Some(redis_host)
        );
        let duration = start.elapsed();
        println!("  Time: {:?}", duration);
        
        // Use the table for encryption
        println!("Testing encryption with cached table:");
        let m = Integer::from(42);
        let mut rng = rand_dev::DevRng::new();
        let start = Instant::now();
        let c = ek
            .encrypt_with_precompute_table(&mut rng, &precompute, &m)
            .unwrap();
        let duration = start.elapsed();
        println!("  Encryption time: {:?}", duration);
        
        // Test decryption
        let start = Instant::now();
        let recovered_m = dk.decrypt(&c).unwrap();
        let duration = start.elapsed();
        println!("  Decryption time: {:?}", duration);
        println!("  Original: {}, Recovered: {}", m, recovered_m);
        
        // Try with dynamic programming version
        println!("Testing with DP algorithm:");
        let start = Instant::now();
        let _precompute_dp = PrecomputeTable::new_dp(
            base.clone(), 
            block_size, 
            pow_size, 
            modulo.clone(), 
            Some(redis_host)
        );
        let duration = start.elapsed();
        println!("  Time: {:?}", duration);
        
        // Print table statistics
        println!("Table statistics:");
        println!("  Size in bytes: {}", precompute.size_in_bytes());
        println!("  Block size: {}", precompute.block_size());
        println!("  Power size: {}", precompute.pow_size());
    }
} 
