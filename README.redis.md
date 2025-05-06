# Redis Integration for Fast Paillier

This extension provides Redis caching for precomputed tables in the Fast Paillier library. It allows you to store computation-intensive precomputation tables in Redis to avoid recalculating them when the same parameters are used multiple times.

## Features

- Automatic caching of precomputed tables in Redis
- Transparent fallback to local computation when Redis is unavailable
- Hash-based key generation to efficiently identify tables
- Docker setup for easy Redis deployment

## Setup

### 1. Enable the Redis feature

Add the `redis-cache` feature to your Cargo.toml dependencies:

```toml
[dependencies]
fast-paillier = { version = "0.1.0", features = ["redis-cache"] }
```

### 2. Start Redis

You can use the provided Docker setup to run a Redis instance:

```bash
# Build and start Redis
docker-compose up -d

# Check if Redis is running
docker ps
```

## Usage

Once the Redis feature is enabled, you can use the Redis-enabled precompute table constructors:

```rust
use fast_paillier::{PrecomputeTable, DecryptionKey};

fn main() {
    let dk = DecryptionKey::sample_128();
    let ek = dk.encryption_key();
    let base = ek.h_pow_n();
    let block_size = 5;
    let pow_size = ek.a_size() as usize;
    let modulo = ek.nn().clone();
    
    // Connect to Redis and use caching (provide Redis URL)
    let redis_host = "redis://127.0.0.1/";
    let precompute = PrecomputeTable::new(
        base.clone(), 
        block_size, 
        pow_size, 
        modulo.clone(), 
        Some(redis_host)
    );
    
    // Use the precomputed table
    let m = Integer::from(10);
    let mut rng = rand_dev::DevRng::new();
    let c = ek.encrypt_with_precompute_table(&mut rng, &precompute, &m).unwrap();
    
    // The second time you create the same table, it will be loaded from Redis
    let precompute2 = PrecomputeTable::new(
        base.clone(), 
        block_size, 
        pow_size, 
        modulo.clone(), 
        Some(redis_host)
    );
    
    // You can also use the dynamic programming version
    let precompute_dp = PrecomputeTable::new_dp(
        base.clone(), 
        block_size, 
        pow_size, 
        modulo.clone(), 
        Some(redis_host)
    );
}
```

## Key Generation

Table keys in Redis are generated using SHA-256 hashes of the input parameters to ensure uniqueness and efficiency. The format is:

```
precompute_table:{SHA-256 hex encoded hash of g + block_size + pow_size + modulo}
```

## Troubleshooting

1. If Redis connection fails, the library will fall back to local computation without raising an error.
2. To check if Redis is properly storing tables, you can use the Redis CLI:

```bash
docker exec -it fast_paillier_redis redis-cli keys "precompute_table:*"
```

## Configuration

The Redis configuration can be modified in the `redis.conf` file. Key settings include:

- `maxmemory`: Maximum memory Redis can use (default: 512MB)
- `maxmemory-policy`: Eviction policy when memory limit is reached (default: allkeys-lru) 
