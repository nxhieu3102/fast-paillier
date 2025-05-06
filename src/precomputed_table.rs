use rug::{Complete, Integer};
use std::mem;
#[cfg(feature = "redis-cache")]
use {
    bincode::{deserialize, serialize},
    hex::encode,
    redis::{Client, Connection, RedisError},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
};

#[cfg(test)]
use {
    bincode::serialize,
    serde::{Deserialize, Serialize},
};

/// A table for precomputed values to speed up Paillier encryption operations.
/// This table stores modular exponentiations for faster computation of cryptographic operations.
#[cfg_attr(any(feature = "redis-cache", test), derive(Serialize, Deserialize))]
pub struct PrecomputeTable {
    pow_size: usize,
    block_size: usize,
    modulo: Integer,
    table: Vec<Vec<Integer>>,
}

/// Represents errors that can occur during Redis integration operations
#[cfg(feature = "redis-cache")]
#[derive(thiserror::Error, Debug)]
pub enum RedisIntegrationError {
    /// Error that occurs when there's a problem connecting to Redis
    #[error("Failed to connect to Redis: {0}")]
    ConnectionError(#[from] RedisError),

    /// Error that occurs during serialization or deserialization of data
    #[error("Failed to serialize/deserialize data: {0}")]
    SerializationError(#[from] bincode::Error),
}

impl PrecomputeTable {
    fn calculate_table(
        base: &Integer,
        block_size: usize,
        pow_size: usize,
        modulo: &Integer,
    ) -> Vec<Vec<Integer>> {
        let num_blocks = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        let max_block_value = (1 << block_size) - 1;

        // table[i][j] is
        // table[i][j] = [base^(2^(i*block_size))]^j % modulo

        let mut table = vec![vec![Integer::from(1); max_block_value + 1]; num_blocks + 1];

        for i in 0..=num_blocks {
            for j in 0..=max_block_value {
                // tmp1 = 2^(i*block_size) % modulo
                let tmp1 = Integer::from(2)
                    .pow_mod(&Integer::from((i * block_size) as u32), modulo)
                    .unwrap();
                // tmp2 = base^(tmp1) % modulo
                let tmp2: Integer = base.clone().pow_mod(&tmp1, modulo).unwrap();
                // tmp3 = tmp2^j % modulo
                let tmp3: Integer = tmp2
                    .clone()
                    .pow_mod(&Integer::from(j as u32), modulo)
                    .unwrap();
                table[i][j] = tmp3;
            }
        }
        table
    }

    fn calculate_table_dp(
        base: &Integer,
        block_size: usize,
        pow_size: usize,
        modulo: &Integer,
    ) -> Vec<Vec<Integer>> {
        let num_blocks = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        let max_block_value = (1 << block_size) - 1;

        // Initialize table: table[i][j] = (base^(2^(i*block_size)))^j % modulo
        let mut table = vec![vec![Integer::from(0); max_block_value + 1]; num_blocks + 1];

        // Handle j=0 case: any number raised to 0 is 1
        for i in 0..=num_blocks {
            table[i][0] = Integer::from(1);
        }

        // Precompute 2^(i*block_size) % modulo for each i
        let mut pow_2 = vec![Integer::from(1); num_blocks + 1];
        for i in 1..=num_blocks {
            // Compute 2^(i*block_size) = 2^((i-1)*block_size) * 2^block_size
            let prev = &pow_2[i - 1];
            let block_exp = Integer::from(2)
                .pow_mod(&Integer::from(block_size as u32), modulo)
                .unwrap();
            pow_2[i] = (prev * &block_exp).complete().modulo(modulo);
        }

        // Compute table[i][j]
        for i in 0..=num_blocks {
            // Compute tmp2 = base^(2^(i*block_size)) % modulo
            let tmp2: Integer = base.pow_mod_ref(&pow_2[i], modulo).unwrap().into();

            // Compute table[i][j] iteratively for j >= 1
            table[i][1] = tmp2.clone();
            for j in 2..=max_block_value {
                // table[i][j] = table[i][j-1] * tmp2 % modulo
                table[i][j] = (&table[i][j - 1] * &tmp2).complete().modulo(modulo);
            }
        }

        table
    }

    #[cfg(feature = "redis-cache")]
    fn generate_cache_key(
        g: &Integer,
        block_size: usize,
        pow_size: usize,
        modulo: &Integer,
    ) -> String {
        // Generate a unique key based on parameters
        let mut hasher = Sha256::new();
        hasher.update(g.to_string().as_bytes());
        hasher.update(block_size.to_string().as_bytes());
        hasher.update(pow_size.to_string().as_bytes());
        hasher.update(modulo.to_string().as_bytes());

        let result = hasher.finalize();
        format!("precompute_table:{}", encode(result))
    }

    #[cfg(feature = "redis-cache")]
    fn connect_to_redis(host: Option<&str>) -> Result<Option<Connection>, RedisIntegrationError> {
        if let Some(host) = host {
            match Client::open(host) {
                Ok(client) => match client.get_connection() {
                    Ok(conn) => Ok(Some(conn)),
                    Err(err) => Err(RedisIntegrationError::ConnectionError(err)),
                },
                Err(err) => Err(RedisIntegrationError::ConnectionError(err)),
            }
        } else {
            Ok(None)
        }
    }

    #[cfg(feature = "redis-cache")]
    fn get_from_cache(
        conn: &mut Connection,
        key: &str,
    ) -> Result<Option<Self>, RedisIntegrationError> {
        let exists: bool = redis::cmd("EXISTS").arg(key).query(conn)?;
        if !exists {
            return Ok(None);
        }

        let data: Vec<u8> = redis::cmd("GET").arg(key).query(conn)?;
        let table: Self = deserialize(&data)?;
        Ok(Some(table))
    }

    #[cfg(feature = "redis-cache")]
    fn store_in_cache(
        conn: &mut Connection,
        key: &str,
        table: &Self,
    ) -> Result<(), RedisIntegrationError> {
        let data = serialize(table)?;
        println!("Storing in cache: {}", key.len());
        println!("Data: {:?}", data.len());
        redis::cmd("SET").arg(key).arg(data).execute(conn);
        Ok(())
    }

    /// Creates a new precomputed table using the standard calculation method.
    ///
    /// # Arguments
    /// * `g` - The base integer for exponentiation
    /// * `block_size` - Size of each block in bits
    /// * `pow_size` - Maximum power size in bits
    /// * `modulo` - The modulus for all operations
    /// * `redis_host` - Optional Redis host URL (e.g., "redis://127.0.0.1/")
    #[cfg(feature = "redis-cache")]
    pub fn new(
        g: Integer,
        block_size: usize,
        pow_size: usize,
        modulo: Integer,
        redis_host: Option<&str>,
    ) -> Self {
        // Try to connect to Redis if host is provided
        let mut conn = Self::connect_to_redis(redis_host).unwrap_or(None);

        // If connected to Redis, try to get the table from cache
        if let Some(ref mut conn) = conn {
            let cache_key = Self::generate_cache_key(&g, block_size, pow_size, &modulo);
            if let Ok(Some(table)) = Self::get_from_cache(conn, &cache_key) {
                return table;
            }

            // If not found in cache, calculate and store
            let table = PrecomputeTable {
                pow_size,
                block_size,
                modulo: modulo.clone(),
                table: Self::calculate_table(&g, block_size, pow_size, &modulo),
            };
            println!("Table size: {}", table.size_in_bytes());
            println!("block_size: {:?}", block_size);
            println!("pow_size: {:?}", pow_size);
            // Store the calculated table in Redis
            let _ = Self::store_in_cache(conn, &cache_key, &table);
            return table;
        }

        // Fall back to calculating the table if Redis is not available
        let table = Self::calculate_table(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            pow_size,
            block_size,
            modulo,
            table,
        }
    }

    /// Creates a new precomputed table using dynamic programming for calculation.
    ///
    /// # Arguments
    /// * `g` - The base integer for exponentiation
    /// * `block_size` - Size of each block in bits
    /// * `pow_size` - Maximum power size in bits
    /// * `modulo` - The modulus for all operations
    /// * `redis_host` - Optional Redis host URL (e.g., "redis://127.0.0.1/")
    #[cfg(feature = "redis-cache")]
    pub fn new_dp(
        g: Integer,
        block_size: usize,
        pow_size: usize,
        modulo: Integer,
        redis_host: Option<&str>,
    ) -> Self {
        // Try to connect to Redis if host is provided
        let mut conn = Self::connect_to_redis(redis_host).unwrap_or(None);

        // If connected to Redis, try to get the table from cache
        if let Some(ref mut conn) = conn {
            let cache_key = Self::generate_cache_key(&g, block_size, pow_size, &modulo);
            if let Ok(Some(table)) = Self::get_from_cache(conn, &cache_key) {
                return table;
            }

            // If not found in cache, calculate and store
            let table = PrecomputeTable {
                pow_size,
                block_size,
                modulo: modulo.clone(),
                table: Self::calculate_table_dp(&g, block_size, pow_size, &modulo),
            };

            println!("Table size: {}", table.size_in_bytes());
            println!("block_size: {:?}", block_size);
            println!("pow_size: {:?}", pow_size);
            // Store the calculated table in Redis
            let _ = Self::store_in_cache(conn, &cache_key, &table);
            return table;
        }

        // Fall back to calculating the table if Redis is not available
        let table = Self::calculate_table_dp(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            pow_size,
            block_size,
            modulo,
            table,
        }
    }

    /// Creates a new precomputed table using the standard calculation method.
    ///
    /// # Arguments
    /// * `g` - The base integer for exponentiation
    /// * `block_size` - Size of each block in bits
    /// * `pow_size` - Maximum power size in bits
    /// * `modulo` - The modulus for all operations
    #[cfg(not(feature = "redis-cache"))]
    pub fn new(g: Integer, block_size: usize, pow_size: usize, modulo: Integer) -> Self {
        let table = Self::calculate_table(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            pow_size,
            block_size,
            modulo,
            table,
        }
    }

    /// Creates a new precomputed table using dynamic programming for calculation.
    ///
    /// # Arguments
    /// * `g` - The base integer for exponentiation
    /// * `block_size` - Size of each block in bits
    /// * `pow_size` - Maximum power size in bits
    /// * `modulo` - The modulus for all operations
    #[cfg(not(feature = "redis-cache"))]
    pub fn new_dp(g: Integer, block_size: usize, pow_size: usize, modulo: Integer) -> Self {
        let table = Self::calculate_table_dp(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            pow_size,
            block_size,
            modulo,
            table,
        }
    }

    /// Returns the size of the precomputed table in bytes.
    pub fn size_in_bytes(&self) -> usize {
        let mut size = 0;
        for row in &self.table {
            size += row.len() * mem::size_of::<Integer>();
        }
        size
    }

    /// Returns the block size used in this precomputed table.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Returns the maximum power size in bits used in this precomputed table.
    pub fn pow_size(&self) -> usize {
        self.pow_size
    }

    /// Returns a reference to the inner table of precomputed values.
    pub fn table(&self) -> &Vec<Vec<Integer>> {
        &self.table
    }

    /// Returns a reference to the modulus used for calculations.
    pub fn modulo(&self) -> &Integer {
        &self.modulo
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecryptionKey;

    fn test_dk_with_128b() -> DecryptionKey {
        DecryptionKey::sample_128()
    }

    fn test_dk_with_112b() -> DecryptionKey {
        DecryptionKey::sample_112()
    }

    #[test]
    fn test_encryption_with_precompute_128b() {
        let dk = test_dk_with_128b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 5 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &Integer = ek.nn();

        // pow <= 2^pow_size - 1
        #[cfg(feature = "redis-cache")]
        let precompute =
            PrecomputeTable::new(base.clone(), block_size, pow_size, modulo.clone(), None);
        #[cfg(not(feature = "redis-cache"))]
        let precompute = PrecomputeTable::new(base.clone(), block_size, pow_size, modulo.clone());

        let m = Integer::from(10);
        let mut rng = rand_dev::DevRng::new();
        let c = ek
            .encrypt_with_precompute_table(&mut rng, &precompute, &m)
            .unwrap();
        let recovered_m = dk.decrypt(&c).unwrap();
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_encryption_with_precompute_112b() {
        let dk = test_dk_with_112b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 5 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &Integer = ek.nn();

        #[cfg(feature = "redis-cache")]
        let precompute =
            PrecomputeTable::new(base.clone(), block_size, pow_size, modulo.clone(), None);
        #[cfg(not(feature = "redis-cache"))]
        let precompute = PrecomputeTable::new(base.clone(), block_size, pow_size, modulo.clone());

        let m = Integer::from(10);
        let mut rng = rand_dev::DevRng::new();
        let c = ek
            .encrypt_with_precompute_table(&mut rng, &precompute, &m)
            .unwrap();
        let recovered_m = dk.decrypt(&c).unwrap();
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_encryption_with_precompute_dp_128b() {
        let dk = test_dk_with_128b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 10 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &Integer = ek.nn();

        #[cfg(feature = "redis-cache")]
        let precompute =
            PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone(), None);
        #[cfg(not(feature = "redis-cache"))]
        let precompute =
            PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());

        let m = Integer::from(10);
        let mut rng = rand_dev::DevRng::new();
        let c = ek
            .encrypt_with_precompute_table(&mut rng, &precompute, &m)
            .unwrap();
        let recovered_m = dk.decrypt(&c).unwrap();
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_encryption_with_precompute_dp_112b() {
        let dk = test_dk_with_112b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 10 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &Integer = ek.nn();

        #[cfg(feature = "redis-cache")]
        let precompute =
            PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone(), None);
        #[cfg(not(feature = "redis-cache"))]
        let precompute =
            PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());

        let m = Integer::from(10);
        let mut rng = rand_dev::DevRng::new();
        let c = ek
            .encrypt_with_precompute_table(&mut rng, &precompute, &m)
            .unwrap();
        let recovered_m = dk.decrypt(&c).unwrap();
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_precompute_table_creation() {
        let g = Integer::from(7);
        let block_size = 4;
        let pow_size = 16;
        let modulo = Integer::from(11);

        #[cfg(feature = "redis-cache")]
        let table = PrecomputeTable::new(g.clone(), block_size, pow_size, modulo.clone(), None);
        #[cfg(not(feature = "redis-cache"))]
        let table = PrecomputeTable::new(g.clone(), block_size, pow_size, modulo.clone());

        assert_eq!(table.block_size(), block_size);
        assert_eq!(table.pow_size(), pow_size);
        assert_eq!(*table.modulo(), modulo);

        let expected_rows = pow_size / block_size + 1;
        let expected_cols = 1 << block_size;
        let table_data = table.table();
        assert_eq!(table_data.len(), expected_rows);
        for row in table_data {
            assert_eq!(row.len(), expected_cols);
        }
    }

    #[test]
    fn test_precompute_table_dp_creation() {
        let g = Integer::from(7);
        let block_size = 4;
        let pow_size = 16;
        let modulo = Integer::from(11);

        #[cfg(feature = "redis-cache")]
        let table = PrecomputeTable::new_dp(g.clone(), block_size, pow_size, modulo.clone(), None);
        #[cfg(not(feature = "redis-cache"))]
        let table = PrecomputeTable::new_dp(g.clone(), block_size, pow_size, modulo.clone());

        assert_eq!(table.block_size(), block_size);
        assert_eq!(table.pow_size(), pow_size);
        assert_eq!(*table.modulo(), modulo);

        let expected_rows = pow_size / block_size + 1;
        let expected_cols = 1 << block_size;
        let table_data = table.table();
        assert_eq!(table_data.len(), expected_rows);
        for row in table_data {
            assert_eq!(row.len(), expected_cols);
        }
    }

    #[test]
    fn test_table_values() {
        let g = Integer::from(2);
        let block_size = 2;
        let pow_size = 4;
        let modulo = Integer::from(7);

        #[cfg(feature = "redis-cache")]
        let table = PrecomputeTable::new(g.clone(), block_size, pow_size, modulo.clone(), None);
        #[cfg(not(feature = "redis-cache"))]
        let table = PrecomputeTable::new(g.clone(), block_size, pow_size, modulo.clone());

        let table_data = table.table();

        assert_eq!(table_data[0][0], Integer::from(1));
        assert_eq!(table_data[0][1], Integer::from(2));
        assert_eq!(table_data[0][2], Integer::from(4));
        assert_eq!(table_data[0][3], Integer::from(1));

        assert_eq!(table_data[1][0], Integer::from(1));
        assert_eq!(table_data[1][1], Integer::from(2));
        assert_eq!(table_data[1][2], Integer::from(4));
        assert_eq!(table_data[1][3], Integer::from(1));

        assert_eq!(table_data[2][0], Integer::from(1));
        assert_eq!(table_data[2][1], Integer::from(4));
        assert_eq!(table_data[2][2], Integer::from(2));
        assert_eq!(table_data[2][3], Integer::from(1));
    }

    #[test]
    fn test_table_dp_values() {
        let g = Integer::from(2);
        let block_size = 2;
        let pow_size = 4;
        let modulo = Integer::from(7);

        #[cfg(feature = "redis-cache")]
        let table = PrecomputeTable::new_dp(g.clone(), block_size, pow_size, modulo.clone(), None);
        #[cfg(not(feature = "redis-cache"))]
        let table = PrecomputeTable::new_dp(g.clone(), block_size, pow_size, modulo.clone());

        let table_data = table.table();

        assert_eq!(table_data[0][0], Integer::from(1));
        assert_eq!(table_data[0][1], Integer::from(2));
        assert_eq!(table_data[0][2], Integer::from(4));
        assert_eq!(table_data[0][3], Integer::from(1));

        assert_eq!(table_data[1][0], Integer::from(1));
        assert_eq!(table_data[1][1], Integer::from(2));
        assert_eq!(table_data[1][2], Integer::from(4));
        assert_eq!(table_data[1][3], Integer::from(1));

        assert_eq!(table_data[2][0], Integer::from(1));
        assert_eq!(table_data[2][1], Integer::from(4));
        assert_eq!(table_data[2][2], Integer::from(2));
        assert_eq!(table_data[2][3], Integer::from(1));
    }

    #[test]
    fn test_size_in_bytes() {
        use bincode::serialize;
        let g = Integer::from(7);
        let block_size = 4;
        let pow_size = 16;
        let modulo = Integer::from(11);
        let table = PrecomputeTable::new(g.clone(), block_size, pow_size, modulo.clone());

        let serialized_size = serialize(&table).unwrap().len();
        let estimated_size = table.size_in_bytes();

        println!("Serialized size: {}", serialized_size);
        println!("Estimated size (size_in_bytes): {}", estimated_size);

        assert!(serialized_size > 0);
        let expected_rows = pow_size / block_size + 1;
        let expected_cols = 1 << block_size;
        let expected_elements = expected_rows * expected_cols;
        let expected_size = expected_elements * mem::size_of::<Integer>();

        assert!(estimated_size >= expected_size);
    }
}
