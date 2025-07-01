use malachite::Integer;
use std::mem;

/// A table for precomputed values to speed up Paillier encryption operations.
/// This table stores modular exponentiations for faster computation of cryptographic operations.
pub struct PrecomputeTable {
    pow_size: usize,
    block_size: usize,
    modulo: Integer,
    table: Vec<Vec<Integer>>,
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
                let tmp1 = crate::integer_ext::mod_pow_int(&Integer::from(2), &Integer::from((i * block_size) as u32), modulo);
                // tmp2 = base^(tmp1) % modulo
                let tmp2: Integer = crate::integer_ext::mod_pow_int(base, &tmp1, modulo);
                // tmp3 = tmp2^j % modulo
                let tmp3: Integer = crate::integer_ext::mod_pow_int(&tmp2, &Integer::from(j as u32), modulo);
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
            let block_exp = crate::integer_ext::mod_pow_int(&Integer::from(2), &Integer::from(block_size as u32), modulo);
            pow_2[i] = (prev * &block_exp) % modulo;
        }

        // Compute table[i][j]
        for i in 0..=num_blocks {
            // Compute tmp2 = base^(2^(i*block_size)) % modulo
            let tmp2: Integer = crate::integer_ext::mod_pow_int(base, &pow_2[i], modulo);

            // Compute table[i][j] iteratively for j >= 1
            table[i][1] = tmp2.clone();
            for j in 2..=max_block_value {
                // table[i][j] = table[i][j-1] * tmp2 % modulo
                table[i][j] = (&table[i][j - 1] * &tmp2) % modulo;
            }
        }

        table
    }
    /// Creates a new precomputed table using the standard calculation method.
    ///
    /// # Arguments
    /// * `g` - The base integer for exponentiation
    /// * `block_size` - Size of each block in bits
    /// * `pow_size` - Maximum power size in bits
    /// * `modulo` - The modulus for all operations
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

        let table: PrecomputeTable =
            PrecomputeTable::new_dp(g.clone(), block_size, pow_size, modulo.clone());

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

    use crate::EncryptionKey;

    // #[test]
    // fn test_size_in_bytes() {
    //     let block_size = 18;
    //     let pow_size = 512;
    //     let ek = EncryptionKey::sample_128();
    //     let modulo = ek.nn();
    //     let base = ek.h_pow_n();
    //     let table = PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());

    //     let size = table.size_in_bytes();
    //     assert!(size > 0);

    //     let expected_rows = pow_size / block_size + 1;
    //     let expected_cols = 1 << block_size;
    //     let expected_elements = expected_rows * expected_cols;
    //     let expected_size = expected_elements * mem::size_of::<Integer>();
    //     println!("expected_size: {}", expected_size);
    //     println!("size: {}", size);
    //     assert!(size >= expected_size);
    // }
}
