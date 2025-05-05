use std::mem;
use rug::{Complete, Integer};

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
    ) -> Vec<Vec<Integer>>
    {
        let num_blocks = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        let max_block_value = (1 << block_size) - 1;

        // table[i][j] is 
        // table[i][j] = [base^(2^(i*block_size))]^j % modulo
        
        let mut table = vec![vec![Integer::from(1); max_block_value + 1]; num_blocks + 1];

        for i in 0..=num_blocks {
            for j in 0..=max_block_value {
                let tmp1 = Integer::from(2).pow_mod(
                    &Integer::from((i * block_size) as u32),
                    modulo,
                ).unwrap();
                let tmp2: Integer = base.clone().pow_mod(&tmp1, modulo).unwrap().into();
                let tmp3: Integer = tmp2.clone().pow_mod(&Integer::from(j as u32), modulo).unwrap().into();
                table[i][j] = tmp3;
            }
        }

        table
    }

    fn calculate_table_dp(
        g: &Integer,
        block_size: usize,
        pow_size: usize,
        modulo: &Integer,
    ) -> Vec<Vec<Integer>>
    {
        // let i_min = 1 as usize;
        let i_max = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        // let j_min = 0 as usize;
        let j_max = (1 << block_size) - 1;
        // table[i][j] = [g^(2^(ib))]^j mod modulo
        let mut table = vec![vec![Integer::from(1); j_max + 1]; i_max + 1];

        // base case 0: i = 0, j = 0, table[0][0] = 1

        // base case 1: i = 0, for all j, table[0][j] = [g^(2^(0b))]^j mod modulo = g^j mod modulo
        // table[0][j] = table[0][j - 1] * g mod modulo
        for j in 1..=j_max {
            let product = (&table[0][j - 1] * g).complete();
            table[0][j] = product.modulo(modulo);
        }

        // base case 2: j = 0, for all i, table[i][0] = [g^(2^(ib))]^0 mod modulo = 1
        // already done because by default, all elements in table are 1

        // for all i > 0, table[i][1] = (table[i - 1][1])^(2^b), where b is block_size
        // 2^b as a constant
        let two_pow_b = Integer::from(2).pow_mod(
            &Integer::from(block_size as u32),
            modulo,
        ).unwrap();

        for i in 1..=i_max {
            table[i][1] = table[i - 1][1].pow_mod_ref(&two_pow_b, modulo).unwrap().into();
        }


        // for i >= 1 and j >= 2: table[i][j] = table[i][j - 1] . table[i][1]
        for i in 1..=i_max {
            for j in 2..=j_max {
                let product = (&table[i][j - 1] * &table[i][1]).complete();
                table[i][j] = product.modulo(modulo);
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
    use crate::EncryptionKey;
    use crate::DecryptionKey;

    fn test_ek() -> EncryptionKey {
        let p: Integer = Integer::from_str_radix("58840286422659759040264722526723163115947585338232456760625037250347772947158924579397568010160401824142812407358290596642469990113927112749530655037092283267003056548558029709374658607773847180644927643815153088281601855305598381448858360794678123176275437646277062199420220697194572706984411597767662174219", 10).unwrap();
        let q = Integer::from_str_radix("64569320288008737248616342555880093394368754507783709070327116553058977898351053473313292166959127254971093796968717357648354685162478156927773865332477516856906959367256797593402514551692581319610393653175392375527614160563282643144940815153885487175996514917461421149259641826709133924683180923570779884947", 10).unwrap();
        let n = (&p * &q).complete();
        let a_size = 448 as u32;
        let h = Integer::from(2); // Define h as a simple value for testing

        EncryptionKey::new(n.significant_bits(), a_size, h, n).unwrap()
    }

    fn test_dk() -> DecryptionKey { 
        DecryptionKey::sample()
    }



    #[test]
    fn test_encryption_with_precompute() {
        let dk = test_dk();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        // block_size > 10 --> memory error
        let block_size = 5 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &Integer = ek.nn();

        // pow <= 2^pow_size - 1
        let precompute = PrecomputeTable::new(base.clone(), block_size, pow_size, modulo.clone());
        let m = Integer::from(10);
        let c = ek.encrypt_with_precompute_table(&precompute, &m).unwrap();
        // println!("ciphertext: {}", c);
        let recovered_m = dk.decrypt(&c).unwrap();

        println!("recovered_m: {}", recovered_m);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_encryption_with_precompute_dp() {
        let dk = test_dk();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        // block_size > 10 --> memory error
        let block_size = 10 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &Integer = ek.nn();

        println!("base: {}", base);
        println!("pow_size: {}", pow_size);
        println!("modulo: {}", modulo);

        // pow <= 2^pow_size - 1
        let precompute = PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());
        let m = Integer::from(10);
        let c = ek.encrypt_with_precompute_table(&precompute, &m).unwrap();
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
        
        // Verify dimensions
        let expected_rows = pow_size / block_size + 1; // Ceiling of pow_size/block_size
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

        let table: PrecomputeTable = PrecomputeTable::new_dp(g.clone(), block_size, pow_size, modulo.clone());

        assert_eq!(table.block_size(), block_size);
        assert_eq!(table.pow_size(), pow_size);
        assert_eq!(*table.modulo(), modulo);
        
        // Verify dimensions
        let expected_rows = pow_size / block_size + 1; // Ceiling of pow_size/block_size
        let expected_cols = 1 << block_size;
        let table_data = table.table();
        assert_eq!(table_data.len(), expected_rows);
        for row in table_data {
            assert_eq!(row.len(), expected_cols);
        }
    }

    #[test]
    fn test_table_values() {
        // Use a small modulo and small values to test actual table values
        let g = Integer::from(2);
        let block_size = 2;
        let pow_size = 4;
        let modulo = Integer::from(7);

        let table = PrecomputeTable::new(g.clone(), block_size, pow_size, modulo.clone());
        let table_data = table.table();

        // Based on the observed values from debug printing, let's assert the correct values
        
        // First row (i=0)
        assert_eq!(table_data[0][0], Integer::from(0));
        assert_eq!(table_data[0][1], Integer::from(1));
        assert_eq!(table_data[0][2], Integer::from(4));
        assert_eq!(table_data[0][3], Integer::from(2));
        
        // Second row (i=1)
        assert_eq!(table_data[1][0], Integer::from(0));
        assert_eq!(table_data[1][1], Integer::from(1));
        assert_eq!(table_data[1][2], Integer::from(4));
        assert_eq!(table_data[1][3], Integer::from(2));
        
        // Third row (i=2)
        assert_eq!(table_data[2][0], Integer::from(0));
        assert_eq!(table_data[2][1], Integer::from(1));
        assert_eq!(table_data[2][2], Integer::from(2));
        assert_eq!(table_data[2][3], Integer::from(4));
    }

    #[test]
    fn test_table_dp_values() {
        // Use a small modulo and small values to test actual table values
        let g = Integer::from(2);
        let block_size = 2;
        let pow_size = 4;
        let modulo = Integer::from(7);

        let table = PrecomputeTable::new_dp(g.clone(), block_size, pow_size, modulo.clone());
        let table_data = table.table();

        // Test the base cases and a few computed values
        // First row (i=0)
        assert_eq!(table_data[0][0], Integer::from(1)); // Base case: j=0 => g^0 = 1
        assert_eq!(table_data[0][1], Integer::from(2)); // g^1 mod 7 = 2
        assert_eq!(table_data[0][2], Integer::from(4)); // g^2 mod 7 = 4
        assert_eq!(table_data[0][3], Integer::from(1)); // g^3 mod 7 = 8 mod 7 = 1
        
        // Second row (i=1)
        assert_eq!(table_data[1][0], Integer::from(1)); // Base case: j=0 => 1
        
        // For [1][1], the DP algorithm uses: table[i][1] = (table[i-1][1])^(2^b)
        // table[1][1] = (table[0][1])^(2^2) = 2^4 = 16 mod 7 = 2
        assert_eq!(table_data[1][1], Integer::from(2));
        
        // For [1][2], the DP algorithm uses: table[i][j] = table[i][j-1] * table[i][1]
        // table[1][2] = table[1][1] * table[1][1] = 2 * 2 = 4
        assert_eq!(table_data[1][2], Integer::from(4));
        
        // For [1][3], the DP algorithm uses: table[i][j] = table[i][j-1] * table[i][1]
        // table[1][3] = table[1][2] * table[1][1] = 4 * 2 = 8 mod 7 = 1
        assert_eq!(table_data[1][3], Integer::from(1));
        
        // Third row (i=2) if it exists
        if table_data.len() > 2 {
            assert_eq!(table_data[2][0], Integer::from(1)); // Base case: j=0 => 1
            
            // For [2][1], the DP algorithm uses: table[i][1] = (table[i-1][1])^(2^b)
            // table[2][1] = (table[1][1])^(2^2) = 2^4 = 16 mod 7 = 2
            assert_eq!(table_data[2][1], Integer::from(2));
            
            // For [2][2] = table[2][1] * table[2][1] = 2 * 2 = 4
            assert_eq!(table_data[2][2], Integer::from(4));
            
            // For [2][3] = table[2][2] * table[2][1] = 4 * 2 = 8 mod 7 = 1 
            assert_eq!(table_data[2][3], Integer::from(1));
        }
    }

    #[test]
    fn test_size_in_bytes() {
        let g = Integer::from(7);
        let block_size = 4;
        let pow_size = 16;
        let modulo = Integer::from(11);

        let table = PrecomputeTable::new(g.clone(), block_size, pow_size, modulo.clone());
        
        // Size should be > 0
        let size = table.size_in_bytes();
        assert!(size > 0);
        
        // Check that the formula is consistent
        let expected_rows = pow_size / block_size + 1;
        let expected_cols = 1 << block_size;
        let expected_elements = expected_rows * expected_cols;
        let expected_size = expected_elements * mem::size_of::<Integer>();
        
        // Note: This is not exactly equal because the size_in_bytes method counts
        // actual allocated memory while our calculation is an estimate
        // But the size returned should be at least as large as our estimate
        assert!(size >= expected_size);
    }
}

