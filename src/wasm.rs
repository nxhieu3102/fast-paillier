// #![cfg(feature = "wasm")]

use crate::{
    precomputed_table::PrecomputeTable, AnyEncryptionKeyExt, DecryptionKey, EncryptionKey,
};
use num_bigint::BigInt;
use num_traits::{Num, ToPrimitive};
use rand::{rngs::ThreadRng, thread_rng};
use wasm_bindgen::prelude::*;

/// WebAssembly interface for Paillier cryptosystem
#[wasm_bindgen]
pub struct PaillierWasm {
    dk: DecryptionKey,
    ek: EncryptionKey,
    rng: ThreadRng,
    precomputed_table: Option<PrecomputeTable>,
}

#[wasm_bindgen]
impl PaillierWasm {
    /// Creates a new Paillier instance with 128-bit security
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook::set_once();

        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key().clone();
        let rng = thread_rng();

        Self {
            dk,
            ek,
            rng,
            precomputed_table: None,
        }
    }

    /// Creates a precomputed table for faster encryption
    ///
    /// # Arguments
    /// * `window_size` - The window size for the precomputed table (typically 5-8)
    #[wasm_bindgen]
    pub fn create_precomputed_table(&mut self, window_size: u32) -> Result<(), JsError> {
        let base = self.ek.h_pow_n().clone();
        let block_size = window_size as usize;
        let pow_size = self.ek.a_size() as usize;
        let modulo = self.ek.nn().clone();

        let precomputed = PrecomputeTable::new(base, block_size, pow_size, modulo);
        self.precomputed_table = Some(precomputed);
        Ok(())
    }

    /// Encrypts a plaintext value
    ///
    /// # Arguments
    /// * `plaintext` - The integer value to encrypt
    #[wasm_bindgen]
    pub fn encrypt(&mut self, plaintext: &str) -> Result<String, JsError> {
        let plaintext = BigInt::from_str_radix(plaintext, 10)
            .map_err(|_| JsError::new("Invalid plaintext format"))?;

        let (ciphertext, _) = self
            .ek
            .encrypt_with_random(&mut self.rng, &plaintext)
            .map_err(|e| JsError::new(&format!("Encryption failed: {:?}", e)))?;

        Ok(ciphertext.to_string())
    }

    /// Encrypts a plaintext value using the precomputed table for faster computation
    ///
    /// # Arguments
    /// * `plaintext` - The integer value to encrypt
    #[wasm_bindgen]
    pub fn encrypt_with_precomputed(&mut self, plaintext: i64) -> Result<String, JsError> {
        if let Some(precomputed) = &self.precomputed_table {
            let plaintext = BigInt::from(plaintext);

            let ciphertext = self
                .ek
                .encrypt_with_precompute_table(&mut self.rng, precomputed, &plaintext)
                .map_err(|e| {
                    JsError::new(&format!(
                        "Encryption with precomputed table failed: {:?}",
                        e
                    ))
                })?;

            Ok(ciphertext.to_string())
        } else {
            Err(JsError::new("Precomputed table not initialized"))
        }
    }

    /// Decrypts a ciphertext
    ///
    /// # Arguments
    /// * `ciphertext_str` - The ciphertext as a string
    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext_str: &str) -> Result<String, JsError> {
        let ciphertext = ciphertext_str
            .parse::<BigInt>()
            .map_err(|_| JsError::new("Invalid ciphertext format"))?;

        let plaintext = self
            .dk
            .decrypt(&ciphertext)
            .map_err(|e| JsError::new(&format!("Decryption failed: {:?}", e)))?;

        Ok(plaintext.to_string())
    }

    /// Performs homomorphic addition of two ciphertexts
    ///
    /// # Arguments
    /// * `ciphertext1_str` - First ciphertext as a string
    /// * `ciphertext2_str` - Second ciphertext as a string
    #[wasm_bindgen]
    pub fn homomorphic_add(
        &self,
        ciphertext1_str: &str,
        ciphertext2_str: &str,
    ) -> Result<String, JsError> {
        let c1 = ciphertext1_str
            .parse::<BigInt>()
            .map_err(|_| JsError::new("Invalid ciphertext format for c1"))?;

        let c2 = ciphertext2_str
            .parse::<BigInt>()
            .map_err(|_| JsError::new("Invalid ciphertext format for c2"))?;

        let result = self
            .ek
            .oadd(&c1, &c2)
            .map_err(|e| JsError::new(&format!("Homomorphic addition failed: {:?}", e)))?;

        Ok(result.to_string())
    }

    /// Performs homomorphic scalar multiplication on a ciphertext
    ///
    /// # Arguments
    /// * `ciphertext_str` - The ciphertext as a string
    /// * `scalar` - The scalar value to multiply by
    #[wasm_bindgen]
    pub fn homomorphic_mul(&self, ciphertext_str: &str, scalar: i64) -> Result<String, JsError> {
        let ciphertext = ciphertext_str
            .parse::<BigInt>()
            .map_err(|_| JsError::new("Invalid ciphertext format"))?;

        let scalar = BigInt::from(scalar);

        let result = self
            .ek
            .omul(&scalar, &ciphertext)
            .map_err(|e| JsError::new(&format!("Homomorphic multiplication failed: {:?}", e)))?;

        Ok(result.to_string())
    }
}

/// Initializes the WASM module
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}
