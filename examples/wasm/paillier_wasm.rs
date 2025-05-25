use fast_paillier::{
    DecryptionKey, EncryptionKey, Plaintext, Ciphertext, Nonce, AnyEncryptionKeyExt,
    precomputed_table::PrecomputedTable,
};
use num_bigint::BigInt;
use wasm_bindgen::prelude::*;
use rand::{rngs::ThreadRng, thread_rng};

#[wasm_bindgen]
pub struct PaillierWasm {
    dk: DecryptionKey,
    ek: EncryptionKey,
    rng: ThreadRng,
    precomputed_table: Option<PrecomputedTable>,
}

#[wasm_bindgen]
impl PaillierWasm {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
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

    #[wasm_bindgen]
    pub fn create_precomputed_table(&mut self, window_size: u32) -> Result<(), JsError> {
        let precomputed = PrecomputedTable::new(&self.ek, window_size)
            .map_err(|e| JsError::new(&format!("Failed to create precomputed table: {:?}", e)))?;
        self.precomputed_table = Some(precomputed);
        Ok(())
    }

    #[wasm_bindgen]
    pub fn encrypt(&mut self, plaintext: i64) -> Result<String, JsError> {
        let plaintext = BigInt::from(plaintext);
        
        let (ciphertext, _) = self.ek.encrypt_with_random(&mut self.rng, &plaintext)
            .map_err(|e| JsError::new(&format!("Encryption failed: {:?}", e)))?;
        
        Ok(ciphertext.to_string())
    }

    #[wasm_bindgen]
    pub fn encrypt_with_precomputed(&mut self, plaintext: i64) -> Result<String, JsError> {
        if let Some(precomputed) = &self.precomputed_table {
            let plaintext = BigInt::from(plaintext);
            
            let (ciphertext, _) = precomputed.encrypt_with_random(&mut self.rng, &plaintext)
                .map_err(|e| JsError::new(&format!("Encryption with precomputed table failed: {:?}", e)))?;
            
            Ok(ciphertext.to_string())
        } else {
            Err(JsError::new("Precomputed table not initialized"))
        }
    }

    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext_str: &str) -> Result<i64, JsError> {
        let ciphertext = ciphertext_str.parse::<BigInt>()
            .map_err(|_| JsError::new("Invalid ciphertext format"))?;
        
        let plaintext = self.dk.decrypt(&ciphertext)
            .map_err(|e| JsError::new(&format!("Decryption failed: {:?}", e)))?;
        
        plaintext.to_i64().ok_or_else(|| JsError::new("Plaintext too large for i64"))
    }

    #[wasm_bindgen]
    pub fn homomorphic_add(&self, ciphertext1_str: &str, ciphertext2_str: &str) -> Result<String, JsError> {
        let c1 = ciphertext1_str.parse::<BigInt>()
            .map_err(|_| JsError::new("Invalid ciphertext format for c1"))?;
        
        let c2 = ciphertext2_str.parse::<BigInt>()
            .map_err(|_| JsError::new("Invalid ciphertext format for c2"))?;
        
        let result = self.ek.oadd(&c1, &c2)
            .map_err(|e| JsError::new(&format!("Homomorphic addition failed: {:?}", e)))?;
        
        Ok(result.to_string())
    }

    #[wasm_bindgen]
    pub fn homomorphic_mul(&self, ciphertext_str: &str, scalar: i64) -> Result<String, JsError> {
        let ciphertext = ciphertext_str.parse::<BigInt>()
            .map_err(|_| JsError::new("Invalid ciphertext format"))?;
        
        let scalar = BigInt::from(scalar);
        
        let result = self.ek.omul(&scalar, &ciphertext)
            .map_err(|e| JsError::new(&format!("Homomorphic multiplication failed: {:?}", e)))?;
        
        Ok(result.to_string())
    }
}

#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
} 
