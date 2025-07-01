use wasm_bindgen::prelude::*;
use malachite::Integer;
use malachite_base::num::conversion::traits::FromStringBase;
use malachite_base::num::logic::traits::SignificantBits;

use crate::{DecryptionKey, EncryptionKey, Plaintext};

/// A lightweight wrapper around [`crate::DecryptionKey`] that exposes a
/// very small subset of the Paillier API to JavaScript / WebAssembly.
///
/// The implementation purposefully keeps the interface minimal so that the
/// generated WASM binary is small and compilation succeeds with the default
/// tool-chain (`cargo build --target wasm32-unknown-unknown`).  It is **NOT**
/// intended for production use – it exists only as a demo/show-case.
#[wasm_bindgen]
pub struct PaillierWasm {
    dk: DecryptionKey,
}

#[wasm_bindgen]
impl PaillierWasm {
    /// Create a new Paillier instance with the hard-coded 128-bit demo key.
    ///
    /// Generating a fresh key inside WASM would require a source of
    /// cryptographically secure randomness that works in all JS
    /// environments – keeping a static key avoids those complications while
    /// still demonstrating the basic API.
    #[wasm_bindgen(constructor)]
    pub fn new() -> PaillierWasm {
        // Sample_128 is deterministic (no RNG involved) and therefore works
        // out-of-the-box on wasm32.
        let dk = DecryptionKey::sample_128();
        PaillierWasm { dk }
    }

    /// Encrypt a decimal string representing an integer that lies in the
    /// valid message range (\[-N/2, N/2]).
    ///
    /// For the sake of simplicity and portability the nonce is fixed to 1.
    /// DO **NOT** re-use this implementation in a real application – always
    /// use *random* nonces!
    #[wasm_bindgen]
    pub fn encrypt(&self, plaintext: &str) -> Result<String, JsValue> {
        // Parse the input string as base-10 integer.
        let x: Integer = Integer::from_string_base(10, plaintext)
            .ok_or_else(|| JsValue::from_str("invalid plaintext number"))?;

        let ek: &EncryptionKey = self.dk.encryption_key();

        // Fixed nonce = 1 ‑- this is fine for a demo, but destroys semantic
        // security — never do this in production!
        let nonce = Integer::from(1);

        let c = ek
            .encrypt_with(&x, &nonce)
            .map_err(|e| JsValue::from_str(&format!("encryption error: {e}")))?;
        Ok(c.to_string())
    }

    /// Decrypt a ciphertext provided as a base-10 string.
    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext: &str) -> Result<String, JsValue> {
        let c: Integer = Integer::from_string_base(10, ciphertext)
            .ok_or_else(|| JsValue::from_str("invalid ciphertext number"))?;

        let m: Plaintext = self
            .dk
            .decrypt(&c)
            .map_err(|e| JsValue::from_str(&format!("decryption error: {e}")))?;
        Ok(m.to_string())
    }

    /// Convenience getter that exposes the modulus size (in bits) so that a
    /// JS caller can check the security level.
    #[wasm_bindgen(getter)]
    pub fn n_bits(&self) -> u32 {
        self.dk.n().significant_bits() as u32
    }
} 
