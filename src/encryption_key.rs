use rand_core::{CryptoRng, RngCore};
use rug::{Complete, Integer};

use crate::{utils, Ciphertext, Nonce, Plaintext};
use crate::{Bug, Error, Reason};
use kzen_paillier::optimized_paillier::{
    Decrypt, DecryptionKey as OptimizedDecryptionKey, Encrypt,
    EncryptionKey as OptimizedEncryptionKey, KeyGeneration, NGen, OptimizedPaillier, RawCiphertext,
    RawPlaintext,
};

/// Paillier encryption key
#[derive(Clone)]
pub struct EncryptionKey {
    /// n = q * p
    pub n: Integer,

    /// nn = n * n
    pub nn: Integer,

    /// half_n = n >> 1u32
    pub half_n: Integer,

    /// neg_half_n = - half_n
    pub neg_half_n: Integer,

    /// addtional info of optimized paillier ek
    pub optimized_ek: OptimizedEncryptionKey,
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("n", &self.n)
            .field("nn", &self.nn)
            .field("half_n", &self.half_n)
            .field("neg_half_n", &self.neg_half_n)
            .finish_non_exhaustive()
    }
}

impl EncryptionKey {
    /// Constructs an encryption key from `N`
    pub fn from_n(n: Integer) -> Self {
        let nn = n.clone() * &n;
        let half_n = n.clone() >> 1u32;
        let neg_half_n = -half_n.clone();
        let optimized_ek =
            OptimizedEncryptionKey::from_n(utils::integer_to_bigint(n.clone()), 2048);
        Self {
            n,
            nn,
            half_n,
            neg_half_n,
            optimized_ek,
        }
    }

    /// Returns `N`
    pub fn n(&self) -> &Integer {
        &self.n
    }

    /// Returns `N^2`
    pub fn nn(&self) -> &Integer {
        &self.nn
    }

    /// Returns `N/2`
    pub fn half_n(&self) -> &Integer {
        &self.half_n
    }

    /// `l(x) = (x-1)/n`
    pub(crate) fn l(&self, x: &Integer) -> Option<Integer> {
        if (x % self.n()).complete() != *Integer::ONE {
            return None;
        }
        if !utils::in_mult_group(x, self.nn()) {
            return None;
        }

        // (x - 1) / N
        Some((x - Integer::ONE).complete() / self.n())
    }

    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}` with `nonce` in `Z*_n`
    ///
    /// Returns error if inputs are not in specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        if !self.in_signed_group(x) || !utils::in_mult_group(nonce, self.n()) {
            return Err(Reason::Encrypt.into());
        }

        let x_bigint = utils::integer_to_bigint(x.clone());
        let raw_plaintext = RawPlaintext::new(x_bigint);
        let result = OptimizedPaillier::encrypt(&self.optimized_ek, raw_plaintext);
        Ok(utils::bigint_to_integer(result.to_bigint().clone()))
    }

    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}`
    ///
    /// Nonce is sampled randomly using `rng`.
    ///
    /// Returns error if plaintext is not in specified range
    pub fn encrypt_with_random(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        x: &Plaintext,
    ) -> Result<(Ciphertext, Nonce), Error> {
        let nonce = utils::sample_in_mult_group(rng, self.n());
        let ciphertext = self.encrypt_with(x, &nonce)?;
        Ok((ciphertext, nonce))
    }

    /// Homomorphic addition of two ciphertexts
    ///
    /// ```text
    /// oadd(Enc(a1), Enc(a2)) = Enc(a1 + a2)
    /// ```
    pub fn oadd(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        if !utils::in_mult_group(c1, self.nn()) || !utils::in_mult_group(c2, self.nn()) {
            return Err(Reason::Ops.into());
        }
        let c1_raw = RawCiphertext::new(utils::integer_to_bigint(c1.clone()));
        let c2_raw = RawCiphertext::new(utils::integer_to_bigint(c2.clone()));
        let result = self.optimized_ek.oadd(&c1_raw, &c2_raw);
        Ok(utils::bigint_to_integer(result.to_bigint().clone()))
    }

    /// Homomorphic subtraction of two ciphertexts
    ///
    /// ```text
    /// osub(Enc(a1), Enc(a2)) = Enc(a1 - a2)
    /// ```
    pub fn osub(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        if !utils::in_mult_group(c1, self.nn()) {
            return Err(Reason::Ops.into());
        }
        let c1_raw = RawCiphertext::new(utils::integer_to_bigint(c1.clone()));
        let c2_raw = RawCiphertext::new(utils::integer_to_bigint(c2.clone()));
        let result = self.optimized_ek.osub(&c1_raw, &c2_raw);
        Ok(utils::bigint_to_integer(result.to_bigint().clone()))
    }

    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// ```text
    /// omul(a, Enc(c)) = Enc(a * c)
    /// ```
    pub fn omul(&self, scalar: &Integer, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        if !utils::in_mult_group_abs(scalar, self.n())
            || !utils::in_mult_group(ciphertext, self.nn())
        {
            return Err(Reason::Ops.into());
        }
        let scalar_bigint = utils::integer_to_bigint(scalar.clone());
        let ciphertext_raw = RawCiphertext::new(utils::integer_to_bigint(ciphertext.clone()));
        let result = self.optimized_ek.omul(&scalar_bigint, &ciphertext_raw);
        Ok(utils::bigint_to_integer(result.to_bigint().clone()))
    }

    /// Homomorphic negation of a ciphertext
    ///
    /// ```text
    /// oneg(Enc(a)) = Enc(-a)
    /// ```
    pub fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        let ciphertext_raw = RawCiphertext::new(utils::integer_to_bigint(ciphertext.clone()));
        let result = self.optimized_ek.oneg(&ciphertext_raw);
        Ok(utils::bigint_to_integer(result.to_bigint().clone()))
    }

    /// Checks whether `x` is `{-N/2, .., N/2}`
    pub fn in_signed_group(&self, x: &Integer) -> bool {
        self.neg_half_n <= *x && *x <= self.half_n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_dev::DevRng;

    fn setup() -> EncryptionKey {
        // Using a larger prime number for testing
        let n = Integer::from(15485863) * Integer::from(15485867); // Two large primes
        EncryptionKey::from_n(n)
    }

    #[test]
    fn test_encrypt_decrypt() {
        let ek = setup();
        let mut rng = DevRng::new();
        let plaintext: Integer = Integer::from(5);

        let (ciphertext, _nonce) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
    }

    #[test]
    fn test_homomorphic_add() {
        let ek = setup();
        let mut rng = DevRng::new();

        let p1 = Integer::from(3);
        let p2 = Integer::from(4);

        let (c1, _) = ek.encrypt_with_random(&mut rng, &p1).unwrap();
        let (c2, _) = ek.encrypt_with_random(&mut rng, &p2).unwrap();

        let c_sum = ek.oadd(&c1, &c2).unwrap();
        assert_ne!(c_sum, c1);
        assert_ne!(c_sum, c2);
    }

    #[test]
    fn test_homomorphic_mul() {
        let ek = setup();
        let mut rng = DevRng::new();

        let plaintext = Integer::from(5);
        let scalar = Integer::from(3);

        let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        let result = ek.omul(&scalar, &ciphertext).unwrap();
        assert_ne!(result, ciphertext);
    }

    #[test]
    fn test_homomorphic_neg() {
        let ek = setup();
        let mut rng = DevRng::new();

        let plaintext = Integer::from(5);
        let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();

        let neg = ek.oneg(&ciphertext).unwrap();
        assert_ne!(neg, ciphertext);
    }

    #[test]
    fn test_in_signed_group() {
        let ek = setup();
        let half_n = ek.half_n();

        assert!(ek.in_signed_group(half_n));
        assert!(ek.in_signed_group(&Integer::from(0)));
        assert!(!ek.in_signed_group(&(half_n + Integer::from(1))));
    }
}
