use rand_core::{CryptoRng, RngCore};
use rug::{Complete, Integer};

use crate::{utils, Ciphertext, EncryptionKey, Nonce, Plaintext};
use crate::{Error, Reason};
use kzen_paillier::optimized_paillier::{Decrypt, DecryptionKey as OptimizedDecryptionKey, EncryptionKey as OptimizedEncryptionKey, KeyGeneration, NGen, OptimizedPaillier, RawCiphertext, RawPlaintext, Encrypt};
/// Paillier decryption key
#[derive(Clone)]
pub struct DecryptionKey {
    ek: EncryptionKey,
    /// `lcm(p-1, q-1)`
    lambda: Integer,
    /// `lambda^-1 mod N`
    mu: Integer,

    p: Integer,
    q: Integer,
    
    crt_mod_nn: utils::CrtExp,
    /// Calculates `x ^ N mod N^2`. It's used for faster encryption
    exp_n: utils::Exponent,
    /// Calculates `x ^ lambda mod N^2`. It's used for faster decryption
    exp_lambda: utils::Exponent,

    optimized_dk: OptimizedDecryptionKey,
    optimized_ek: OptimizedEncryptionKey,
}

impl DecryptionKey {
    /// Generates a paillier key
    ///
    /// Samples two safe 1536-bits primes that meets 128 bits security level
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, Error> {
        let ngen = OptimizedPaillier::ngen(2048, 448);
        let (_ek, dk) = ngen.keys();
        let p = utils::bigint_to_integer(ngen.p);
        let q = utils::bigint_to_integer(ngen.q);

        let pm1 = Integer::from(&p - 1);
        let qm1 = Integer::from(&q - 1);
        let ek = EncryptionKey::from_n((&p * &q).complete());
        let lambda = pm1.clone().lcm(&qm1);
        if lambda.cmp0().is_eq() {
            return Err(Reason::InvalidPQ.into());
        }

        // u = lambda^-1 mod N
        let u = lambda.invert_ref(ek.n()).ok_or(Reason::InvalidPQ)?.into();

        let crt_mod_nn = utils::CrtExp::build_nn(&p, &q).ok_or(Reason::BuildFastExp)?;
        let exp_n = crt_mod_nn.prepare_exponent(ek.n());
        let exp_lambda = crt_mod_nn.prepare_exponent(&lambda);
        
        let optimized_dk = OptimizedDecryptionKey::new(
            dk.p.clone(),
            dk.q.clone(),
            dk.alpha.clone(),
            dk.n.clone()
        );
        
    
        let optimized_ek = OptimizedEncryptionKey::new(
            2048, 
            _ek.n.clone(),
            _ek.h.clone(),
            _ek.hn.clone()
        );
        
        
        Ok(Self {
            ek,
            lambda,
            mu: u,
            p,
            q,
            crt_mod_nn,
            exp_n,
            exp_lambda,
            optimized_dk,
            optimized_ek,
        })
    
    }

    /// Constructs a paillier key from primes `p`, `q`
    ///
    /// `p` and `q` need to be safe primes sufficiently large to meet security level requirements.
    ///
    /// Returns error if `p` and `q` do not correspond to a valid paillier key.
    #[allow(clippy::many_single_char_names)]
    pub fn from_primes(p: Integer, q: Integer) -> Result<Self, Error> {
        // Paillier doesn't work if p == q
        if p == q {
            return Err(Reason::InvalidPQ.into());
        }
        let pm1 = Integer::from(&p - 1);
        let qm1: Integer = Integer::from(&q - 1);
        let ek: EncryptionKey = EncryptionKey::from_n((&p * &q).complete());
        let lambda: Integer = pm1.clone().lcm(&qm1);
        if lambda.cmp0().is_eq() {
            return Err(Reason::InvalidPQ.into());
        }

        // u = lambda^-1 mod N
        let u = lambda.invert_ref(ek.n()).ok_or(Reason::InvalidPQ)?.into();

        let crt_mod_nn = utils::CrtExp::build_nn(&p, &q).ok_or(Reason::BuildFastExp)?;
        let exp_n = crt_mod_nn.prepare_exponent(ek.n());
        let exp_lambda = crt_mod_nn.prepare_exponent(&lambda);

        let (_ek, dk) = NGen::keys_with_primes(&utils::integer_to_bigint(p.clone()), &utils::integer_to_bigint(q.clone()), 2048).unwrap();
        

        Ok(Self {
            ek,
            lambda,
            mu: u,
            p,
            q,
            crt_mod_nn,
            exp_n,
            exp_lambda,
            optimized_dk: dk,
            optimized_ek: _ek,
        })
    }

    /// Decrypts the ciphertext, returns plaintext in `{-N/2, .., N_2}`
    pub fn decrypt(&self, c: &Ciphertext) -> Result<Plaintext, Error> {
        if !utils::in_mult_group(c, self.ek.nn()) {
            return Err(Reason::Decrypt.into());
        }
        let _c = RawCiphertext::new(utils::integer_to_bigint(c.clone()));
        let plaintext = OptimizedPaillier::decrypt(&self.optimized_dk, _c);
        let plaintext_integer = utils::bigint_to_integer(RawPlaintext::to_bigint(&plaintext.clone()));
        Ok(plaintext_integer)
    }

    /// Encrypts a plaintext `x` in `{-N/2, .., N/2}` with `nonce` from `Z*_n`
    ///
    /// It uses the fact that factorization of `N` is known to speed up encryption.
    ///
    /// Returns error if inputs are not in specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        if !self.ek.in_signed_group(x) || !utils::in_mult_group(nonce, self.n()) {
            return Err(Reason::Encrypt.into());
        }

        let plt_as_u64 = x.to_u64().ok_or(Reason::Encrypt)?;
        let ciphertext = OptimizedPaillier::encrypt(&self.optimized_ek, plt_as_u64);
        let ciphertext_integer = utils::bigint_to_integer(ciphertext.raw.clone());
        
        Ok(ciphertext_integer)
    }

    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}`
    ///
    /// It's uses the fact that factorization of `N` is known to speed up encryption.
    ///
    /// Nonce is sampled randomly using `rng`.
    ///
    /// Returns error if plaintext is not in specified range
    pub fn encrypt_with_random(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        x: &Plaintext,
    ) -> Result<(Ciphertext, Nonce), Error> {
        let nonce = utils::sample_in_mult_group(rng, self.ek.n());
        let ciphertext = self.encrypt_with(x, &nonce)?;
        Ok((ciphertext, nonce))
    }

    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// It uses the fact that factorization of `N` is known to speed up an operation.
    ///
    /// ```text
    /// omul(a, Enc(c)) = Enc(a * c)
    /// ```
    pub fn omul(&self, scalar: &Integer, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        if !utils::in_mult_group_abs(scalar, self.n())
            || !utils::in_mult_group(ciphertext, self.ek.nn())
        {
            return Err(Reason::Ops.into());
        }

        let scalar_bigint = utils::integer_to_bigint(scalar.clone());
        let ciphertext_raw = RawCiphertext::new(utils::integer_to_bigint(ciphertext.clone()));
        let result = self.optimized_dk.omul(&scalar_bigint, &ciphertext_raw);
        Ok(utils::bigint_to_integer(result.to_bigint()))
    }

    /// Returns a (public) encryption key corresponding to the (secret) decryption key
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.ek
    }

    /// The Paillier modulus
    pub fn n(&self) -> &Integer {
        self.ek.n()
    }

    /// The Paillier `lambda`
    pub fn lambda(&self) -> &Integer {
        &self.lambda
    }

    /// The Paillier `mu`
    pub fn mu(&self) -> &Integer {
        &self.mu
    }

    /// Prime `p`
    pub fn p(&self) -> &Integer {
        &self.p
    }
    /// Prime `q`
    pub fn q(&self) -> &Integer {
        &self.q
    }

    /// Bits length of smaller prime (`p` or `q`)
    pub fn bits_length(&self) -> u32 {
        self.p.significant_bits().min(self.q.significant_bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_dev::DevRng;

    fn setup() -> DecryptionKey {
        // Using two large primes for testing
        let p = Integer::from(15485863);
        let q = Integer::from(15485867);
        DecryptionKey::from_primes(p, q).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt() {
        let dk = setup();
        let mut rng = DevRng::new();
        let plaintext = Integer::from(5);
        
        let (ciphertext, _) = dk.encrypt_with_random(&mut rng, &plaintext).unwrap();
        let decrypted = dk.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_homomorphic_add() {
        let dk = setup();
        let ek = dk.encryption_key();
        let mut rng = DevRng::new();
        
        let p1 = Integer::from(3);
        let p2 = Integer::from(4);
        
        let (c1, _) = dk.encrypt_with_random(&mut rng, &p1).unwrap();
        let (c2, _) = dk.encrypt_with_random(&mut rng, &p2).unwrap();
        
        let c_sum = ek.oadd(&c1, &c2).unwrap();
        let decrypted = dk.decrypt(&c_sum).unwrap();
        assert_eq!(decrypted, p1 + p2);
    }

    #[test]
    fn test_homomorphic_mul() {
        let dk = setup();
        let mut rng = DevRng::new();
        
        let plaintext = Integer::from(5);
        let scalar = Integer::from(3);
        
        let (ciphertext, _) = dk.encrypt_with_random(&mut rng, &plaintext).unwrap();
        let result = dk.omul(&scalar, &ciphertext).unwrap();
        let decrypted = dk.decrypt(&result).unwrap();
        assert_eq!(decrypted, plaintext * scalar);
    }

    #[test]
    fn test_homomorphic_neg() {
        let dk = setup();
        let ek = dk.encryption_key();
        let mut rng = DevRng::new();
        
        let plaintext = Integer::from(5);
        let (ciphertext, _) = dk.encrypt_with_random(&mut rng, &plaintext).unwrap();
        
        let neg = ek.oneg(&ciphertext).unwrap();
        let decrypted = dk.decrypt(&neg).unwrap();
        assert_eq!(decrypted, -plaintext);
    }

    #[test]
    fn test_key_generation() {
        let mut rng = DevRng::new();
        let dk = DecryptionKey::generate(&mut rng).unwrap();
        
        // Test basic encryption/decryption with generated key
        let plaintext = Integer::from(42);
        let (ciphertext, _) = dk.encrypt_with_random(&mut rng, &plaintext).unwrap();
        let decrypted = dk.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
