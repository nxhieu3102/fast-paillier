use rand_core::{CryptoRng, RngCore};
use rug::{Complete, Integer};

use crate::{utils, Ciphertext, Nonce, Plaintext};
use crate::{Bug, Error, Reason};

/// Paillier encryption key
#[derive(Clone, Debug)]
pub struct EncryptionKey {
    /// n size (number bits of n)
    n_size: u32,

    /// alpha size in decryption key
    a_size: u32,

    /// nounce (random) in encryption have size 2*a_size
    nounce_size: u32,

    /// generator of nounce space (G)
    /// h = -y^(2*beta) mod n
    h: Integer,

    /// n = q * p (q,p are primes)
    n: Integer,

    /// nn = n * n
    /// modulo in Paillier scheme
    nn: Integer,

    /// h_pow_n = (h^n) mod nn
    /// a constant in encryption
    h_pow_n: Integer,

    /// half_n = n / 2
    /// use in validate plaintext (-n/2 <= p <= n/2)
    half_n: Integer,

    /// neg_half_n = - (n / 2)
    /// use in validate plaintext (-n/2 <= p <= n/2)
    neg_half_n: Integer,
}

impl EncryptionKey {
    /// Constructs an encryption key
    pub fn new(n_size: u32, a_size: u32, h: Integer, n: Integer) -> Result<Self, Error> {
        let nounce_size = a_size * 2;
        let nn = n.clone() * &n;
        let half_n = n.clone() >> 1u32;
        let neg_half_n = -half_n.clone();
        let h_pow_n = h.clone().pow_mod(&n, &nn).map_err(|_| Bug::PowModUndef)?;

        Ok(Self {
            n_size,
            a_size,
            nounce_size,
            h,
            n,
            nn,
            h_pow_n,
            half_n,
            neg_half_n,
        })
    }

    /// Returns `n_size`
    pub fn n_size(&self) -> u32 {
        self.n_size
    }

    /// Returns `a_size`
    pub fn a_size(&self) -> u32 {
        self.a_size
    }

    /// Returns `nounce_size`
    pub fn nounce_size(&self) -> u32 {
        self.nounce_size
    }

    /// Returns `h`
    pub fn h(&self) -> &Integer {
        &self.h
    }

    /// Returns `N`
    pub fn n(&self) -> &Integer {
        &self.n
    }

    /// Returns `N^2`
    pub fn nn(&self) -> &Integer {
        &self.nn
    }

    /// Returns `h^N mod N^2`
    pub fn h_pow_n(&self) -> &Integer {
        &self.h_pow_n
    }

    /// Returns `N/2`
    pub fn half_n(&self) -> &Integer {
        &self.half_n
    }

    /// Returns `-N/2`
    pub fn neg_half_n(&self) -> &Integer {
        &self.neg_half_n
    }
}

impl EncryptionKey {
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

        let x = if x.cmp0().is_ge() {
            x.clone()
        } else {
            (x + self.n()).complete()
        };

        // a = (1 + N)^x mod N^2 = (1 + xN) mod N^2
        let a = (Integer::ONE + (&x * self.n()).complete()) % self.nn();
        // b = nonce^N mod N^2
        let b = nonce
            .clone()
            .pow_mod(self.n(), self.nn())
            .map_err(|_| Bug::PowModUndef)?;

        let c = (a * b).modulo(self.nn());
        Ok(c)
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
        Ok((c1 * c2).complete() % self.nn())
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
        let c2 = self.oneg(c2)?;
        Ok((c1 * c2) % self.nn())
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

        Ok(ciphertext
            .pow_mod_ref(scalar, self.nn())
            .ok_or(Reason::Ops)?
            .into())
    }

    /// Homomorphic negation of a ciphertext
    ///
    /// ```text
    /// oneg(Enc(a)) = Enc(-a)
    /// ```
    pub fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        Ok(ciphertext.invert_ref(self.nn()).ok_or(Reason::Ops)?.into())
    }

    /// Checks whether `x` is `{-N/2, .., N/2}`
    pub fn in_signed_group(&self, x: &Integer) -> bool {
        self.neg_half_n <= *x && *x <= self.half_n
    }
}
