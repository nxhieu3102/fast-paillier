use rand_core::{CryptoRng, RngCore};
use rug::{Complete, Integer};

use crate::{utils, Ciphertext, Nonce, Plaintext};
use crate::{Bug, Error, Reason};
use crate::precomputed_table::PrecomputeTable;
// use crate::utils;
/// Paillier encryption key
#[derive(Clone, Debug)]
pub struct EncryptionKey {
    /// n size (number bits of n)
    n_size: u32,

    /// alpha size in decryption key
    a_size: u32,

    /// nounce (random) in encryption have size a_size (follow the paper)
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
        let nounce_size = a_size;
        let nn = n.clone() * &n;
        let half_n: Integer = n.clone() >> 1u32;
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

    /// Sample a default encryption key for testing
    pub fn sample() -> Self {
        let n_size = 2048;
        let a_size = 448;
        let h = Integer::from_str_radix("1c5e08d902e681c9bc7e915aa58ba4e5b67d7cd4a20d07253bb486d3cf0c9c4eb05f28fac0b30bce24b2502592ec06f206f07d298676e655b2a47575750f177ba05ca985900c053716cb41595ae7b6b90e2473d04f8ee0300e9441dba1e53fc26795e4e099a983fbfcc118390112c2fe2cb1e9a4ea3b32a6a458ae6a2a22d89d7f6a8ace29cc1c8bdb0babb7d8d85de58e3c0c5eae53fe638bf34b7b2aef251fd12e42d8c8498e29907205ec0e8520a508ab7f76ddb8b971d7ba7f92f4ecf074f5eced4a0fb0ee842707b0ba8fb8615dd5a67d7543b5c7c82a3df778c4a14082153e64842e97c3956d66af26dedf499343e992efae9283ae5a1aa9f939edfffe", 16).unwrap();
        let n = Integer::from_str_radix("243518fee03fdf73a53413db4bd932ec13f07bd48bd815274f3571caa06c9b691dcb95779cbcd2fa844d04b6104c79d510782e9da665e9dd6b544169ed5ea23dba3a07c404a3469d1e4a7759987d75d03023ec87ee1c245402c1a9cae0c64dbc5d2cd8faec558aa981c09a29df4cd9725eb523181dc854ada7f9d137c7452f0115fee48c03308d58c6e87dd93cf1fde5850f6317a0eea6c822fa9485a3f610aae8353c237fd0fcb21e7e2b3de72bab897e37c4fd3b53a89960b546a31beff7466b2abe7a3a32795fe52f8146a28c1bdc659a44c6e2b73061a077945c6b26eb6d43a3a48c291cd39903e6ba29a169128743d0935cd60fd26f710dad064edfa7c5", 16).unwrap();

        Self::new(n_size, a_size, h, n).unwrap()
    }

    /// Returns `n_size`
    pub(crate) fn n_size(&self) -> u32 {
        self.n_size
    }

    /// Returns `a_size`
    pub(crate) fn a_size(&self) -> u32 {
        self.a_size
    }

    /// Returns `nounce_size`
    pub(crate) fn nounce_size(&self) -> u32 {
        self.nounce_size
    }

    /// Returns `h`
    pub(crate) fn h(&self) -> &Integer {
        &self.h
    }

    /// Returns `N`
    pub(crate) fn n(&self) -> &Integer {
        &self.n
    }

    /// Returns `N^2`
    pub(crate) fn nn(&self) -> &Integer {
        &self.nn
    }

    /// Returns `h^N mod N^2`
    pub(crate) fn h_pow_n(&self) -> &Integer {
        &self.h_pow_n
    }

    /// Returns `N/2`
    pub(crate) fn half_n(&self) -> &Integer {
        &self.half_n
    }

    /// Returns `-N/2`
    pub(crate) fn neg_half_n(&self) -> &Integer {
        &self.neg_half_n
    }
}

impl EncryptionKey {
    /// Checks whether `x` is `{-N/2, .., N/2}`
    pub fn in_signed_group(&self, x: &Integer) -> bool {
        self.neg_half_n <= *x && *x <= self.half_n
    }
}

impl EncryptionKey {
    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}` with `nonce` in `{0,1}^nounce_size`
    /// regard nounce as an integer in Z naturally
    ///
    /// Encrypt: Enc(x) = (1 + N)^x.(h^r mod N)^N mod N^2
    ///                 = (1 + x.N).(h^N mod N^2)^r mod N^2
    ///                 = (1 + x.N).h_pow_n^r mod N^2 (h_pow_n = h^N mod N^2)
    ///
    /// Returns error if inputs are not in specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        // Check plaintext is in signed group
        if !self.in_signed_group(x) {
            return Err(Reason::Encrypt.into());
        }

        // Make x positive
        let x = if x.cmp0().is_ge() {
            x.clone()
        } else {
            (x + self.n()).complete()
        };

        // a = (1 + N)^x mod N^2 = (1 + xN) mod N^2
        let a = (Integer::from(1) + (&x * self.n()).complete()) % self.nn();
        // b = (h^nonce mod N)^N mod N^2 = (h^n mod N^2)^nonce mod N^2 = h_pow_n^nonce mod N^2
        let b = self
            .h_pow_n()
            .clone()
            .pow_mod(nonce, self.nn())
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
        let nonce = utils::sample_with_size(rng, self.nounce_size());
        let ciphertext = self.encrypt_with(x, &nonce)?;
        Ok((ciphertext, nonce))
    }
}

impl EncryptionKey {
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
}

impl EncryptionKey {
    /// Encrypts the plaintext using a precomputed table for faster exponentiation
    pub fn encrypt_with_precompute_table(&self, precompute_table: &PrecomputeTable, m: &Plaintext) -> Result<Ciphertext, Error> {
        let r = utils::sample_with_size(&mut rand_core::OsRng, self.nounce_size());
         // rn = hn^r (mod n^2)
        // use Self::pow() instead of BigInt::mod_pow()
        // so, we replace `let rn = BigInt::mod_pow(&ek.hn, &r.0, &ek.nn);` by
        let rn = Self::pow(precompute_table, &r);

        // gm = (1 + m*n) (mod n^2)
        let gm = ((m * &self.n).complete() + 1) % &self.nn;

        let c = (gm * rn) % &self.nn;
        Ok(c)
    }

    fn pow(precompute_table: &PrecomputeTable, pow: &Integer) -> Integer {
        let pow_blocks = Self::convert_into_block(&precompute_table, &pow);
        let mut result = Integer::from(1);

        for (id, pow_block) in pow_blocks.iter().enumerate() {
            result = (result * &precompute_table.table()[id][*pow_block]).modulo(&precompute_table.modulo());
        }

        result
    }

    fn convert_into_block(precompute_table: &PrecomputeTable, x: &Integer) -> Vec<usize> {
        // convert bigint --> list of bits
        // block_size bits --> group (right to left)
        // each group --> usize/u64/...
        let block_size = precompute_table.block_size();
        let pow_size = precompute_table.pow_size();
        let num_block = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };

        let mut result = vec![0; num_block];

        for bit_id in 0..pow_size {
            if x.get_bit(bit_id as u32) {
                // bit_id in is the (bit_id % block_size) bit of group (bit_id / block_size)
                // turn on the (bit_id % block_size) bit of group (bit_id / block_size)
                let block_id = bit_id / block_size;
                let bit_id = bit_id % block_size;
                result[block_id] |= 1 << bit_id;
            }
        }

        result
    }
}
