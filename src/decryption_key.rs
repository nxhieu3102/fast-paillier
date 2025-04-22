use rand_core::{CryptoRng, RngCore};
use rug::Integer;

use crate::Error;
use crate::{utils, Bug, Ciphertext, EncryptionKey, Nonce, Plaintext};

/// Paillier decryption key
#[derive(Clone)]
pub struct DecryptionKey {
    /// encryption key
    ek: EncryptionKey,

    /// prime (n = p * q)
    p: Integer,
    /// prime (n = p * q)
    q: Integer,

    /// (p-1)(q-1)/4 mod alpha = 0
    alpha: Integer,
}

impl DecryptionKey {
    /// Returns a (public) encryption key corresponding to the (secret) decryption key
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.ek
    }

    /// The Paillier modulus
    pub fn n(&self) -> &Integer {
        self.ek.n()
    }

    /// Prime `p`
    pub fn p(&self) -> &Integer {
        &self.p
    }
    /// Prime `q`
    pub fn q(&self) -> &Integer {
        &self.q
    }

    /// alpha | (p - 1)(q - 1)/4
    pub fn alpha(&self) -> &Integer {
        &self.alpha
    }

    /// Bits length of smaller prime (`p` or `q`)
    pub fn bits_length(&self) -> u32 {
        self.p.significant_bits().min(self.q.significant_bits())
    }
}

impl DecryptionKey {
    /// Generates a paillier key
    ///
    /// QR_N: set of all quadratic residues in Z*_N
    /// QR_N = {x^2 mod N | x in Z*_N}
    ///
    /// N = Q * P
    /// Then, QR_N is a cyclic group of order phi(N)/4 = (P -1)(Q - 1)/4
    ///
    /// If: alpha * beta = (P - 1)(Q - 1)/4
    /// QR_N = QR^alpha_N * QR^beta_N
    /// QR^alpha_N = {x^(2.alpha) mod N | x in Z*_N} of size beta
    /// QR^beta_N  = {x^(2.beta)  mod N | x in Z*_N} of size alpha
    ///
    /// Random space: G = QR^beta_N * <-1> of Z*_N, cyclic group of order 2.alpha
    /// h is a generator of G -> h^(2.alpha) = 1 mod N
    /// We can chose: h = -y^(2*beta) mod N, where y is a random element of Z*_N
    ///
    /// Requirements:
    /// div_p | (p -1)
    /// div_q | (q -1)
    /// p = q = 3 (mod 4)
    /// gcd(p - 1, q - 1) = 2
    /// gcd(div_p.div_q, (p - 1)(q - 1)/4) = 1
    ///
    /// Then:
    /// alpha = div_p * div_q
    /// beta = (p - 1)(q - 1)/(4.alpha)
    /// n = p * q
    /// h = - y^(2*beta) mod n
    pub fn generate(
        rng: &mut (impl RngCore + CryptoRng),
        n_size: u32,
        a_size: u32,
    ) -> Result<Self, Error> {
        let mut count = 0;
        let (p, q, alpha) = loop {
            count += 1;
            println!("-------------- Loop #{count:}");

            // Step 1: generate div_p, div_q, other_div_p, other_div_q
            // let div_p, div_q are (a_size/2)-bit odd PRIMES
            // let other_div_p, other_div_q are ((n_size - a_size)/2 - 1)-bit odd INTEGERS

            println!("Generating div_p, div_q");
            // TODO: check the performance of `generate_safe_prime`
            let div_p = utils::generate_safe_prime(rng, a_size / 2);
            let div_q = utils::generate_safe_prime(rng, a_size / 2);

            println!("Generating other_div_p, other_div_q");
            let other_bit_length = (n_size - a_size) / 2 - 1;
            let other_div_p = utils::sample_odd_with_size(rng, other_bit_length);
            let other_div_q = utils::sample_odd_with_size(rng, other_bit_length);

            // Step 2: calculate p, q
            // p = 2 * div_p * other_div_p + 1
            // q = 2 * div_q * other_div_q + 1
            println!("Calculating p, q");
            let p: Integer = Integer::from(2) * &div_p * &other_div_p + 1;
            let q: Integer = Integer::from(2) * &div_q * &other_div_q + 1;

            // Step 3: validate q, p
            // p, q are PRIMES
            // p, q, div_p, div_q are COPRIME
            println!("Validating p, q");
            if !(utils::is_safe_prime(&p)) || !(utils::is_safe_prime(&q)) {
                continue;
            }

            println!("Validating coprime");
            if !utils::check_coprime(&[&div_p, &div_q, &other_div_p, &other_div_q]) {
                continue;
            }

            // Step 4: calculate alpha = div_p * div_q
            println!("Calculating alpha");
            let alpha = div_p * div_q;

            println!("Random success");
            break (p, q, alpha);
        };

        println!("COUNT = {}", count);

        // n = p * q
        println!("Calculating n");
        let n = p.clone() * &q;

        // h = -y^(2*beta) mod n
        // where beta = (p - 1)(q - 1)/(4.alpha)
        // y is a random element of Z*_N

        println!("Calculating h");
        let beta: Integer = (p.clone() - 1) * (q.clone() - 1) / (Integer::from(4) * &alpha);
        let y = utils::sample_in_mult_group(rng, &n);
        let h = -y
            .pow_mod(&(Integer::from(2) * &beta), &n)
            .map_err(|_| Bug::PowModUndef)?;

        println!("Calculating encryption key");
        let ek = EncryptionKey::new(n_size, a_size, h, n)?;

        println!("Decryption key generated");
        Ok(Self { ek, p, q, alpha })
    }
}

impl DecryptionKey {
    /// Decrypts the ciphertext, returns plaintext in `{-N/2, .., N_2}`
    pub fn decrypt(&self, c: &Ciphertext) -> Result<Plaintext, Error> {
        todo!()
    }

    /// Encrypts a plaintext `x` in `{-N/2, .., N/2}` with `nonce` from `Z*_n`
    ///
    /// It uses the fact that factorization of `N` is known to speed up encryption.
    ///
    /// Returns error if inputs are not in specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        todo!()
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
        todo!()
    }

    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// It uses the fact that factorization of `N` is known to speed up an operation.
    ///
    /// ```text
    /// omul(a, Enc(c)) = Enc(a * c)
    /// ```
    pub fn omul(&self, scalar: &Integer, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use rug::Integer;

    use crate::decryption_key::DecryptionKey;

    #[test]
    fn test_decryption_key() {
        println!("test_decryption_key");

        let mut rng = rand::thread_rng();
        // let n_size = 2048;
        // let a_size = 448;
        let n_size = 15;
        let a_size = 10;

        let dk = DecryptionKey::generate(&mut rng, n_size, a_size).unwrap();

        assert_eq!(dk.bits_length(), a_size / 2);
        assert_eq!(dk.p().significant_bits(), dk.q().significant_bits());
        assert_eq!(dk.p().clone() % 4, Integer::from(3));
        assert_eq!(dk.q().clone() % 4, Integer::from(3));
    }
}
