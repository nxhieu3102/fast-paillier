use malachite::Integer;
use malachite_base::num::arithmetic::traits::Parity;
use malachite_base::num::basic::traits::{One, Zero};
use malachite_base::num::conversion::traits::FromStringBase;
use malachite_base::num::logic::traits::SignificantBits;
use rand_core::{CryptoRng, RngCore};

use crate::integer_ext::{mod_inverse_int, mod_pow_int};
use crate::{utils, AnyEncryptionKey, Bug, Ciphertext, EncryptionKey, Nonce, Plaintext};
use crate::{Error, Reason};

/// Paillier decryption key
#[derive(Clone, Debug)]
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
        self.p.significant_bits().min(self.q.significant_bits()) as u32
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
        let (p, q, alpha, n) = 'outer: loop {
            // Step 1: generate div_p, div_q, other_div_p, other_div_q
            // let div_p, div_q are (a_size/2)-bit odd PRIMES
            // let other_div_p, other_div_q are ((n_size - a_size)/2 - 1)-bit odd INTEGERS

            let div_p = utils::generate_safe_prime(rng, a_size / 2);
            let div_q = utils::generate_safe_prime(rng, a_size / 2);
            assert_eq!(div_p.significant_bits(), (a_size / 2) as u64);
            assert_eq!(div_q.significant_bits(), (a_size / 2) as u64);
            assert!(utils::is_prime(&div_p));
            assert!(utils::is_prime(&div_q));

            // TODO: do we need to check if alpha size is exactly a_size?
            // let temp_alpha = div_p.clone() * &div_q;
            // if temp_alpha.significant_bits() != a_size {
            //     // can not construct alpha of the right size
            //     println!("div_p * div_q size is not equal to a_size");
            //     continue 'outer;
            // }

            let mut max_loop = 100;
            'inner: loop {
                max_loop -= 1;
                if max_loop == 0 {
                    // Max loop reached
                    break 'inner;
                }

                let other_bit_length = (n_size - a_size) / 2 - 1;

                let other_div_p = utils::sample_odd_with_size(rng, other_bit_length);
                let other_div_q = utils::sample_odd_with_size(rng, other_bit_length);
                assert!(other_div_p.odd());
                assert!(other_div_q.odd());
                assert!(other_div_p.significant_bits() == other_bit_length as u64);
                assert!(other_div_q.significant_bits() == other_bit_length as u64);

                // Step 2: calculate p, q
                // p = 2 * div_p * other_div_p + 1
                // q = 2 * div_q * other_div_q + 1
                let p: Integer = Integer::from(2) * &div_p * &other_div_p + Integer::from(1);
                let q: Integer = Integer::from(2) * &div_q * &other_div_q + Integer::from(1);

                // Step 3: validate

                // TODO: do we need to check if n size is exactly n_size?
                // // validate p, q can construct n of the right size
                // let temp_n = p.clone() * &q;
                // if temp_n.significant_bits() != n_size {
                //     // can not construct n of the right size
                //     println!("p * q size is not equal to n_size");
                //     continue 'outer;
                // }

                // validate div_p, div_q, other_div_p, other_div_q are COPRIME
                if !utils::check_coprime(&[&div_p, &div_q, &other_div_p, &other_div_q]) {
                    // println!("div_p, div_q, other_div_p, other_div_q are not coprime");
                    continue 'inner;
                }

                // p, q are PRIMES
                if !(utils::is_prime(&p)) || !(utils::is_prime(&q)) {
                    // println!("p or q are not prime");
                    continue 'inner;
                }

                // Step 4: calculate alpha = div_p * div_q
                // n = p * q
                let alpha = div_p * div_q;
                let n = p.clone() * &q;

                break 'outer (p, q, alpha, n);
            }
        };

        // h = -y^(2*beta) mod n
        // where beta = (p - 1)(q - 1)/(4.alpha)
        // y is a random element of Z*_N

        let beta: Integer = (p.clone() - Integer::from(1)) * (q.clone() - Integer::from(1))
            / (Integer::from(4) * &alpha);
        let y = utils::sample_in_mult_group(rng, &n);
        let exponent = Integer::from(2) * &beta;
        let h = -mod_pow_int(&y, &exponent, &n);

        let ek = EncryptionKey::new(n_size, a_size, h, n)?;

        Ok(Self { ek, p, q, alpha })
    }

    /// Return a decryption key from the encryption key, p, q, alpha
    pub fn new(ek: EncryptionKey, p: Integer, q: Integer, alpha: Integer) -> Result<Self, Error> {
        // TODO: validate ek, p, q, alpha are valid

        Ok(Self { ek, p, q, alpha })
    }

    /// Return a fix decryptoion key for testing
    /// n size = 2048
    /// alpha size = 448
    pub fn sample_112() -> Self {
        Self {
            ek: EncryptionKey::sample_112(),
            p: Integer::from_string_base(16, "352b408f842f95ff7b042028afbd2a9312066e4e41d105e8ca2e162686c05908199e14805579c1a180aba9b20ec3e6d86e77be0cf0cc92212932606089bce6366a978b45e139d2b4abfa86e4fc198f3710d571988b39a050f0d0d857caabb74347d069c7f30d8a93db788abc1814caf5fd755df47391a8f350f85b1c522c7d5b").unwrap(),
            q: Integer::from_string_base(16, "ae553897573c0513948d2430f88e41120d9bfe9dacfcb0213bdb51c2880e388f5966d272cb97dd88666d2a921748ead1f787067f1c758f334a5ecefafb6afdbf3c0ffd2632d49d0448ef314d95c0b92711ebe1bc40b031e300f7cb2a78520e130446f7f4bc014253b47627dee93094c8907c67fe0681bc24ebfd57e5b241d95f").unwrap(),
            alpha: Integer::from_string_base(16, "7ffeabae28c7c128fab071c9f379387da9b8d4ce576c6f5af837d676a89109b7461ea3376a52b5a38ffcd40eb55dab3478b5fe94579512e9").unwrap(),
        }
    }

    /// Return a fix decryptoion key for testing
    /// n size = 3072
    /// alpha size = 512
    pub fn sample_128() -> Self {
        Self {
            ek: EncryptionKey::sample_128(),
            p: Integer::from_string_base(10, "839604457153382033720003326654997544118596113373609234678587338149161354994347914267636071525512710050467656632783964681190975719416301416318441172804941007905632800346097169656312745185266337930499545855863665404948257291631593104963187840014286605100283580915042595051907308234079655979670315278879818661888922549182364361303144823692211219484740422088705064262682566575832813433144012908049224984636749169319450779863173356117467976440703403995243646456725591").unwrap(),
            q: Integer::from_string_base(10, "743801265514881103483768821893245925378134035335216611973520259829027656422723219709692160610663116273054702837694488638022069484892336461456218827736375462047842812789380167552340656549341374717474433671272564983828365484016261471809658880542451263854116138619518659990303082479785471490469802954931219698744200396168471293146272351181923597139787506343883140313058926610440737746588145351090170254693560055414792516210777763575309516717116560514389624057706987").unwrap(),
            alpha: Integer::from_string_base(10, "4741906189692490942881550526551134583945588334769176626212802369003989678803877719143415897043820272564409651596590439168843375671085094013575119097115737").unwrap(),
        }
    }
}

impl DecryptionKey {
    /// Decrypts the ciphertext, returns plaintext in `{-N/2, .., N_2}`
    ///
    /// plaintext = L(c^(2*alpha) mod N^2, N) * (2*alpha)^{-1} mod N
    /// where: L(u, N) = (u - 1) / N (mod)
    pub fn decrypt(&self, c: &Ciphertext) -> Result<Plaintext, Error> {
        let two_alpha = Integer::from(2) * &self.alpha;

        // L(c^(2*alpha) mod N^2, N)
        let u = mod_pow_int(c, &two_alpha, self.nn());
        // TODO: do we need to check u % N^2 == 1?
        // assert_eq!(u.clone() % self.nn(), Integer::from(1);

        let l = (u - Integer::from(1)) / self.n();

        // (2 * alpha)^{-1} mod N
        let two_alpha_inv =
            mod_inverse_int(&two_alpha, self.n()).ok_or(Error(Reason::Bug(Bug::InvertUndef)))?;

        // plaintext = L(c^(2*alpha) mod N^2, N) * (2*alpha)^{-1} mod N
        let plaintext = l * &two_alpha_inv % self.n();

        // make sure plaintext is positive
        if plaintext > *self.half_n() {
            Ok(plaintext - self.n())
        } else {
            Ok(plaintext)
        }
    }

    /// Encrypts a plaintext `x` in `{-N/2, .., N/2}` with `nonce` from `Z*_n`
    ///
    /// It uses the fact that factorization of `N` is known to speed up encryption.
    ///
    /// Returns error if inputs are not in specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        // TODO: encrypt using Chinese Remainder Theorem

        self.ek
            .encrypt_with(x, nonce)
            .map_err(|_| Error(Reason::Bug(Bug::PowModUndef)))
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
        // TODO: encrypt using Chinese Remainder Theorem

        self.ek
            .encrypt_with_random(rng, x)
            .map_err(|_| Error(Reason::Bug(Bug::PowModUndef)))
    }

    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// It uses the fact that factorization of `N` is known to speed up an operation.
    ///
    /// ```text
    /// omul(a, Enc(c)) = Enc(a * c)
    /// ```
    pub fn omul(&self, scalar: &Integer, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        // TODO: omul using Chinese Remainder Theorem

        self.ek.omul(scalar, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use malachite::Integer;

    use crate::decryption_key::DecryptionKey;

    #[test]
    fn test_sample_decryption_key_112() {
        let dk = DecryptionKey::sample_112();

        assert_eq!(dk.p().clone() % Integer::from(4), Integer::from(3));
        assert_eq!(dk.q().clone() % Integer::from(4), Integer::from(3));
    }

    #[test]
    fn test_sample_decryption_key_128() {
        let dk = DecryptionKey::sample_128();

        assert_eq!(dk.p().clone() % Integer::from(4), Integer::from(3));
        assert_eq!(dk.q().clone() % Integer::from(4), Integer::from(3));
    }
}
