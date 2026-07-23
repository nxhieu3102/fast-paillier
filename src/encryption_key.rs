use crate::common::BigIntExt;
use crate::precomputed_table::PrecomputeTable;
use crate::{utils, Ciphertext, Nonce, Plaintext};
use crate::{Error, Reason};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Num;
use num_traits::One;
use num_traits::Zero;
use rand_core::{CryptoRng, RngCore};
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
    h: BigInt,

    /// n = q * p (q,p are primes)
    n: BigInt,

    /// nn = n * n
    /// modulo in Paillier scheme
    nn: BigInt,

    /// h_pow_n = (h^n) mod nn
    /// a constant in encryption
    h_pow_n: BigInt,

    /// half_n = n / 2
    /// use in validate plaintext (-n/2 <= p <= n/2)
    half_n: BigInt,

    /// neg_half_n = - (n / 2)
    /// use in validate plaintext (-n/2 <= p <= n/2)
    neg_half_n: BigInt,
}

impl EncryptionKey {
    /// Constructs an encryption key
    pub fn new(n_size: u32, a_size: u32, h: BigInt, n: BigInt) -> Result<Self, Error> {
        let nounce_size = a_size;
        let nn = n.clone() * &n;
        let half_n = n.clone() >> 1u32;
        let neg_half_n = -half_n.clone();
        let h_pow_n = h
            .clone()
            .modpow_ext(&n, &nn)
            .ok_or(Error(Reason::InvalidPowMod))?;

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
    /// Security level (kappa) = 112
    pub fn sample_112() -> Self {
        let n_size = 2048;
        let a_size = 448;
        let h = BigInt::from_str_radix("1c5e08d902e681c9bc7e915aa58ba4e5b67d7cd4a20d07253bb486d3cf0c9c4eb05f28fac0b30bce24b2502592ec06f206f07d298676e655b2a47575750f177ba05ca985900c053716cb41595ae7b6b90e2473d04f8ee0300e9441dba1e53fc26795e4e099a983fbfcc118390112c2fe2cb1e9a4ea3b32a6a458ae6a2a22d89d7f6a8ace29cc1c8bdb0babb7d8d85de58e3c0c5eae53fe638bf34b7b2aef251fd12e42d8c8498e29907205ec0e8520a508ab7f76ddb8b971d7ba7f92f4ecf074f5eced4a0fb0ee842707b0ba8fb8615dd5a67d7543b5c7c82a3df778c4a14082153e64842e97c3956d66af26dedf499343e992efae9283ae5a1aa9f939edfffe", 16).unwrap();
        let n = BigInt::from_str_radix("243518fee03fdf73a53413db4bd932ec13f07bd48bd815274f3571caa06c9b691dcb95779cbcd2fa844d04b6104c79d510782e9da665e9dd6b544169ed5ea23dba3a07c404a3469d1e4a7759987d75d03023ec87ee1c245402c1a9cae0c64dbc5d2cd8faec558aa981c09a29df4cd9725eb523181dc854ada7f9d137c7452f0115fee48c03308d58c6e87dd93cf1fde5850f6317a0eea6c822fa9485a3f610aae8353c237fd0fcb21e7e2b3de72bab897e37c4fd3b53a89960b546a31beff7466b2abe7a3a32795fe52f8146a28c1bdc659a44c6e2b73061a077945c6b26eb6d43a3a48c291cd39903e6ba29a169128743d0935cd60fd26f710dad064edfa7c5", 16).unwrap();

        Self::new(n_size, a_size, h, n).unwrap()
    }

    /// Sample a default encryption key for testing
    /// Security level (kappa) = 128
    pub fn sample_128() -> Self {
        let n_size = 3072;
        let a_size = 512;
        let h = BigInt::from_str_radix("-46118646770832830045641315635057147415619452896408495725084525515631763498419217092239007240481104785951515106141330780184017724711354754878105138981527814046713442701173158787961318701138213050689131500547667287835057808777090201233823259693317234765298199512393795028689399638011557338811405434847285549626923699588499355369100778944461335938055933338208588737362787471904613721909499495052563847250494605740519245116885721410290558409599017491571221814391229137726330359398608150289466563711537032436971344700037076458377527561048872725835181683669452128606967411636366306264582886347600341878183021479279996250977820902830628786961783055120959326713538614909410942862567628149824740864114037208934860868056544040342709335908500229136286989784554496443156132704420811055403006822848620991994750093609373760282848220484869564427940530240476784686626726481501299422807761209664211819557525909377117754524995670714798106228", 10).unwrap();
        let n = BigInt::from_str_radix("624498857762620325098235170965743800775986411638861818063975567416457548620626106589775762742147050332061040035988343327949848344781895647064874621111687462752351420252191016556563422405065857493565714223369457326132905751097688764312209576092608940344112195727294420580004446885734418485854984933721637793585572313379454462372823080364186214267829274487061982469987426935994509566980637443218966350207542793855595534878529696726480414810101468713027596090923530806002617542180788766147785236740591484455822141732077626477810969339706966842770784842141574665525282473888631304800798834440140046529558448816002513160409692564156284555087902686772224299491823502624123052301570848969169650127973801617496811923093923613174646328722924361659936987353289043665636098196190290386284750432940209381911182951746612131658041398132442860120556913619042902264243188841994871986844780749268847877605077940655376360242193578643742404317", 10).unwrap();

        Self::new(n_size, a_size, h, n).unwrap()
    }

    /// Sample another default encryption key for testing
    /// Security level (kappa) = 128
    pub fn sample_other_128() -> Self {
        let n_size = 3072;
        let a_size = 512;
        let h = BigInt::from_str_radix("-238268e4f0068befb247206cb393feec56046c7f3d347c080ffb1b2a8821c932e2aa150c36586fa060f2d35024487179427f17b8d92d979ae051ec45302c33beb4d7ce7bb9ff6dc807fc9993a4449c00af55789e0a500bcaf0d011d16cd2b784ed21e52fa8424565d91b2848f7be6ecd2d2d8c42a4299221ea1fccf486a19b844bba31e3224a341e625151e751b435a376eb64df69223003a5188cc9d8675e45c8a004258e296552ad50d017719e16ea225f073eab2b1abcccc22b592b40a204868ad020d7294bca1360cdea97da59765b03baf97e856f2bef986f88e56c75dd54dadcd1f71aae5cb25edfcc78ec175a3cd554f9ba6d125da80a3ae2b135bb061c31451463234ac217f3e642a2eb5b5869a4285f9ab442f8aef3efdb20ce9ae954968c9a1174a031e93b30c295e8f385f3e6654385b8f0d9706ad8879f6555f85d0b4b78942f65ccebdcd6405666e5e5488761e87c5babe9b60dd50923ed9073d45802d5be7116ab4ef74e46018d7142d2cb3be5e385a32f85c94b24d430ccee", 16).unwrap();
        let n = BigInt::from_str_radix("2f3fb34b2019f8046dea612a987751e756d9a16b9f1a524943a3cc756e3a85c039c44a8e92e105f7d65d4208fa9fd464ad870168e6a868d8e36263bfea05c3e0e6175ccb6686b5c1379da4259e695c46f0c0138474bf1ef67320b521154aaccc8489e4cccbd81fb8e3a7f274c8dffe03fc0d81935db916d7065b738a1e233d013caa4cd94b83a27cbfbba80997fba751ae9da403f53e9f4dbc894c3c813e4fb529805483ca45f5239e6d8119d95179e0ca8e16a166dc849d4f3691de2695eafe59d6ac0b9ac14a4bee2d60325f77485cb41e0f06883901190032cc0f08a83699715a6c71efe501ab366c270ff91cfae3169bee3b7c21169fd8293c9fc95e4565c2322e55cf8767fae0142aaf57fe1951b3ff95be14ce4b273a42c6b6e6e1a278010e59f1a28e07ef4ae0b9a0a8ac4c02c536565f5f007bb585a3f3a1ed2b641976f3dadb4465ea46150dab90dc38faaa362e8bc3dd6adfc1db60959b624092a48a6caeaf6aeb24fe76252a17b27694c99bc690bebd4bfd6c742f4e1c9eec239d", 16).unwrap();

        Self::new(n_size, a_size, h, n).unwrap()
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
    pub fn h(&self) -> &BigInt {
        &self.h
    }

    /// Returns `N`
    pub fn n(&self) -> &BigInt {
        &self.n
    }

    /// Returns `N^2`
    pub fn nn(&self) -> &BigInt {
        &self.nn
    }

    /// Returns `h^N mod N^2`
    pub fn h_pow_n(&self) -> &BigInt {
        &self.h_pow_n
    }

    /// Returns `N/2`
    pub fn half_n(&self) -> &BigInt {
        &self.half_n
    }

    /// Returns `-N/2`
    pub fn neg_half_n(&self) -> &BigInt {
        &self.neg_half_n
    }
}

impl EncryptionKey {
    /// Checks whether `x` is `{-N/2, .., N/2}`
    pub fn in_signed_group(&self, x: &BigInt) -> bool {
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

        // assert_eq!(self.nounce_size(), nonce.bits() as u32, "nonce size is not correct");

        if !self.in_signed_group(x) {
            println!("error in in_signed_group");
            return Err(Reason::Encrypt.into());
        }

        // Make x positive
        let x = if *x > BigInt::ZERO {
            x.clone()
        } else {
            x + self.n()
        };

        // a = (1 + N)^x mod N^2 = (1 + xN) mod N^2
        let a = (BigInt::one() + (&x * self.n())).mod_floor(self.nn());
        // b = (h^nonce mod N)^N mod N^2 = (h^n mod N^2)^nonce mod N^2 = h_pow_n^nonce mod N^2
        let b: BigInt = self
            .h_pow_n()
            .clone()
            .modpow_ext(nonce, self.nn())
            .ok_or(Error(Reason::InvalidPowMod))?;

        let c = (a * b).mod_floor(self.nn());
        assert!(
            utils::in_mult_group(&c, self.nn()),
            "Ciphertext is not in the multiplicative group"
        );
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

        println!("c1: {:?}, c2: {:?}, nn: {:?}", c1, c2, self.nn());

        Ok((c1 * c2).mod_floor(self.nn()))
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
        Ok((c1 * c2).mod_floor(self.nn()))
    }

    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// ```text
    /// omul(a, Enc(c)) = Enc(a * c)
    /// ```
    pub fn omul(&self, scalar: &BigInt, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        // Handle zero scalar case: ciphertext^0 = 1 (identity element)
        if scalar.is_zero() {
            if !utils::in_mult_group(ciphertext, self.nn()) {
                return Err(Reason::Ops.into());
            }
            return Ok(BigInt::from(1));
        }
        
        if !utils::in_mult_group_abs(scalar, self.n())
            || !utils::in_mult_group(ciphertext, self.nn())
        {
            return Err(Reason::Ops.into());
        }

        println!("omul: scalar: {:?}, ciphertext: {:?}, nn: {:?}", scalar, ciphertext, self.nn());

        ciphertext
            .modpow_ext(scalar, self.nn())
            .ok_or(Error(Reason::Ops))
    }

    /// Homomorphic negation of a ciphertext
    ///
    /// ```text
    /// oneg(Enc(a)) = Enc(-a)
    /// ```
    pub fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        Ok(ciphertext.modinv(self.nn()).ok_or(Reason::Ops)?)
    }
}

impl EncryptionKey {
    /// Encrypts the plaintext using a precomputed table for faster exponentiation
    pub fn encrypt_with_precompute_table(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        precompute_table: &PrecomputeTable,
        m: &Plaintext,
        nonce: Option<&Nonce>,
    ) -> Result<Ciphertext, Error> {
        let r = match nonce {
            Some(nonce) => nonce,
            None => &utils::sample_with_size(rng, self.nounce_size()),
        };
        println!("nonce: {:?}, r: {:?}", nonce, r);
        assert_eq!(
            precompute_table.pow_size(),
            r.bits() as usize,
            "nonce size is not correct"
        );

        // h_pow_rn = (h^n)^r = h^(n*r) mod n^2
        let h_pow_rn = Self::pow(precompute_table, &r);

        assert_eq!(
            self.h_pow_n().modpow_ext(&r, self.nn()).unwrap(),
            h_pow_rn,
            "h_pow_rn is not correct"
        );

        // g_pow_m = g^m = (1 + n) ^ m = (1 + n * m) mod n^2
        let g_pow_m = ((m * &self.n) + BigInt::from(1)).mod_floor(&self.nn);

        assert_eq!(
            g_pow_m,
            (BigInt::from(1) + (m * &self.n)).mod_floor(&self.nn),
            "g_pow_m is not correct"
        );

        let c = (g_pow_m * h_pow_rn).mod_floor(&self.nn);
        assert!(
            utils::in_mult_group(&c, self.nn()),
            "Ciphertext is not in the multiplicative group"
        );

        Ok(c)
    }

    fn pow(precompute_table: &PrecomputeTable, pow: &BigInt) -> BigInt {
        let pow_blocks = Self::convert_into_blocks(precompute_table, pow);
        let mut result = BigInt::from(1);

        for (id, pow_block) in pow_blocks.iter().enumerate() {
            result = (result * &precompute_table.table()[id][*pow_block])
                .mod_floor(precompute_table.modulo());
        }

        result.mod_floor(precompute_table.modulo())
    }

    fn convert_into_blocks(precompute_table: &PrecomputeTable, x: &BigInt) -> Vec<usize> {
        // convert bigint --> list of bits
        // block_size bits --> group (right to left)
        // each group --> usize/u64/...
        let block_size = precompute_table.block_size();
        let pow_size = precompute_table.pow_size();
        let num_block = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };

        let mut result = vec![0; num_block];

        for bit_id in 0..pow_size {
            if x.bit(bit_id as u64) {
                // bit_id in is the (bit_id.mod_floor(block_size) bit of group (bit_id / block_size)
                // turn on the (bit_id.mod_floor(block_size) bit of group (bit_id / block_size)
                let block_id = bit_id / block_size;
                let bit_id = bit_id % block_size;
                result[block_id] |= 1 << bit_id;
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecryptionKey;
    use num_bigint::RandBigInt;
    use num_traits::Zero;
    use rand::thread_rng;

    #[test]
    fn test_omul_basic() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test basic multiplication
        let plaintext = BigInt::from(42);
        let scalar = BigInt::from(7);
        let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        
        let result_ciphertext = ek.omul(&scalar, &ciphertext).unwrap();
        let result_plaintext = dk.decrypt(&result_ciphertext).unwrap();
        
        assert_eq!(result_plaintext, plaintext * scalar);
    }

    #[test]
    fn test_omul_zero_scalar() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test multiplication by zero
        let plaintext = BigInt::from(123);
        let scalar = BigInt::zero();
        let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        
        let result_ciphertext = ek.omul(&scalar, &ciphertext).unwrap();
        let result_plaintext = dk.decrypt(&result_ciphertext).unwrap();
        
        assert_eq!(result_plaintext, BigInt::zero());
    }

    #[test]
    fn test_omul_one_scalar() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test multiplication by one (should be identity)
        let plaintext = BigInt::from(456);
        let scalar = BigInt::from(1);
        let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        
        let result_ciphertext = ek.omul(&scalar, &ciphertext).unwrap();
        let result_plaintext = dk.decrypt(&result_ciphertext).unwrap();
        
        assert_eq!(result_plaintext, plaintext);
    }

    #[test]
    fn test_omul_negative_scalar() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test multiplication by negative scalar
        let plaintext = BigInt::from(100);
        let scalar = BigInt::from(-3);
        let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        
        let result_ciphertext = ek.omul(&scalar, &ciphertext).unwrap();
        let result_plaintext = dk.decrypt(&result_ciphertext).unwrap();
        
        let expected = (plaintext * scalar).mod_floor(ek.n());
        // Handle negative modulo to get result in signed group
        let expected = if expected > *ek.half_n() {
            expected - ek.n()
        } else {
            expected
        };
        
        assert_eq!(result_plaintext, expected);
    }

    #[test]
    fn test_omul_negative_plaintext() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test multiplication with negative plaintext
        let plaintext = BigInt::from(-50);
        let scalar = BigInt::from(4);
        let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        
        let result_ciphertext = ek.omul(&scalar, &ciphertext).unwrap();
        let result_plaintext = dk.decrypt(&result_ciphertext).unwrap();
        
        let expected = (plaintext * scalar).mod_floor(ek.n());
        // Handle negative modulo to get result in signed group
        let expected = if expected > *ek.half_n() {
            expected - ek.n()
        } else {
            expected
        };
        
        assert_eq!(result_plaintext, expected);
    }

    #[test]
    fn test_omul_large_scalar() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test multiplication with large scalar
        let plaintext = BigInt::from(17);
        let scalar = BigInt::from(123456789);
        let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        
        let result_ciphertext = ek.omul(&scalar, &ciphertext).unwrap();
        let result_plaintext = dk.decrypt(&result_ciphertext).unwrap();
        
        let expected = (plaintext * scalar).mod_floor(ek.n());
        // Handle modulo to get result in signed group
        let expected = if expected > *ek.half_n() {
            expected - ek.n()
        } else {
            expected
        };
        
        assert_eq!(result_plaintext, expected);
    }

    #[test]
    fn test_omul_random_values() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test with random values multiple times
        for _ in 0..10 {
            let plaintext = rng.gen_bigint_range(ek.neg_half_n(), ek.half_n());
            let scalar = rng.gen_bigint_range(&BigInt::from(-1000), &BigInt::from(1000));
            
            let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
            let result_ciphertext = ek.omul(&scalar, &ciphertext).unwrap();
            let result_plaintext = dk.decrypt(&result_ciphertext).unwrap();
            
            let expected = (plaintext * scalar).mod_floor(ek.n());
            // Handle modulo to get result in signed group
            let expected = if expected > *ek.half_n() {
                expected - ek.n()
            } else {
                expected
            };
            
            assert_eq!(result_plaintext, expected);
        }
    }

    #[test]
    fn test_omul_with_addition() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test that omul and oadd work together correctly
        // Enc(a) * s + Enc(b) * s = Enc((a + b) * s)
        let plaintext_a = BigInt::from(30);
        let plaintext_b = BigInt::from(20);
        let scalar = BigInt::from(5);
        
        let (ciphertext_a, _) = ek.encrypt_with_random(&mut rng, &plaintext_a).unwrap();
        let (ciphertext_b, _) = ek.encrypt_with_random(&mut rng, &plaintext_b).unwrap();
        
        let mul_a = ek.omul(&scalar, &ciphertext_a).unwrap();
        let mul_b = ek.omul(&scalar, &ciphertext_b).unwrap();
        let sum = ek.oadd(&mul_a, &mul_b).unwrap();
        
        let result = dk.decrypt(&sum).unwrap();
        let expected = (plaintext_a + plaintext_b) * scalar;
        
        assert_eq!(result, expected);
    }

    #[test]
    fn test_omul_distributive() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test distributive property: (a + b) * s = a * s + b * s
        let plaintext_a = BigInt::from(15);
        let plaintext_b = BigInt::from(25);
        let scalar = BigInt::from(3);
        
        let (ciphertext_a, _) = ek.encrypt_with_random(&mut rng, &plaintext_a).unwrap();
        let (ciphertext_b, _) = ek.encrypt_with_random(&mut rng, &plaintext_b).unwrap();
        
        // Method 1: (a + b) * s
        let sum_ab = ek.oadd(&ciphertext_a, &ciphertext_b).unwrap();
        let result1 = ek.omul(&scalar, &sum_ab).unwrap();
        
        // Method 2: a * s + b * s
        let mul_a = ek.omul(&scalar, &ciphertext_a).unwrap();
        let mul_b = ek.omul(&scalar, &ciphertext_b).unwrap();
        let result2 = ek.oadd(&mul_a, &mul_b).unwrap();
        
        let decrypted1 = dk.decrypt(&result1).unwrap();
        let decrypted2 = dk.decrypt(&result2).unwrap();
        
        assert_eq!(decrypted1, decrypted2);
        assert_eq!(decrypted1, (plaintext_a + plaintext_b) * scalar);
    }

    #[test]
    fn test_omul_error_cases() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test with invalid ciphertext (0 should not be in multiplicative group)
        let plaintext = BigInt::from(10);
        let scalar = BigInt::from(2);
        let (valid_ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        
        // This should work with valid ciphertext
        assert!(ek.omul(&scalar, &valid_ciphertext).is_ok());
        
        // Test with zero ciphertext (should fail)
        let zero_ciphertext = BigInt::zero();
        assert!(ek.omul(&scalar, &zero_ciphertext).is_err());
    }

    #[test]
    fn test_oadd_error_cases() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test with invalid ciphertext (0 should not be in multiplicative group)
        let plaintext = BigInt::from(10);
        let (valid_ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        
        // This should work with valid ciphertext
        assert!(ek.oadd(&valid_ciphertext, &valid_ciphertext).is_ok());
        
        // Test with zero ciphertext (should fail)
        let zero_ciphertext = BigInt::zero();
        assert!(ek.oadd(&zero_ciphertext, &valid_ciphertext).is_err());
        assert!(ek.oadd(&valid_ciphertext, &zero_ciphertext).is_err());
    }

    #[test]
    fn test_oadd_with_mock_data_case1() {
        // Mock data from log case 1
        let c1 = BigInt::from_str_radix("243217886746839219387246971771771864248058682442548641117409358408733043048150648099878540961465664914358825409573138654028555055309050855210031834540487236496643947880872767136792012398283376861139770924137292614206176397855314220964352933127641954516377482096526862890688501729285449754168873767139612150499121781516048793126706857327885146917426549406981658532308751288503414062836320183676233017339732838752495891931041667026809440018225532065516371837490011904432208273129808879897589872987165262939243463218964044727938416938045508034086736470131756134261439297517733263177565265105619889827259986810245987469478373146104255888379368872724758415256788347151145235856584841535133354891888646508027718435096322274872113557727799863539852640776671322958163989058211082051914278781056799747512329680381337036511213325098691480573246942798005265069517997451000252750625151809018772129351426239366864741668192764214622276202566467167501540750772195103001043545293561382755334438544138042341260460547400704921209789631676005167244205961385321254144136297984712743843759230499401382129946685278654200548433284093669142917027861970107924226681649168076797412274156108327921151174459274405395883388368690694101298952134118752717049822507030746469977962850499006434912277469566052659425768336190645305760052288869956227023382352158930188898007679708075703793733859661888761552325540789472442027494609275372923595141644373373780978534878913533080332044078321783047289990070793695390157988497924331672083544319315719590369928092340688085056289987599433784893577294872065636431880718558065552953642200010462251351727789736639683533243477348864808716575965497708526079611970961267883738456457415847035374098706052160483897548642180337192116741520419629558830638124811616503977509061608750365893183608098721128742321564657413254597867202297191068234634875221", 10).unwrap();
        let c2 = BigInt::from_str_radix("52469213083780640591069768279317801043100441069066839554915143983651321495438231971944140271656190182582153702577602567106909995367878791151846851069432660365225372078378849732488210851595769504540644313551938176672371428711630067066930801524489987171106832824340820431069829187462728702538353740133130962461190154927901710429903039725665820556801260036721366144206795994041073168543965464292628093209319697097931304619477874652473416152379568582043178898694243641257749138007744831543677277611676989468112309660676300406295988676404745420718151767851066179654213957176171009399475064018573543385263844940726932718728511695470150334275122368874820674098525879525075090194429379793741217235694093595966763526472768313178621186763362499681571802678732197997649883595785235056322754995703380266211363900869602443223206916696949628608723287402778652248697192192378178443815325554492842699341055599944037710773873104416215421878537457213347037894913167408961079423749235431473282826524414854833723578535585512907421265427591447474912217821638677196932385917746150360669726950321445124368620108685719706039597803879112036450325337781484067230760761588791431117524461691287320349699576197234918492156146529465574880777000449176173498197152275770404523253563080584134914401512142149604603357430306776966113662054655123186769923134926681328118275403848386135069146160768765742610889053975155569366312214541893252025773368399180134283158325689978155787828175494989544705098519583975126288123903809188758950175294916125175571150035563087132420294157622065219086810003883875260679377767386887912026162333328106951946239726312237537286362958181293808725276888937470640032928972574523730306581399523212275766776425825621545197828904783844332914643162156197560608577552939009952799395460769127329769550574612947545475386226521961453749296794552777259390343817786", 10).unwrap();
        let nn = BigInt::from_str_radix("389998823346817492279222314223551080505180805475706337027025956966403471294762004769066881057362798779750332696173995457617532729651084640523327088094706613265574285481686058120088735441902247610351181085437937118696838848613005174638797825664363529159731133542626140220240518394255122086425022121010915161625272747636723704710811939651980420334713185063879966480330054563383827405910421365428762316612441220780629209877847344985893407949699041691022121487966595040633486446063547700285829198390221412195420487395420077861921179711330364264681051397654248123980134337099702505911317863346682099421969756501701642540525861381521672639563144870245471574600852756697188009971717854229368926438734840864494919993557086988404799658984437284097829895353071548609409838763579542915679139639019485748424784568145390360990346525001365844938493189128570603900486769584568826440240280007515106194021998526596091238683068117538160250825273127849132437916209958700561125954595686242592168327953772095100690463591434610851366061308171604109964788184471433313218928111239876916448240180867356133350000976310725213239456159976021319608238468255806951628489354008273766636026396675676997161595989671340128997096964182987883472568635133970692468147891504331284796592813555966449149639420015727762939893158024828936849816026229909612829624444987122630193255501956181713098523666271127622444128964280809770508271689880931239956159970158192437784731460370155790745780080945173697175328320583101697237494120815439628216110660153330493335331528234573121312611419202556814074507493014946492251750022399671103638424684351624740562863375261088149227079221283580469970139204545260977336023420408838106158134698739380669740150685417368146172581171913583576175617863987038943094217798279816274446368816471023685792807360364513195274957840031930934110129078118035567831900236489", 10).unwrap();

        // Create a temporary encryption key with the same nn value
        let n = BigInt::from_str_radix("624498857762620325098235170965743800775986411638861818063975567416457548620626106589775762742147050332061040035988343327949848344781895647064874621111687462752351420252191016556563422405065857493565714223369457326132905751097688764312209576092608940344112195727294420580004446885734418485854984933721637793585572313379454462372823080364186214267829274487061982469987426935994509566980637443218966350207542793855595534878529696726480414810101468713027596090923530806002617542180788766147785236740591484455822141732077626477810969339706966842770784842141574665525282473888631304800798834440140046529558448816002513160409692564156284555087902686772224299491823502624123052301570848969169650127973801617496811923093923613174646328722924361659936987353289043665636098196190290386284750432940209381911182951746612131658041398132442860120556913619042902264243188841994871986844780749268847877605077940655376360242193578643742404317", 10).unwrap();
        let h = BigInt::from_str_radix("-46118646770832830045641315635057147415619452896408495725084525515631763498419217092239007240481104785951515106141330780184017724711354754878105138981527814046713442701173158787961318701138213050689131500547667287835057808777090201233823259693317234765298199512393795028689399638011557338811405434847285549626923699588499355369100778944461335938055933338208588737362787471904613721909499495052563847250494605740519245116885721410290558409599017491571221814391229137726330359398608150289466563711537032436971344700037076458377527561048872725835181683669452128606967411636366306264582886347600341878183021479279996250977820902830628786961783055120959326713538614909410942862567628149824740864114037208934860868056544040342709335908500229136286989784554496443156132704420811055403006822848620991994750093609373760282848220484869564427940530240476784686626726481501299422807761209664211819557525909377117754524995670714798106228", 10).unwrap();
        let ek = EncryptionKey::new(3072, 512, h, n).unwrap();

        // Verify nn matches expected value
        assert_eq!(ek.nn(), &nn);
        
        // Test oadd with the mock data
        let result = ek.oadd(&c1, &c2);
        assert!(result.is_ok(), "oadd should succeed with valid ciphertexts");
        
        let sum = result.unwrap();
        let expected = (c1 * c2).mod_floor(&nn);
        assert_eq!(sum, expected);
        
        // Verify the result is in the multiplicative group
        assert!(utils::in_mult_group(&sum, &nn));
    }

    #[test]
    fn test_oadd_with_mock_data_case2() {
        // Mock data from log case 2
        let c1 = BigInt::from_str_radix("24001803448353818750122517063935251459034643788309841616514147592757643226312735060981263749708788369313076967316895409916148578190804885030307212834112354929080371628800539706649513986586217878059796817385286648876471033272035845725462568789480985941763734083471775263274111435465707524031588671203984621660598691971405984247383216241445482793021383382872522997250569866360064619865186817580123909682165848344946853893789248322226218391386471575931534588338006077197781099019519473731175921794857798774907728164623779664129732607575742366073095400846993585710029329657480342030315217890046420583559006058809706126205145415129383721564540728534994823986629433843429456995056662970149624004533371146427558052995895156411950292370238170530479874931992509362907349216172697940879276804981606874198485436078784922914976493846132236489673168177276420369135785914228634466416404966458027148010095803602464960012785220520217775743031988761153058015631777063935868210755016805700632064529077533337834957245076735640677236087306398176993334711135648229205996666056188894010274104847997459510575412398065419642648256042019061237656944819140269490486953110931187878320498382869308385895783520751145177794047101310764742582704028723502199119293243626613406135804872916321075245049233590853962781973347269263969323267681593627283638461733331062415308468517179974694635849230552370235580006367119029717132796107489123940456212232871784700970020457930302337531849487202517257325599449885730656541202849132786651487513630189399388077541551171163902693917279300172482761805860486455791009249708461054606235209172952109877402979426823545719214346859714032402248328583330174632518547706277888987981848351286894333046467421012987025555512128495340434026514941258565657533850571671338558965234132706212487059994636048674912709094464874121580259107597071665264853268714", 10).unwrap();
        let c2 = BigInt::from_str_radix("114258191002836073010684303536945013028255692211830842638822696238443706431462108301349442081732416499226411633945264877570807942085597041990493977527782151265115603018731692434123087187947352325571275366619377823521504507327625321254462266074915601623503117426548626930672865930696333218942424109656221411994913327006096192043119604367768113755688180159629563120423975590097601312806448697568074870380848261817601929931651191412472413128210779555873376266853028358116993591417365227971308545838222429244282206506448174145886426536408363249741817930040779334793109583045912794631356266031163370393065662847535714831793071981598518759548118695217198976307755351758345660228373500941331718944820684744261424466482617893811656248933467132281472370545104139532636790696792451447518849770748695192356897098485351715819018946641685222973560541778062222492908667878646130681227014175235125173778893241716683219330779564187970910153922314179064373035792299348312583352498429171715634368758623114334566485735838091311820166105213788556891055881785552402753879139774308206298547185827382940656306509979737169968043426863526626276082201126260789941267952398459032765989356971514526104030997041614293528362553628713617304606532831780297643980516203674112696562169809627156851468543767914506798547067016542732941059147405541484371136718271376342967484342192442643417809578749052140291604379219299834658607036620296497562226557049876486209742869211402180511774820561127578136114594957142382990238090004796668034672665211409483329364860591898969331922512106581879742432344957685675083247291281760456446813310021374076099757136984279536904787827609164131633238009302871741171122076015041890569377386599640834586953360808691349083129608906811429386768752703745262914674538326017054948329956222288292568747840604288112717808713690612664315443814380559205387930914870", 10).unwrap();
        let nn = BigInt::from_str_radix("389998823346817492279222314223551080505180805475706337027025956966403471294762004769066881057362798779750332696173995457617532729651084640523327088094706613265574285481686058120088735441902247610351181085437937118696838848613005174638797825664363529159731133542626140220240518394255122086425022121010915161625272747636723704710811939651980420334713185063879966480330054563383827405910421365428762316612441220780629209877847344985893407949699041691022121487966595040633486446063547700285829198390221412195420487395420077861921179711330364264681051397654248123980134337099702505911317863346682099421969756501701642540525861381521672639563144870245471574600852756697188009971717854229368926438734840864494919993557086988404799658984437284097829895353071548609409838763579542915679139639019485748424784568145390360990346525001365844938493189128570603900486769584568826440240280007515106194021998526596091238683068117538160250825273127849132437916209958700561125954595686242592168327953772095100690463591434610851366061308171604109964788184471433313218928111239876916448240180867356133350000976310725213239456159976021319608238468255806951628489354008273766636026396675676997161595989671340128997096964182987883472568635133970692468147891504331284796592813555966449149639420015727762939893158024828936849816026229909612829624444987122630193255501956181713098523666271127622444128964280809770508271689880931239956159970158192437784731460370155790745780080945173697175328320583101697237494120815439628216110660153330493335331528234573121312611419202556814074507493014946492251750022399671103638424684351624740562863375261088149227079221283580469970139204545260977336023420408838106158134698739380669740150685417368146172581171913583576175617863987038943094217798279816274446368816471023685792807360364513195274957840031930934110129078118035567831900236489", 10).unwrap();

        // Create a temporary encryption key with the same nn value
        let n = BigInt::from_str_radix("624498857762620325098235170965743800775986411638861818063975567416457548620626106589775762742147050332061040035988343327949848344781895647064874621111687462752351420252191016556563422405065857493565714223369457326132905751097688764312209576092608940344112195727294420580004446885734418485854984933721637793585572313379454462372823080364186214267829274487061982469987426935994509566980637443218966350207542793855595534878529696726480414810101468713027596090923530806002617542180788766147785236740591484455822141732077626477810969339706966842770784842141574665525282473888631304800798834440140046529558448816002513160409692564156284555087902686772224299491823502624123052301570848969169650127973801617496811923093923613174646328722924361659936987353289043665636098196190290386284750432940209381911182951746612131658041398132442860120556913619042902264243188841994871986844780749268847877605077940655376360242193578643742404317", 10).unwrap();
        let h = BigInt::from_str_radix("-46118646770832830045641315635057147415619452896408495725084525515631763498419217092239007240481104785951515106141330780184017724711354754878105138981527814046713442701173158787961318701138213050689131500547667287835057808777090201233823259693317234765298199512393795028689399638011557338811405434847285549626923699588499355369100778944461335938055933338208588737362787471904613721909499495052563847250494605740519245116885721410290558409599017491571221814391229137726330359398608150289466563711537032436971344700037076458377527561048872725835181683669452128606967411636366306264582886347600341878183021479279996250977820902830628786961783055120959326713538614909410942862567628149824740864114037208934860868056544040342709335908500229136286989784554496443156132704420811055403006822848620991994750093609373760282848220484869564427940530240476784686626726481501299422807761209664211819557525909377117754524995670714798106228", 10).unwrap();
        let ek = EncryptionKey::new(3072, 512, h, n).unwrap();

        // Verify nn matches expected value
        assert_eq!(ek.nn(), &nn);
        
        // Test oadd with the mock data
        let result = ek.oadd(&c1, &c2);
        assert!(result.is_ok(), "oadd should succeed with valid ciphertexts");
        
        let sum = result.unwrap();
        let expected = (c1 * c2).mod_floor(&nn);
        assert_eq!(sum, expected);
        
        // Verify the result is in the multiplicative group
        assert!(utils::in_mult_group(&sum, &nn));
    }

    #[test]
    fn test_oadd_with_mock_data_case3() {
        // Mock data from log case 3
        let c1 = BigInt::from_str_radix("332211724793106910761089513170058970651785138048780776378434224225992408772748329904366170795901431410949607263093067597228748153016064174897964317038721829489273525917398965857989875782410144693464115374048144592582670503378655052169169676291200898395373861783053316917080988408731406881372034424785931305459982751366636015848700531684348576760529167685423549931933893219215636815808916247675109071029186682662164224471180489028173411168604515078355504696841848600761459309961573258189397085154388337230717203898025999423967534161851489098808413008894347814198914712152443789778226068102791127326026445489469674364913152685632808484435455375399983931916606034303431541447121190348604093564465297067559665377526387041981362689061256431388917413090232378004418100760608591805430327280461834892871579177947679376389704731570241530342650006031889191738551842063398843370833480531987217305978785396658060980411334297607624539544490853573080138929085313798541801690782600202957035482890018230977542708810868675010327772213610711116238598184966434157674170032957043662199171820393063037693868881875029177255582907777533849325153136027511862672526937588002425589025170477432601098559442652898377534755123709801087204207134195794305870628363529461578372321503097795925987758041752893594450858576439991263824838127580137385894273132518184542653635808256542037326757336656184162350224175745891728436124847555168912267825865109540200939647870198002657193108993325766393913103635218777456553196131806849904177963217256451738661500534872986544588251729368467189563928524286279765927255886494211979045417457832298112335482943313683615730575923322841291924652346590284395073761391910028644391568720003101145788401457002738342972691115600395353533965419461432149723049991074342473248168309931775074009253846068600469729385997726607241593855200534214360143627179358", 10).unwrap();
        let c2 = BigInt::from_str_radix("205334457453623600605969227586687483908728840492463037475443437703928487929329352600658691042896864644566192228644206350909192960596050923130554495826357761528323800798376454655326879539413647207313676816085320407040755502802259008663906579061131178622247916884947353837643308872724644543743616989252579008059971616983358228084022549779625479318030130262980496354458663043240697383571255503479166024811827872965871422010872093927281544242081319637524359780914006634308273340538488540076201021915956178889603421050766463244910650878854154890001463482121975016453676022692582863901990357976178052250769312546440564051115981999673708953449254668475126171578050966094143680536898210824599142428316845510052787569923842676165323311611115027710145768549436020772300322895365993853497638738028532072740629666081717099015876884027467308331306901333007440153863606049787905131386765342730375943017006186303013574482287458827526704264946461889173447227654957608487574326814718537101966159681830866344338319600223899824312732509896933406142321464646911065096726964098843635031333706163165523308693211951894537187102353063027638055750346418493331724800304353231877522232816305752062519017213300764063029962897252752137007625593738262640918722821107331319767951803234567530326820098691112964586604274555157076048357694247501138094843130757233140732828566160073727048106609953080754741956934664285024821366814075807514358380593107425661496138888352998168258768286079214151762069466856662357082411855858816352913724298705179207389078981221198630086748854178965665162558734375234357159749846935055265011654186125123703375007045876622812452273710307944516857460079828506924581982382805473690861628557833494281790666856832890487049287002407119190247789878717512353779530513516663162596324010963087747937293780038622083906578956639742444426134889319858048960468030659", 10).unwrap();
        let nn = BigInt::from_str_radix("389998823346817492279222314223551080505180805475706337027025956966403471294762004769066881057362798779750332696173995457617532729651084640523327088094706613265574285481686058120088735441902247610351181085437937118696838848613005174638797825664363529159731133542626140220240518394255122086425022121010915161625272747636723704710811939651980420334713185063879966480330054563383827405910421365428762316612441220780629209877847344985893407949699041691022121487966595040633486446063547700285829198390221412195420487395420077861921179711330364264681051397654248123980134337099702505911317863346682099421969756501701642540525861381521672639563144870245471574600852756697188009971717854229368926438734840864494919993557086988404799658984437284097829895353071548609409838763579542915679139639019485748424784568145390360990346525001365844938493189128570603900486769584568826440240280007515106194021998526596091238683068117538160250825273127849132437916209958700561125954595686242592168327953772095100690463591434610851366061308171604109964788184471433313218928111239876916448240180867356133350000976310725213239456159976021319608238468255806951628489354008273766636026396675676997161595989671340128997096964182987883472568635133970692468147891504331284796592813555966449149639420015727762939893158024828936849816026229909612829624444987122630193255501956181713098523666271127622444128964280809770508271689880931239956159970158192437784731460370155790745780080945173697175328320583101697237494120815439628216110660153330493335331528234573121312611419202556814074507493014946492251750022399671103638424684351624740562863375261088149227079221283580469970139204545260977336023420408838106158134698739380669740150685417368146172581171913583576175617863987038943094217798279816274446368816471023685792807360364513195274957840031930934110129078118035567831900236489", 10).unwrap();

        // Create a temporary encryption key with the same nn value
        let n = BigInt::from_str_radix("624498857762620325098235170965743800775986411638861818063975567416457548620626106589775762742147050332061040035988343327949848344781895647064874621111687462752351420252191016556563422405065857493565714223369457326132905751097688764312209576092608940344112195727294420580004446885734418485854984933721637793585572313379454462372823080364186214267829274487061982469987426935994509566980637443218966350207542793855595534878529696726480414810101468713027596090923530806002617542180788766147785236740591484455822141732077626477810969339706966842770784842141574665525282473888631304800798834440140046529558448816002513160409692564156284555087902686772224299491823502624123052301570848969169650127973801617496811923093923613174646328722924361659936987353289043665636098196190290386284750432940209381911182951746612131658041398132442860120556913619042902264243188841994871986844780749268847877605077940655376360242193578643742404317", 10).unwrap();
        let h = BigInt::from_str_radix("-46118646770832830045641315635057147415619452896408495725084525515631763498419217092239007240481104785951515106141330780184017724711354754878105138981527814046713442701173158787961318701138213050689131500547667287835057808777090201233823259693317234765298199512393795028689399638011557338811405434847285549626923699588499355369100778944461335938055933338208588737362787471904613721909499495052563847250494605740519245116885721410290558409599017491571221814391229137726330359398608150289466563711537032436971344700037076458377527561048872725835181683669452128606967411636366306264582886347600341878183021479279996250977820902830628786961783055120959326713538614909410942862567628149824740864114037208934860868056544040342709335908500229136286989784554496443156132704420811055403006822848620991994750093609373760282848220484869564427940530240476784686626726481501299422807761209664211819557525909377117754524995670714798106228", 10).unwrap();
        let ek = EncryptionKey::new(3072, 512, h, n).unwrap();

        // Verify nn matches expected value
        assert_eq!(ek.nn(), &nn);
        
        // Test oadd with the mock data
        let result = ek.oadd(&c1, &c2);
        assert!(result.is_ok(), "oadd should succeed with valid ciphertexts");
        
        let sum = result.unwrap();
        let expected = (c1 * c2).mod_floor(&nn);
        assert_eq!(sum, expected);
        
        // Verify the result is in the multiplicative group
        assert!(utils::in_mult_group(&sum, &nn));
    }

    #[test]
    fn test_oadd_commutativity() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test commutativity: oadd(a, b) = oadd(b, a)
        let plaintext_a = BigInt::from(25);
        let plaintext_b = BigInt::from(35);
        
        let (ciphertext_a, _) = ek.encrypt_with_random(&mut rng, &plaintext_a).unwrap();
        let (ciphertext_b, _) = ek.encrypt_with_random(&mut rng, &plaintext_b).unwrap();
        
        let sum_ab = ek.oadd(&ciphertext_a, &ciphertext_b).unwrap();
        let sum_ba = ek.oadd(&ciphertext_b, &ciphertext_a).unwrap();
        
        let decrypted_ab = dk.decrypt(&sum_ab).unwrap();
        let decrypted_ba = dk.decrypt(&sum_ba).unwrap();
        
        assert_eq!(decrypted_ab, decrypted_ba);
        assert_eq!(decrypted_ab, plaintext_a + plaintext_b);
    }

    #[test]
    fn test_oadd_associativity() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test associativity: oadd(oadd(a, b), c) = oadd(a, oadd(b, c))
        let plaintext_a = BigInt::from(10);
        let plaintext_b = BigInt::from(20);
        let plaintext_c = BigInt::from(30);
        
        let (ciphertext_a, _) = ek.encrypt_with_random(&mut rng, &plaintext_a).unwrap();
        let (ciphertext_b, _) = ek.encrypt_with_random(&mut rng, &plaintext_b).unwrap();
        let (ciphertext_c, _) = ek.encrypt_with_random(&mut rng, &plaintext_c).unwrap();
        
        // (a + b) + c
        let sum_ab = ek.oadd(&ciphertext_a, &ciphertext_b).unwrap();
        let sum_ab_c = ek.oadd(&sum_ab, &ciphertext_c).unwrap();
        
        // a + (b + c)
        let sum_bc = ek.oadd(&ciphertext_b, &ciphertext_c).unwrap();
        let sum_a_bc = ek.oadd(&ciphertext_a, &sum_bc).unwrap();
        
        let decrypted_ab_c = dk.decrypt(&sum_ab_c).unwrap();
        let decrypted_a_bc = dk.decrypt(&sum_a_bc).unwrap();
        
        assert_eq!(decrypted_ab_c, decrypted_a_bc);
        assert_eq!(decrypted_ab_c, plaintext_a + plaintext_b + plaintext_c);
    }

    #[test]
    fn test_oadd_with_negative_values() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test addition with negative values
        let plaintext_a = BigInt::from(50);
        let plaintext_b = BigInt::from(-30);
        
        let (ciphertext_a, _) = ek.encrypt_with_random(&mut rng, &plaintext_a).unwrap();
        let (ciphertext_b, _) = ek.encrypt_with_random(&mut rng, &plaintext_b).unwrap();
        
        let sum = ek.oadd(&ciphertext_a, &ciphertext_b).unwrap();
        let result = dk.decrypt(&sum).unwrap();
        
        assert_eq!(result, plaintext_a + plaintext_b);
        assert_eq!(result, BigInt::from(20));
    }

    #[test]
    fn test_oadd_with_zero() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test addition with zero (identity element)
        let plaintext = BigInt::from(42);
        let zero = BigInt::zero();
        
        let (ciphertext, _) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        let (zero_ciphertext, _) = ek.encrypt_with_random(&mut rng, &zero).unwrap();
        
        let sum = ek.oadd(&ciphertext, &zero_ciphertext).unwrap();
        let result = dk.decrypt(&sum).unwrap();
        
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_oadd_multiple_operations() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test multiple additions
        let plaintexts = vec![
            BigInt::from(10),
            BigInt::from(20),
            BigInt::from(-5),
            BigInt::from(15),
            BigInt::from(-8),
        ];
        
        let mut ciphertexts = Vec::new();
        for plaintext in &plaintexts {
            let (ciphertext, _) = ek.encrypt_with_random(&mut rng, plaintext).unwrap();
            ciphertexts.push(ciphertext);
        }
        
        // Sum all ciphertexts
        let mut sum = ciphertexts[0].clone();
        for i in 1..ciphertexts.len() {
            sum = ek.oadd(&sum, &ciphertexts[i]).unwrap();
        }
        
        let result = dk.decrypt(&sum).unwrap();
        let expected: BigInt = plaintexts.iter().sum();
        
        assert_eq!(result, expected);
    }

    #[test]
    fn test_oadd_large_values() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        // Test with large values within the valid range
        let plaintext_a = BigInt::from(123456789);
        let plaintext_b = BigInt::from(987654321);
        
        let (ciphertext_a, _) = ek.encrypt_with_random(&mut rng, &plaintext_a).unwrap();
        let (ciphertext_b, _) = ek.encrypt_with_random(&mut rng, &plaintext_b).unwrap();
        
        let sum = ek.oadd(&ciphertext_a, &ciphertext_b).unwrap();
        let result = dk.decrypt(&sum).unwrap();
        
        assert_eq!(result, plaintext_a + plaintext_b);
    }
}

