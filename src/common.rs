use num_bigint::BigInt;
use num_traits::Signed;

/// Extension trait for BigInt
pub trait BigIntExt: Sized {
    /// Returns `self ^ exp mod modulo`
    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self>;
}

impl BigIntExt for BigInt {
    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self> {
        if exp.is_negative() {
            // For negative exponents: x^(-n) mod m = (x^(-1) mod m)^n mod m
            let base_inverse = self.clone().modinv(modulo)?;
            let positive_exp = -exp.clone();
            Some(base_inverse.modpow(&positive_exp, modulo))
        } else {
            // For positive exponents, use regular modpow
            Some(self.modpow(exp, modulo))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use num_traits::{Num, Zero};

    #[test]
    fn test_modpow_ext_positive_exponent() {
        let base = BigInt::from(3);
        let exp = BigInt::from(4);
        let modulo = BigInt::from(13);
        
        // 3^4 mod 13 = 81 mod 13 = 3
        let result = base.modpow_ext(&exp, &modulo).unwrap();
        assert_eq!(result, BigInt::from(3));
        
        // Verify against regular modpow
        let expected = base.modpow(&exp, &modulo);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_modpow_ext_negative_exponent() {
        let base = BigInt::from(3);
        let exp = BigInt::from(-2);
        let modulo = BigInt::from(13);
        
        // 3^(-2) mod 13 = (3^(-1) mod 13)^2 mod 13
        // First find 3^(-1) mod 13: 3 * 9 = 27 ≡ 1 (mod 13), so 3^(-1) = 9
        // Then (9^2) mod 13 = 81 mod 13 = 3
        let result = base.modpow_ext(&exp, &modulo).unwrap();
        assert_eq!(result, BigInt::from(3));
    }

    #[test]
    fn test_modpow_ext_zero_exponent() {
        let base = BigInt::from(5);
        let exp = BigInt::zero();
        let modulo = BigInt::from(13);
        
        // Any number^0 mod m = 1
        let result = base.modpow_ext(&exp, &modulo).unwrap();
        assert_eq!(result, BigInt::from(1));
    }

    #[test]
    fn test_modpow_ext_exponent_one() {
        let base = BigInt::from(7);
        let exp = BigInt::from(1);
        let modulo = BigInt::from(13);
        
        // 7^1 mod 13 = 7
        let result = base.modpow_ext(&exp, &modulo).unwrap();
        assert_eq!(result, BigInt::from(7));
    }

    #[test]
    fn test_modpow_ext_negative_exponent_one() {
        let base = BigInt::from(3);
        let exp = BigInt::from(-1);
        let modulo = BigInt::from(13);
        
        // 3^(-1) mod 13 = 9 (since 3 * 9 = 27 ≡ 1 (mod 13))
        let result = base.modpow_ext(&exp, &modulo).unwrap();
        assert_eq!(result, BigInt::from(9));
    }

    #[test]
    fn test_modpow_ext_no_modular_inverse() {
        let base = BigInt::from(6);  // gcd(6, 9) = 3 ≠ 1
        let exp = BigInt::from(-1);
        let modulo = BigInt::from(9);
        
        // 6 and 9 are not coprime, so modular inverse doesn't exist
        let result = base.modpow_ext(&exp, &modulo);
        assert!(result.is_none());
    }

    #[test]
    fn test_modpow_ext_large_numbers() {
        let base = BigInt::from(12345);
        let exp = BigInt::from(6789);
        let modulo = BigInt::from(9876543);
        
        // Test with larger numbers
        let result = base.modpow_ext(&exp, &modulo).unwrap();
        let expected = base.modpow(&exp, &modulo);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_modpow_ext_large_negative_exponent() {
        let base = BigInt::from(7);
        let exp = BigInt::from(-100);
        let modulo = BigInt::from(101);  // 101 is prime, so gcd(7, 101) = 1
        
        // Test with large negative exponent
        let result = base.modpow_ext(&exp, &modulo).unwrap();
        
        // Verify by computing it manually: 7^(-100) mod 101 = (7^(-1) mod 101)^100 mod 101
        let inv = base.clone().modinv(&modulo).unwrap();
        let expected = inv.modpow(&BigInt::from(100), &modulo);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_modpow_ext_edge_cases() {
        let modulo = BigInt::from(7);
        
        // Test 1^(-1) mod 7 = 1
        let result = BigInt::from(1).modpow_ext(&BigInt::from(-1), &modulo).unwrap();
        assert_eq!(result, BigInt::from(1));
        
        // Test 1^(-100) mod 7 = 1
        let result = BigInt::from(1).modpow_ext(&BigInt::from(-100), &modulo).unwrap();
        assert_eq!(result, BigInt::from(1));
        
        // Test 1^100 mod 7 = 1
        let result = BigInt::from(1).modpow_ext(&BigInt::from(100), &modulo).unwrap();
        assert_eq!(result, BigInt::from(1));
    }

    #[test]
    fn test_modpow_ext_prime_modulus() {
        let modulo = BigInt::from(17);  // Prime modulus
        
        // Test various bases with negative exponents
        for base in 2..17 {
            let base_bigint = BigInt::from(base);
            let exp = BigInt::from(-1);
            
            let result = base_bigint.modpow_ext(&exp, &modulo).unwrap();
            
            // Verify that base * result ≡ 1 (mod 17)
            let product = (base_bigint * result.clone()) % &modulo;
            assert_eq!(product, BigInt::from(1));
        }
    }

    #[test]
    fn test_modpow_ext_consistency() {
        let base = BigInt::from(5);
        let modulo = BigInt::from(23);
        
        // Test that positive and negative exponents are consistent
        for exp in 1..10 {
            let pos_exp = BigInt::from(exp);
            let neg_exp = BigInt::from(-exp);
            
            let pos_result = base.modpow_ext(&pos_exp, &modulo).unwrap();
            let neg_result = base.modpow_ext(&neg_exp, &modulo).unwrap();
            
            // pos_result * neg_result should be 1 mod modulo
            let product = (pos_result * neg_result) % &modulo;
            assert_eq!(product, BigInt::from(1));
        }
    }

    #[test]
    fn test_modpow_ext_bignum(){
        let base = BigInt::from_str_radix("276384518715169225487553929817914201849548850902444767188388597300106748618171633281298671147795913382274544683180353655300711569353810766131912306219474851444332145692357104507835568124859426676577447955294568132665975011689510456271935580740850362597651150075056749932639131254017646543973968231118468208243418780393370399341871637961283954445014550108852500214302654460086232565494646614329508517889279379319205032997351194776487068953652784384469376409336424055003575385245573418459870198741108194384939021088206583320420347510484021975394357720183679131573061647020078719454258420613172676583470939620237900193069530761070245266700415094785550433108202057009711078275142903383584493579897653767584023959665690100105278321896920508102401899783604566939338109857956720267420363088656928560318726710584712369809115831611560033649555831778727944639937858706824430124896955535715904573814372722312373737282914424604761911631624391276517058678030656378507953522612569950120485529395797730430727746350838688115586889159465034750703560852126301468551888503155533936154621419043835634790366161568335189333172396350019469297620105360940307779061030782120880331249322752469116865862086797691455958509394730993271947244170573619227555809712958327797016709677118271235636347699866901068664098692266349937875973327310516697647297245671082833300289374440477857145730334009242446596941826767251306591709681807250736004015568385192550710397913973212766347205703498666498105212164044900415319880255899598125072574555531216283796334572927174436285871297038372148355790592241373543003492047004485682950869791061880367170719655546605737564377971262204238711241002463004956345805067488483541181715494374179239411972692144981931312371740617540113452444007219298019080701071331083809062968583120624483044986166579113505855423151894684314901256282666443994190723469591", 10).unwrap();
        let exp = BigInt::from_str_radix("-27995244864854644560905527287449105598248984202654137323257656171815556015813135451156967446568126502923282371124914494359851800912773680843148457280122612942481625802148591503132718832133040080733389654316798015681651754100014226216494400955741265266434909371770523354463988077756471239200962490794100623916", 10).unwrap();
        let modulo = BigInt::from_str_radix("389998823346817492279222314223551080505180805475706337027025956966403471294762004769066881057362798779750332696173995457617532729651084640523327088094706613265574285481686058120088735441902247610351181085437937118696838848613005174638797825664363529159731133542626140220240518394255122086425022121010915161625272747636723704710811939651980420334713185063879966480330054563383827405910421365428762316612441220780629209877847344985893407949699041691022121487966595040633486446063547700285829198390221412195420487395420077861921179711330364264681051397654248123980134337099702505911317863346682099421969756501701642540525861381521672639563144870245471574600852756697188009971717854229368926438734840864494919993557086988404799658984437284097829895353071548609409838763579542915679139639019485748424784568145390360990346525001365844938493189128570603900486769584568826440240280007515106194021998526596091238683068117538160250825273127849132437916209958700561125954595686242592168327953772095100690463591434610851366061308171604109964788184471433313218928111239876916448240180867356133350000976310725213239456159976021319608238468255806951628489354008273766636026396675676997161595989671340128997096964182987883472568635133970692468147891504331284796592813555966449149639420015727762939893158024828936849816026229909612829624444987122630193255501956181713098523666271127622444128964280809770508271689880931239956159970158192437784731460370155790745780080945173697175328320583101697237494120815439628216110660153330493335331528234573121312611419202556814074507493014946492251750022399671103638424684351624740562863375261088149227079221283580469970139204545260977336023420408838106158134698739380669740150685417368146172581171913583576175617863987038943094217798279816274446368816471023685792807360364513195274957840031930934110129078118035567831900236489", 10).unwrap();

        let result = base.modpow_ext(&exp, &modulo).unwrap();
        println!("result: {:?}", result);
    }
}
