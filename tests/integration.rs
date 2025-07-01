// TODO: update integration test

use fast_paillier::AnyEncryptionKey;
use fast_paillier::{DecryptionKey};
use rand::{CryptoRng, RngCore};
use malachite::Integer;
use malachite_nz::integer::random::get_uniform_random_integer_from_inclusive_range;
use malachite_base::num::random::random_primitive_ints;
use malachite_base::random::EXAMPLE_SEED;

#[test]
fn encrypt_decrypt() {
    let mut rng = rand_dev::DevRng::new();
    let dk = random_key_for_tests(&mut rng);
    let ek = dk.encryption_key();

    for _ in 0..50 {
        // Generate plaintext in [-N/2; N/2)
        let neg_n = -ek.n();
        let plaintext = get_uniform_random_integer_from_inclusive_range(
            &mut random_primitive_ints(EXAMPLE_SEED),
            neg_n,
            ek.n().clone(),
        );
        let plaintext = plaintext - (ek.n() / Integer::from(2));
        println!("Plaintext: {plaintext}");

        // Encrypt and decrypt
        let (ciphertext, nonce) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        println!("Ciphertext: {ciphertext}");
        println!("Nonce: {nonce}");

        let decrypted = dk.decrypt(&ciphertext).unwrap();
        println!("Decrypted: {decrypted}");

        assert_eq!(plaintext, decrypted);
        println!();
    }

    // Check corner cases

    let lower_bound = -(ek.n() / Integer::from(2));
    let upper_bound = (ek.n() / Integer::from(2));

    let corner_cases = [
        lower_bound.clone(),
        lower_bound.clone() + Integer::from(1),
        upper_bound.clone() - Integer::from(1),
        upper_bound.clone(),
    ];
    for (i, plaintext) in corner_cases.into_iter().enumerate() {
        println!("Corner case {i}");
        let (ciphertext, _nonce) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        let decrypted = dk.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}

// #[test]
// fn doesnt_encrypt_plaintext_out_of_bounds() {
//     let mut rng = rand_dev::DevRng::new();
//     let dk = random_key_for_tests(&mut rng);
//     let ek = dk.encryption_key();

//     let lower_bound = -(ek.n() / Integer::from(2));
//     let upper_bound = (ek.n() / Integer::from(2));

//     let cases = [   
//         lower_bound.clone() - Integer::from(1),
//         lower_bound.clone() - Integer::from(2),
//         upper_bound.clone() + Integer::from(1),
//         upper_bound.clone() + Integer::from(2),
//     ];
//     for (i, plaintext) in cases.into_iter().enumerate() {
//         println!("Case {i}");
//         let _: fast_paillier::Error = ek.encrypt_with_random(&mut rng, &plaintext).unwrap_err();
//     }
// }

// #[test]
// fn homorphic_ops() {
//     let mut rng = rand_dev::DevRng::new();
//     let dk = random_key_for_tests(&mut rng);
//     let ek = dk.encryption_key();

//     for _ in 0..100 {
//         let neg_n = -ek.n().clone();
//         let a = get_uniform_random_integer_from_inclusive_range(
//             &mut random_primitive_ints(EXAMPLE_SEED),
//             neg_n.clone(),
//             ek.n().clone(),
//         );
//         let b = get_uniform_random_integer_from_inclusive_range(
//             &mut random_primitive_ints(EXAMPLE_SEED),
//             neg_n.clone(),
//             ek.n().clone(),
//         );
//         let a = a - (ek.n() / Integer::from(2));
//         let b = b - (ek.n() / Integer::from(2));
//         println!("a: {a}");
//         println!("b: {b}");

//         let (enc_a, _nonce) = ek.encrypt_with_random(&mut rng, &a).unwrap();
//         let (enc_b, _nonce) = ek.encrypt_with_random(&mut rng, &b).unwrap();

//         // Addition
//         {
//             let enc_a_plus_b = ek.oadd(&enc_a, &enc_b).unwrap();
//             let a_plus_b = dk.decrypt(&enc_a_plus_b).unwrap();
//             assert_eq!(a_plus_b, signed_modulo(&(&a + &b), ek.n()));
//         }

//         // Subtraction
//         {
//             let enc_a_minus_b = ek.osub(&enc_a, &enc_b).unwrap();
//             let a_minus_b = dk.decrypt(&enc_a_minus_b).unwrap();
//             assert_eq!(a_minus_b, signed_modulo(&(&a - &b), ek.n()));
//         }

//         // Negation
//         {
//             let enc_neg_a = ek.oneg(&enc_a).unwrap();
//             let neg_a = dk.decrypt(&enc_neg_a).unwrap();
//             assert_eq!(neg_a, signed_modulo(&(-&a), ek.n()));
//         }

//         // Multiplication
//         {
//             let enc_a_at_b = ek.omul(&a, &enc_b).unwrap();
//             let a_at_b = dk.decrypt(&enc_a_at_b).unwrap();
//             assert_eq!(a_at_b, signed_modulo(&(&a * &b), ek.n()));
//         }
//     }
// }

// #[test]
// fn encryption_with_known_factorization() {
//     let mut rng = rand_dev::DevRng::new();
//     let dk = random_key_for_tests(&mut rng);
//     let ek = dk.encryption_key();

//     for i in 0..100 {
//         println!("Iteration {i}");
//         let x = get_uniform_random_integer_from_inclusive_range(
//             &mut random_primitive_ints(EXAMPLE_SEED),
//             -ek.n().clone(),
//             ek.n().clone(),
//         );
//         let x = x - ek.half_n();

//         let nonce = utils::sample_in_mult_group(&mut rng, ek.n());

//         let enc_x1 = ek.encrypt_with(&x, &nonce).unwrap();
//         let enc_x2 = dk.encrypt_with(&x, &nonce).unwrap();

//         assert_eq!(enc_x1, enc_x2);
//     }
// }

// #[test]
// fn factorized_exp_mod_n() {
//     let mut rng = rand_dev::DevRng::new();

//     let p = utils::generate_safe_prime(&mut rng, 512);
//     let q = utils::generate_safe_prime(&mut rng, 512);
//     let n = (&p * &q);
//     println!("n: {n}");

//     let crt = utils::CrtExp::build_n(&p, &q).unwrap();

//     for _ in 0..100 {
//         let x: Integer = n
//             .random_below_ref(&mut utils::external_rand(&mut rng))
//             .into();
//         let mut e: Integer = Integer::random_bits(1024, &mut utils::external_rand(&mut rng)).into();
//         if rng.gen::<bool>() {
//             e = -e
//         }
//         let crt_e = crt.prepare_exponent(&e);

//         println!();
//         println!("x: {x}");
//         println!("e: {e}");

//         let expected: Integer = x.pow_mod_ref(&e, &n).unwrap().into();
//         let actual = crt.exp(&x, &crt_e).unwrap();
//         assert_eq!(expected, actual);
//     }
// }

// #[test]
// fn factorized_exp_mod_nn() {
//     let mut rng = rand_dev::DevRng::new();

//     let p = utils::generate_safe_prime(&mut rng, 512);
//     let q = utils::generate_safe_prime(&mut rng, 512);
//     let nn = (&p * &q).square();
//     println!("nn: {nn}");

//     let crt = utils::CrtExp::build_nn(&p, &q).unwrap();

//     for _ in 0..100 {
//         let x: Integer = nn
//             .random_below_ref(&mut utils::external_rand(&mut rng))
//             .into();
//         let mut e: Integer = Integer::random_bits(1024, &mut utils::external_rand(&mut rng)).into();
//         if rng.gen::<bool>() {
//             e = -e
//         }
//         let crt_e = crt.prepare_exponent(&e);

//         println!();
//         println!("x: {x}");
//         println!("e: {e}");

//         let expected: Integer = x.pow_mod_ref(&e, &nn).unwrap().into();
//         let actual = crt.exp(&x, &crt_e).unwrap();
//         assert_eq!(expected, actual);
//     }
// }

// /// Takes `x mod n` and maps result to `{-N/2, .., N/2}`
// fn signed_modulo(x: &Integer, n: &Integer) -> Integer {
//     let x = x.modulo_ref(n);
//     unsigned_mod_to_signed(x, n)
// }

// /// Maps `{0, .., N-1}` to `{-N/2, .., N/2}`
// fn unsigned_mod_to_signed(x: Integer, n: &Integer) -> Integer {
//     if (Integer::from(2) * &x) >= *n {
//         x - n
//     } else {
//         x
//     }
// }

fn random_key_for_tests(rng: &mut (impl RngCore + CryptoRng)) -> DecryptionKey {
    let n_size = 2048;
    let a_size = 448;

    DecryptionKey::generate(rng, n_size, a_size).unwrap()
}
