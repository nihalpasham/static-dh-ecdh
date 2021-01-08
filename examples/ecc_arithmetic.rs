// #![allow(warnings)]

use static_dh_ecdh::ecdh::affine_math::{APTypes, MyAffinePoint};
use static_dh_ecdh::{constants, dh::dh};

use num_bigint_dig::{BigInt, BigUint, Sign};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn main() {
    // Get constants
    let mod_prime =
        dh::unhexlify_to_bytearray::<48>(&constants::ECDH_NIST_384_MODP.replace("0x", ""));
    let b_val = dh::unhexlify_to_bytearray::<48>(&constants::ECDH_NIST_384_B_VAL.replace("0x", ""));

    let a = BigInt::from(-3);
    let b = BigInt::from_bytes_be(Sign::Plus, &b_val);
    let modp = BigInt::from_bytes_be(Sign::Plus, &mod_prime);

    // Generate Private keys
    let mut rng = ChaCha20Rng::from_seed([13; 32]); // test seed value.
    let mut dest = [0; 48];
    rng.fill_bytes(&mut dest);
    let alice_sk = BigUint::from_bytes_be(&dest);
    println!("alice_sk: {}", &alice_sk);

    let mut rng2 = ChaCha20Rng::from_seed([14; 32]); // test seed value.
    let mut dest2 = [0; 48];
    rng2.fill_bytes(&mut dest2);
    let bob_sk = BigUint::from_bytes_be(&dest2);
    println!("bob_sk: {}", &bob_sk);

    // Derive Public keys
    let gen = MyAffinePoint::<48>::generator();
    let alice_pk = match gen {
        APTypes::P384(gen) => {
            let pub_key = MyAffinePoint::<48>::double_and_add(
                gen,
                alice_sk.clone(),
                &a,
                &b,
                &modp,
            );
            println!("alice_pkx: {}", pub_key.x);
            println!("alice_pky: {}", pub_key.y);
            pub_key
        }
        _ => unreachable!(),
    };

    let gen2 = MyAffinePoint::<48>::generator();
    let bob_pk = match gen2 {
        APTypes::P384(gen) => {
            let pub_key = MyAffinePoint::<48>::double_and_add(gen, bob_sk.clone(), &a, &b, &modp);
            println!("bob_pkx: {:x}", pub_key.x);
            println!("bob_pky: {:x}", pub_key.y);
            pub_key
        }

        _ => unreachable!(),
    };

    // Evaluate Shared secret keys
    let alice_ss = MyAffinePoint::<48>::double_and_add(bob_pk, alice_sk.clone(), &a, &b, &modp);
    let bob_ss = MyAffinePoint::<48>::double_and_add(alice_pk, bob_sk.clone(), &a, &b, &modp);
    
    assert_eq!(alice_ss, bob_ss);

    println!("alice_ss: {:x}", &alice_ss.x);
    println!("alice_ss: {:x}", &alice_ss.y);

    println!("bob_ss: {:x}", &bob_ss.x);
    println!("bob_ss: {:x}", &bob_ss.y);

}

//   let bitarray = MyAffinePoint::<48>::to_bit_array(private_key1.clone(), false);
//     if let BitArrayTypes::P384(bit_array) = bitarray {
//         println!("{:?}", bit_array);
//         println!("{:?}", bit_array.len());
//     }
