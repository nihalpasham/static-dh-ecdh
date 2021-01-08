
// #![allow(warnings)]
use static_dh_ecdh::ecdh::ecdh::{ECDHNISTP256, KeyExchange, ToBytes};


fn main() {
    let alice_sk = ECDHNISTP256::generate_private_key([13; 32]);
    let alice_pk = ECDHNISTP256::generate_public_key(&alice_sk);

    let bob_sk = ECDHNISTP256::generate_private_key([14; 32]);
    let bob_pk = ECDHNISTP256::generate_public_key(&bob_sk);

    let alice_ss = ECDHNISTP256::generate_shared_secret(&alice_sk, &bob_pk);
    let bob_ss = ECDHNISTP256::generate_shared_secret(&bob_sk, &alice_pk);

    assert_eq!(alice_ss, bob_ss);
    println!("alice_ss: {:x}", alice_ss.unwrap().to_bytes());
    println!("bob_ss:   {:x}", bob_ss.unwrap().to_bytes());

    // let bytes = p256::EncodedPoint::from(alice_ss.unwrap().0);
    // let bytes2 = p256::EncodedPoint::from(bob_ss.unwrap().0);

    // println!("256_s_y: {:x}", bytes.y().unwrap());
    // println!("256_s_y: {:x}", bytes2.y().unwrap());

    // println!("{:x?}", alice_sk.to_bytes());
    // println!("{:x?}", bob_sk.to_bytes());

}