
// #![allow(warnings)]
use static_dh_ecdh::ecdh::ecdh::{ECDHNISTP384, KeyExchange, ToBytes};

fn main () {
    let alice_sk = ECDHNISTP384::<48>::generate_private_key([12; 32]);
    let alice_pk = ECDHNISTP384::<48>::generate_public_key(&alice_sk);

    let bob_sk = ECDHNISTP384::<48>::generate_private_key([21; 32]);
    let bob_pk = ECDHNISTP384::<48>::generate_public_key(&bob_sk);

    let alice_ss = ECDHNISTP384::<48>::generate_shared_secret(&alice_sk, &bob_pk);
    let bob_ss = ECDHNISTP384::<48>::generate_shared_secret(&bob_sk, &alice_pk);

    assert_eq!(alice_ss, bob_ss);

    println!("alice_ss: {:x}", &alice_ss.unwrap().to_bytes()); 
    println!("bob_ss:   {:x}", &bob_ss.unwrap().to_bytes());

    // println!("alice_ss: {:x}", &alice_ss.unwrap().0.y().unwrap());  // y co-ord (alice)
    // println!("bob_ss:   {:x}", &bob_ss.unwrap().0.y().unwrap());    // y co-ord (bob)

    // println!("{:x?}", alice_sk.to_bytes());
    // println!("{:x?}", bob_sk.to_bytes());
}