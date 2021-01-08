
#![allow(warnings)]

use static_dh_ecdh::dh::dh::{DH5, DH14, DH15, DH16, DH17, DH18};

fn main(){
    let mut alice = DH15::new();
    alice.init_dh15();
    let alice_pk = alice.generate_private_key();
    let alice_pub_key = alice.generate_pubic_key();
 
    let mut bob = DH15::new();
    bob.init_dh15();
    let bob_pk = bob.generate_private_key();
    let bob_pub_key = bob.generate_pubic_key();
    
    let bob_shared_secret = bob.compute_shared_secret(alice_pub_key);
    let alice_shared_secret = alice.compute_shared_secret(bob_pub_key);

    assert_eq!(alice_shared_secret, bob_shared_secret);
    
    println!("alice_shared_secret: {}", alice_shared_secret);
    println!("bob_shared_secret:   {}", bob_shared_secret);
    
    println!("alice_private_key: {}", alice.private_key);
    println!("bob_private_key:   {}", bob.private_key);

}