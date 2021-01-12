
// #![allow(warnings)]

use p384::{EncodedPoint};
use static_dh_ecdh::signatures::{ECDSASHA256Signature, ECDSASHA384Signature, ECSignature};


fn main () {
    let data = b"ECDSA proves knowledge of a secret number in the context of a single message";
    let mut signer = ECDSASHA256Signature([0; 32], [0; 64]);
    let _keys = signer.generate_keypair([12; 32]);  // test seed value
    let signature = signer.sign(data).unwrap();
    let v = signer.verify(data, &signature.as_ref());

    println!("verified_256: {:?}", v);
    println!("r256: {:?}", ECDSASHA256Signature::r(signature));
    println!("s256: {:?}", ECDSASHA256Signature::s(signature));

    let data = b"ECDSA proves knowledge of a secret number in the context of a single message";
    let mut signer = ECDSASHA384Signature([0; 48], EncodedPoint::identity());
    let _keys = signer.generate_keypair([12; 32]); // test seed value
    let signature = signer.sign(data).unwrap();
    let v = signer.verify(data, &signature.as_ref());
    
    println!("verified_384: {:?}", v);
    println!("r384: {:?}", ECDSASHA384Signature::r(signature));
    println!("s384: {:?}", ECDSASHA384Signature::s(signature));

}