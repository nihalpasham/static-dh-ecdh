
![crypto-code-decipher](https://user-images.githubusercontent.com/20253082/104021017-11ebee00-51e4-11eb-9663-ba8845a8ffcc.jpg "Fun encrypted text")

## What is it?

Pure Rust implementations of **static Diffie-Hellman key-exchange and ECDSA**. It includes `impls` for both plain vanilla DH, elliptic-curve DH along with ECDSA impls for p256, p384.
- The standard DH implementation is a (vanilla) object oriented api. It has support for multiple DH Groups DH5, DH14, DH15, DH16, DH17, DH18. 
- The ECDH implementation comes with a textbook implementation of `Affine-Point` arithemtic as `Projective-Point` arithmetic in RustCrypto is only implemented for curves p256, secp256k1 and support for more curves is on the cards but not yet available.
- ECDSA impls use the ECDH module for key generation. 
- The crate makes use of `min-const-generics` extensively for code-reuse. You'll need rust-1.51 which has added support for it. `min-const-generics` is now stable on `rust-nightly`. 

## Usage: 

```Rust
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

}
```
### Output:

```sh
   Compiling static-dh-ecdh v0.1.0 (C:\Users\Nil\devspace\rust\projects\static-ecdh)
    Finished dev [unoptimized + debuginfo] target(s) in 3.84s
     Running `target\debug\examples\ecdh_p384_curve.exe`   

alice_ss: 66e078e64405a21f61324f23ecc3eaa1376105e4aea83b632625cb4bd1afdb8cb26295c2d20cb89d4af87735491b4214
bob_ss:   66e078e64405a21f61324f23ecc3eaa1376105e4aea83b632625cb4bd1afdb8cb26295c2d20cb89d4af87735491b4214
```

```Rust

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
```
### Output:

```sh

    Finished dev [unoptimized + debuginfo] target(s) in 0.11s
     Running `target\debug\examples\signatures_test.exe`     

verified_256: Ok(true)
r256: [196, 233, 13, 80, 251, 14, 164, 68, 13, 130, 177, 28, 244, 209, 119, 121, 79, 202, 214, 127, 124, 220, 31, 10, 196, 233, 219, 21, 82, 130, 32, 94]  
s256: [156, 131, 138, 215, 204, 167, 103, 102, 47, 2, 88, 246, 171, 235, 128, 210, 180, 243, 74, 72, 20, 75, 26, 178, 185, 58, 183, 245, 209, 186, 33, 162]

verified_384: Ok(true)
r384: [109, 4, 148, 3, 54, 155, 152, 101, 150, 29, 132, 220, 207, 181, 248, 248, 74, 150, 212, 247, 43, 110, 113, 200, 116, 197, 243, 194, 45, 100, 173, 250, 230, 155, 
9, 145, 50, 250, 189, 59, 59, 40, 149, 133, 117, 121, 103, 88]
s384: [183, 102, 204, 199, 243, 16, 212, 232, 50, 154, 154, 87, 92, 167, 101, 87, 222, 7, 15, 182, 219, 143, 178, 57, 2, 15, 162, 104, 160, 201, 5, 163, 31, 205, 21, 172, 160, 200, 142, 227, 253, 135, 53, 129, 29, 139, 20, 230]
```

**Imp:** This crate does not in anyway aim to replace `RustCrypto ECC impls`. I'm working on a `prototype` networking protocol that needs ECDH. and RustCrypto doesn't support a few curves (p-521 and Brainpool) yet. It also doesnt have `out-of-the-box support` for `static ECDH` for implemented curves. So, I put this together. 

## Caveats:

With that in mind, here are the caveats
- This crate has **NOT** been tested (it only includes a few working examples)
- Performance was not a consideration - the arithmetic used in this crate is the textbook version of `Affine-Point` math and relies on the `num_bigint_dig` crate. Although, preliminary testing seems to indicate that its (actually) good. My assumption is `num_bigint_dig` is the cause but cannot confirm.
- It is a `no_std lib` but its not dynamic-memory allocation free as num_bigint_dig relies on `alloc`.
- `Side-channel` attacks have not been considered no attention has been paid to things like `constant time equality` operations. 
- This crate borrows some of its types from RustCrypto's elliptic-curve library so as to build a uniform api and make it easy to integrate `rustcrypto-ecc` for when it adds support for other curves.
- This crate includes curves that are not yet supported (or fully supported) by the RustCrypto project. List of supported curves  -
    - **p256** - This is the 1 impl in this crate that you could probably use in a production environment as it was `lifted` (in an as-is from) from a pretty well-tested crate - `rust-hpke`, which in-turn uses RustCrypto's p256 crate as its base crate.
    - **P384** - Implemented with `Affine-Point` math and a few additional types from RustoCrypto library. 
    - **P521** - support to be added *(the impl will be similar to P384)*
    - **Brainpool** - supported to be added *(the impl will be pretty similar to P384)*