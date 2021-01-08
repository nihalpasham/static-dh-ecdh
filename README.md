
![crypto-code-decipher](https://user-images.githubusercontent.com/20253082/104021017-11ebee00-51e4-11eb-9663-ba8845a8ffcc.jpg "Fun encrypted text")

## What is it?

Pure Rust implementations of static Diffie-Hellman key-exchange. It includes `impls` for both plain vanilla DH and elliptic-curve DH.
- The standard DH implementation is a (vanilla) object oriented api. It has support for multiple DH Groups DH5, DH14, DH15, DH16, DH17, DH18. 
- The ECDH implementation comes with a textbook implementation of `Affine-Point` arithemtic as `Projective-Point` arithmetic in RustCrypto is only implemented for curves p256, secp256k1 and support for more curves is on the cards but not yet available. 
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

**Imp:** This crate does not in anyway aim to replace `RustCrypto ECC impls`. I'm working on a `prototype` networking protocol that needs ECDH. and RustCrypto doesn't support a few curves (p-521 and Brainpool) yet. It also doesnt have `out-of-the-box support` for `static ECDH` for implemented curves. So, I put this together. 

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