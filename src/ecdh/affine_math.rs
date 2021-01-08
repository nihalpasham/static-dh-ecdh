#![allow(warnings)]

use core::convert::TryInto;
// use libc_print::libc_println;
use num_bigint_dig::{BigInt, BigUint, Sign, ModInverse};
use num_traits::{Zero};
use generic_array::GenericArray;
use p384::EncodedPoint;

use super::ecdh::{PkP384, SharedSecretP384};

/// An enum for the various types of AffinePoint(s)
#[derive(Debug, Clone, PartialEq)]
pub enum APTypes {
    /// Affine-Point Type for a point curve NIST-p384
    P384(MyAffinePoint<48>),
    /// Affine-Point Type for a point curve NIST-p521
    P521(MyAffinePoint<66>),
    /// Placeholder for more Affine-Point Types
    __Nonexhaustive,
}

/// An enum to hold the various types of BitArrays required for `affine-point math`.
#[derive(Debug, Clone, PartialEq)]
pub enum BitArrayTypes {
    /// A variant to hold BitArrayType for p384
    P384([u8; 48 * 8]),
    /// A variant to hold BitArrayType for p521
    P521([u8; 66 * 8]),
    /// Placeholder variant to hold BitArrayTypes
    __Nonexhaustive,
}

/// An enum to hold `EncodedPoint` Types. This is just a holder for various types of RustCrypto `EncodedPoint`(s) Types  
/// included in the `elliptic-curve` library  
#[derive(Debug, Clone, PartialEq)]
pub enum EncodedTypes {
    /// An EncodedPoint type for p384
    EncodedTypeP384(PkP384),
    /// An EncodedPoint type for p521
    EncodedTypeP384_SS(SharedSecretP384),
    /// Placeholder variant to hold EncodedPoint types
    __Nonexhaustive,
}

/// Affine coordinates are the conventional way of expressing elliptic curve points in two dimensional space i.e. (x, y)
/// Typically, `x and y` are 2 very large integers (in the order of say 256 or 384 bits, hence the name). In ECC, points on 
/// the curve are represented as some integer modulo a prime number. 
///
/// Infinity - is just a special point usually named `O`. Its also referred to as the identity element of a prime field.
#[derive(Debug, Clone, PartialEq)]
pub struct MyAffinePoint<const N: usize> {
    /// The x co-ordinate of a elliptic curve point modulo a prime 
    pub x: BigInt,
    /// The y co-ordinate of a elliptic curve point modulo a prime 
    pub y: BigInt,
    /// Is just a special point usually named `O`. In our case that's - (0,0, true) 
    pub infinity: bool,
}

impl<const N: usize> MyAffinePoint<N> {
    /// Returns the base point of a NIST p-cURVE.
    pub fn generator() -> APTypes {
        match N {
            // NIST P-384 basepoint in affine coordinates:
            // x = aa87ca22 be8b0537 8eb1c71ef 320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7
            // y = 3617de4a 96262c6f 5d9e98bf9 292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f
            48 => { // Is this expected? The compiler cant seem to tell that the generic constant `N` equals `48`in a `matched` arm. I'm
                    // assuming the compiler has access to this information at compile time.  
                let x: [u8; 48] = [
                    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3,
                    0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7,
                    0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29,
                    0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
                ];
                let y: [u8; 48] = [
                    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92,
                    0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda,
                    0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81,
                    0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
                ];

                APTypes::P384(MyAffinePoint {
                    x: BigInt::from_bytes_be(Sign::Plus, &x),
                    y: BigInt::from_bytes_be(Sign::Plus, &y),
                    infinity: false,
                })
            }

            66 => APTypes::__Nonexhaustive,
            _ => APTypes::__Nonexhaustive,
        }
    }

    /// Returns the identity of the group: the point at infinity.
    pub fn identity() -> MyAffinePoint<N> {
        Self {
            x: Zero::zero(),
            y: Zero::zero(),
            infinity: true,
        }
    }

    /// Is this point the identity point?
    pub fn is_identity(&self) -> bool {
        self.infinity
    }

    /// This method performs the actual math i.e. `POINT doubling` and `addition` operations. In very simple terms, 
    /// this method calculates the result of multiplying (which in ECC arithmetic doubling or adding to itself) the generator point
    /// with that of a private scalar value. (PS - if you're wondering, the scalar itself is huge number - 32 bytes for P256 or 48 for P384)
    ///
    /// Note - This is a texbook implementation taken from RFC https://tools.ietf.org/html/rfc6090#section-3
    pub fn do_the_math(
        &self,
        pointP: MyAffinePoint<N>,
        a: &BigInt,
        b: &BigInt,
        modp: &BigInt,
    ) -> MyAffinePoint<N> {
        if bool::from(self.is_identity()) && bool::from(pointP.infinity) {
            Self::identity()
        } else if bool::from(self.is_identity()) {
            pointP
        } else if bool::from(pointP.infinity) {
            MyAffinePoint {
                x: self.x.clone(),
                y: self.y.clone(),
                infinity: false,
            }
        } else {
            // Point doubling when bitarray[i] == 0
            if pointP.x == self.x && pointP.y == self.y {
                let y1 = self.y.clone();
                let x1 = self.x.clone();
                let t = ((2u8 * &y1) % modp).mod_inverse(modp).unwrap();
                let slope = (((3u8 * &x1 * &x1) + a) * t) % modp;
                let x3 = ((&slope * &slope) - (2u8 * &x1)) % modp;
                let y3 = (&slope * (&x1 - &x3) - &y1) % modp;

                MyAffinePoint {
                    x: x3,
                    y: y3,
                    infinity: false,
                }
            } else if (pointP.x == self.x) && pointP.y == -self.y.clone() {
                Self::identity()
            } else if pointP.x != self.x || pointP.y != self.y {
                // Point addition when bitarray[i] == 1
                let y1 = self.y.clone();
                let x1 = self.x.clone();
                let y2 = pointP.y;
                let x2 = pointP.x;
                let t1 = (&x2 - &x1).mod_inverse(modp).unwrap();
                let slope = ((&y2 - &y1) * t1) % modp;
                let x3 = (&slope * &slope - &x1 - &x2) % modp;
                let y3 = (&slope * (&x1 - &x3) - &y1) % modp;

                MyAffinePoint {
                    x: x3,
                    y: y3,
                    infinity: false,
                }
            } else {
                unreachable!()
            }
        }
    }

    /// Using `group law`, it is easy to `add` points together and to `multiply` a point by an integer,
    /// but very hard to work backwards to `divide` a point by a number; this asymmetry is the basis for elliptic
    /// curve cryptography.
    ///
    /// This function performs the point doubling and addition operations, given a nonzero scalar value (i.e. private key) and a
    /// generator point or a public key value (which is just another point). It is used to do 2 things - generate a public key or
    /// a shared secret/key.
    pub fn double_and_add(
        g: MyAffinePoint<N>,
        k: BigUint,
        a: &BigInt,
        b: &BigInt,
        modp: &BigInt,
    ) -> MyAffinePoint<N> {
        let bits = Self::to_bit_array(k, false);
        let mut p = Self::identity();
        let mut q = g;
        // let mut counter: u16 = 0;
        match bits {
            BitArrayTypes::P384(bitarray) => {
                for i in 0..bitarray.len() {
                    if bitarray[i] == 1 {
                        if q == Self::identity() {
                            return Self::identity();
                        } else {
                            // counter += 1;
                            // libc_println!("counter: {:?}", &counter);
                            p = p.do_the_math(q.clone(), a, b, modp);
                        }
                    }
                    q = q.do_the_math(q.clone(), a, b, modp);
                }
                if p.y.sign() == Sign::Minus {
                    num_bigint_dig::negate_sign(&mut p.y);
                    p.y = modp - p.y; 
                    // libc_println!("p.y:  {:x}", modp - &p.y);
                    p
                } else { 
                    p
                }
            }
            _ => Self::identity(),
        }
    }

    /// Returns an array of bits i.e. its elements represent a `scalar` bit pattern.
    /// Note - this function takes a +ve scalar value.
    pub fn to_bit_array(mut scalar: BigUint, reverse: bool) -> BitArrayTypes {
        match N {
            48 => {
                let mut bit_array = [0u8; 48 * 8]; // Need full featured `const_generics` to make this array generic
                let mut i = 0;
                while &scalar > &BigUint::from(0u8) {
                    let r = scalar.clone() & BigUint::from(1u8);
                    scalar >>= 1;
                    let rclone: [u8; 1] = r.clone().to_bytes_be().try_into().unwrap();
                    bit_array[i] = rclone[0];
                    i += 1;
                }
                if reverse {
                    bit_array.reverse();
                }
                BitArrayTypes::P384(bit_array)
            }
            _ => BitArrayTypes::__Nonexhaustive,
        }
    }

    /// A method to transform `MyAffinePoint` types into RustCrypto's `EncodedPoint`. Encoded points
    /// are the uncompressed form of a point on the curve 
    pub fn to_uncompressed_bytes(&self, ss: bool) -> EncodedTypes {
        match N {
            48 => {
                let mut bytes = GenericArray::default();
                let pub_key_x: [u8; N] = self
                    .x
                    .to_bytes_be()
                    .1
                    .try_into()
                    .expect("failed to serialize pub_x to bytearray");
                let pub_key_y: [u8; N] = self
                    .y
                    .to_bytes_be()
                    .1
                    .try_into()
                    .expect("failed to serialize pub_y to bytearray");
                bytes[..pub_key_x.len()].copy_from_slice(&pub_key_x);
                bytes[pub_key_x.len()..].copy_from_slice(&pub_key_y);
                if ss {
                    EncodedTypes::EncodedTypeP384_SS(SharedSecretP384(EncodedPoint::from_untagged_bytes(&bytes)))
                } else {
                    EncodedTypes::EncodedTypeP384(PkP384(EncodedPoint::from_untagged_bytes(&bytes)))
                }
            }
            _ =>  EncodedTypes::__Nonexhaustive,

        }
    }
}

impl<const N: usize> Default for MyAffinePoint<N> {
    /// Default impl for `MyAffinePoint` point. Returns the identity element.
    fn default() -> Self {
        Self::identity()
    }
}