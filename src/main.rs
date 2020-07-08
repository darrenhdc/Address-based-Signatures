#![feature(test)]
pub mod protocols;

use protocols::bls_sig;
use protocols::bb_sig;
use protocols::addr_schnorr;
use protocols::addr_ecdsa;
use protocols::addr_sig;
use protocols::keyprefix_schnorr;
use protocols::gc1_keyprfx_schnorr;
use protocols::gc2_keyprfx_schnorr;
use protocols::schnorr;
use protocols::ecdsa;

use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};

// H: G->{0,1}^160
pub fn Hash(input: &GE) -> BigInt {
    let two_pow_160 = BigInt::ui_pow_ui(2, 160);
    HSha256::create_hash(&[
        &input.bytes_compressed_to_big_int(),
    ])
    .mod_floor(&two_pow_160)
}

// H
pub fn reversible_hash(input: &GE) -> std::string::String {
    serde_json::to_string(&input).expect("Failed in serialization")
}

// H^-1, didn't add the error output
pub fn reversible_hash_recover_pk(s: &std::string::String) -> GE {
    serde_json::from_str(&s).expect("Failed in deserialization")

// // H
// pub fn reversible_hash(input: &GE) -> BigInt {
//     HSha256::create_hash(&vec![&input.bytes_compressed_to_big_int()])
// }

// // H^-1, didn't add the error output
// pub fn reversible_hash_recover_pk(hash: BigInt) -> GE {
//     let hash_vec =  BigInt::to_vec(&hash);
//     GE::from_bytes(&hash_vec).unwrap()
}


fn main() {
    // let pk = GE::generator();
    // let s = serde_json::to_string(&pk).expect("Failed in serialization");
    // println!("s:{}",s);
    // let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
    // assert_eq!(des_pk, pk);

    let g = GE::generator();
    // let hash = HSha256::create_hash(&vec![&g.bytes_compressed_to_big_int()]);
    // let hash_vec = BigInt::to_vec(&hash);
    // let result = GE::from_bytes(&hash_vec).unwrap();
    // // assert_eq!(result.unwrap_err(), ErrorKey::InvalidPublicKey);
    // assert_eq!(g, result);

    let q = FE::q();
    let x = g.x_coor().unwrap();
    let y2 = (&x * &x * &x + BigInt::from(7)).mod_floor(&FE::q());
    // let y = y2.sqrt().mod_floor(&FE::q());
    assert_eq!(g.y_coor().unwrap().pow(2).mod_floor(&FE::q()), y2);

    println!("Hello, world!");
}
