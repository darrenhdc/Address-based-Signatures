#![feature(test)]
pub mod protocols;
extern crate test;
use test::Bencher;
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
use protocols::gc2_ecdsa;


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

#[bench]
fn Addr_Based_Schnorr_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s2 = addr_schnorr::Addr_Based_Schnorr_Setup::keygen();
    b.iter(||{
        s2.sign(&message);
    });
}

#[bench]
fn Addr_Based_Schnorr_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s2 = addr_schnorr::Addr_Based_Schnorr_Setup::keygen();
    let sig2 = s2.sign(&message);
    b.iter(||{
        addr_schnorr::Addr_Based_Schnorr_Setup::verify(&sig2, &&message, &s2.A);
    });
}

#[bench]
fn Our_Addr_Based_Signature_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s3 = addr_sig::Addr_Based_Setup::keygen();
    b.iter(||{
        s3.sign(&message);
    });
}

#[bench]
fn Our_Addr_Based_Signature_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s3 = addr_sig::Addr_Based_Setup::keygen();
    let sig3 = s3.sign(&message);
    b.iter(||{
        addr_sig::Addr_Based_Setup::verify(&sig3, &message, &s3.A);
    });
}

#[bench]
fn Original_ECDSA_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s4 = ecdsa::Original_ECDSA_Setup::keygen();
    b.iter(||{
        s4.sign(&message);
    });
}

#[bench]
fn Original_ECDSA_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s4 = ecdsa::Original_ECDSA_Setup::keygen();
    let sig4 = s4.sign(&message);
    b.iter(||{
        ecdsa::Original_ECDSA_Setup::verify(&sig4,&s4.X, &message);
    });
}

#[bench]
fn Original_Schnorr_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s5 = schnorr::Original_Schnorr_Setup::keygen();
    b.iter(||{
        s5.sign(&message);
    });
}

#[bench]
fn Original_Schnorr_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s5 = schnorr::Original_Schnorr_Setup::keygen();
    let sig5 = s5.sign(&message);
    b.iter(||{
        schnorr::Original_Schnorr_Setup::verify(&s5.X, &sig5, &message);
    });
}

#[bench]
fn GC1_Key_prefix_Schnorr_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s7 = gc1_keyprfx_schnorr::GC1_Key_prefix_Schnorr_Setup::keygen();
    b.iter(||{
        s7.sign(&message);
    });
}

#[bench]
fn GC1_Key_prefix_Schnorr_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s7 = gc1_keyprfx_schnorr::GC1_Key_prefix_Schnorr_Setup::keygen();
    let sig7 = s7.sign(&message);
    b.iter(||{
        gc1_keyprfx_schnorr::GC1_Key_prefix_Schnorr_Setup::verify(&s7.A, &sig7, &message);
    });
}

#[bench]
fn GC2_Key_prefix_Schnorr_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s8 = gc2_keyprfx_schnorr::GC2_Key_prefix_Schnorr_Setup::keygen();
    b.iter(||{
        s8.sign(&message);
    });
}

#[bench]
fn GC2_Key_prefix_Schnorr_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s8 = gc2_keyprfx_schnorr::GC2_Key_prefix_Schnorr_Setup::keygen();
    let sig8 = s8.sign(&message);
    b.iter(||{
        gc2_keyprfx_schnorr::GC2_Key_prefix_Schnorr_Setup::verify(&s8.A, &s8.X, &sig8, &message);
    });
}

#[bench]
fn GC2_ECDSA_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s9 = gc2_ecdsa::GC2_ECDSA_Setup::keygen();
    b.iter(||{
        s9.sign(&message);
    });
}

#[bench]
fn GC2_ECDSA_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s9 = gc2_ecdsa::GC2_ECDSA_Setup::keygen();
    let sig9 = s9.sign(&message);
    b.iter(||{
        gc2_ecdsa::GC2_ECDSA_Setup::verify(&sig9, &s9.X, &message, &s9.A);
    });
}

fn main() {
    let message: BigInt = BigInt::from(12345);
    let s1 = addr_ecdsa::Addr_Based_ECDSA_Setup::keygen();
    // let sig1 = s1.sign(&message);
    // let ret1 = addr_ecdsa::Addr_Based_ECDSA_Setup::verify(&sig1, &message, &s1.A);
    // println!("addr_ecdsa_verify:{}",ret1); 
/*
    let s2 = addr_schnorr::Addr_Based_Schnorr_Setup::keygen();
    let sig2 = s2.sign(&message);
    let ret2 = addr_schnorr::Addr_Based_Schnorr_Setup::verify(&sig2, &&message, &s2.A);
    println!("addr_based_schnorr_verify:{}",ret2);

    let s3 = addr_sig::Addr_Based_Setup::keygen();
    let sig3 = s3.sign(&message);
    let ret3 = addr_sig::Addr_Based_Setup::verify(&sig3, &message, &s3.A);
    println!("our_addr_sig_verify:{}",ret3);

    let s4 = ecdsa::Original_ECDSA_Setup::keygen();
    let sig4 = s4.sign(&message);
    let ret4 = ecdsa::Original_ECDSA_Setup::verify(&sig4,&s4.X, &message);
    println!("original_ecdsa_verify:{}",ret4);

    let s5 = schnorr::Original_Schnorr_Setup::keygen();
    let sig5 = s5.sign(&message);
    let ret5 = schnorr::Original_Schnorr_Setup::verify(&s5.X, &sig5, &message);
    println!("original_schnorr_verify:{}",ret5);

    let s6 = keyprefix_schnorr::Key_prefix_Schnorr_Setup::keygen();
    let sig6 = s6.sign(&message);
    let ret6 = keyprefix_schnorr::Key_prefix_Schnorr_Setup::verify(&s6.X, &sig6, &message);
    println!("key_prefix_schnorr_verify:{}",ret6);

    let s7 = gc1_keyprfx_schnorr::GC1_Key_prefix_Schnorr_Setup::keygen();
    let sig7 = s7.sign(&message);
    let ret7 = gc1_keyprfx_schnorr::GC1_Key_prefix_Schnorr_Setup::verify(&s7.A, &sig7, &message);
    println!("gc1_key_prefix_schnorr_verify:{}",ret7);

    let s8 = gc2_keyprfx_schnorr::GC2_Key_prefix_Schnorr_Setup::keygen();
    let sig8 = s8.sign(&message);
    let ret8 = gc2_keyprfx_schnorr::GC2_Key_prefix_Schnorr_Setup::verify(&s8.A, &s8.X, &sig8, &message);
    println!("gc2_key_prefix_schnorr_verify:{}",ret8);

    let s9 = gc2_ecdsa::GC2_ECDSA_Setup::keygen();
    let sig9 = s9.sign(&message);
    let ret9 = gc2_ecdsa::GC2_ECDSA_Setup::verify(&sig9, &s9.X, &message, &s9.A);
    println!("gc2_ecdsa_verify:{}",ret9);
*/
    // let pk = GE::generator();
    // let s = serde_json::to_string(&pk).expect("Failed in serialization");
    // println!("s:{}",s);
    // let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
    // assert_eq!(des_pk, pk);

    // let g = GE::generator();
    // let hash = HSha256::create_hash(&vec![&g.bytes_compressed_to_big_int()]);
    // let hash_vec = BigInt::to_vec(&hash);
    // let result = GE::from_bytes(&hash_vec).unwrap();
    // // assert_eq!(result.unwrap_err(), ErrorKey::InvalidPublicKey);
    // assert_eq!(g, result);

    // p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    let p = str::parse(
        "115792089237316195423570985008687907853269984665640564039457584007908834671663",
    )
    .unwrap();
    let g1 = GE::generator() * &ECScalar::from(&BigInt::from(3));
    // let g1 = GE::generator();
    let x = g1.x_coor().unwrap();
    let y2 = (&x * &x * &x + BigInt::from(7)).mod_floor(&p);
    let y = y2.sqrt();//.mod_floor(&p);
    assert_eq!(y.pow(2).mod_floor(&p), y2);
    assert_eq!(g1.y_coor().unwrap().pow(2).mod_floor(&p), y2);

    println!("Hello, world!");
}

    

