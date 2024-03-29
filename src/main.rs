#![feature(test)]
pub mod protocols;
extern crate test;
use test::Bencher;
use protocols::BLS_sig;
use protocols::BB_sig;
use protocols::gc1_BLS_sig;
use protocols::gc1_BB_sig;
use protocols::gc2_BLS_sig;
use protocols::gc2_BB_sig;
use protocols::addr_schnorr;
use protocols::addr_ecdsa;
use protocols::addr_sig;
use protocols::keyprefix_schnorr;
use protocols::gc1_keyprfx_schnorr;
use protocols::gc2_keyprfx_schnorr;
use protocols::schnorr;
use protocols::ecdsa;
use protocols::gc2_ecdsa;

use gmp::mpf::Mpf;

use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};
use rustc_serialize::{Encodable, Decodable};
use rustc_serialize::hex::{FromHex, ToHex};

use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};


pub fn into_hex<S: Encodable>(obj: S) -> Option<String> {
    encode(&obj, Infinite).ok().map(|e| e.to_hex())
}

pub fn from_hex<S: Decodable>(s: &str) -> Option<S> {
    let s = s.from_hex().unwrap();
    decode(&s).ok()
}


// convert typen String to static str
pub fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

// find the solution of x^2 = a mod p
pub fn solve_quadratic_root(a: &BigInt, p: &BigInt) -> BigInt {
    let p: BigInt = str::parse(
        "115792089237316195423570985008687907853269984665640564039457584007908834671663",
    )
    .unwrap();
    // exp = (p+1)/4
    let exp: BigInt = str::parse(
        "28948022309329048855892746252171976963317496166410141009864396001977208667916",
    )
    .unwrap();
    a.powm(&exp, &p)
}

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
/*
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
*/

#[bench]
fn GC2_ECDSA_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s9 = gc2_ecdsa::GC2_ECDSA_Setup::keygen();
    let sig9 = s9.sign(&message);
    b.iter(||{
        gc2_ecdsa::GC2_ECDSA_Setup::verify(&sig9, &s9.X, &message, &s9.A);
    });
}

#[bench]
fn Addr_based_ECDSA_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = addr_ecdsa::Addr_Based_ECDSA_Setup::keygen();
    b.iter(||{
        s1.sign(&message);
    });
}

#[bench]
fn Addr_based_ECDSA_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = addr_ecdsa::Addr_Based_ECDSA_Setup::keygen();
    let sig1 = s1.sign(&message);
    b.iter(||{
        addr_ecdsa::Addr_Based_ECDSA_Setup::verify(&sig1, &message, &s1.A);
    });
}


#[bench]
fn BB_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = BB_sig::BB_Setup::keygen();
    b.iter(||{
        s1.sign(&message);
    });
}

#[bench]
fn BB_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = BB_sig::BB_Setup::keygen();
    let sig1 = s1.sign(&message);
    b.iter(||{
        BB_sig::BB_Setup::verify(s1.X, &sig1, &message);
    });
}

#[bench]
fn BLS_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = BLS_sig::BLS_Setup::keygen();
    b.iter(||{
        s1.sign(&message);
    });
}

#[bench]
fn BLS_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = BLS_sig::BLS_Setup::keygen();
    let sig1 = s1.sign(&message);
    b.iter(||{
        BLS_sig::BLS_Setup::verify(s1.X, &sig1, &message);
    });
}

#[bench]
fn gc1_BB_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = gc1_BB_sig::gc1_BB_Setup::keygen();
    b.iter(||{
        s1.sign(&message);
    });
}

#[bench]
fn gc1_BB_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = gc1_BB_sig::gc1_BB_Setup::keygen();
    let sig1 = s1.sign(&message);
    b.iter(||{
        gc1_BB_sig::gc1_BB_Setup::verify(&s1.A, &sig1, &message);
    });
}

#[bench]
fn gc1_BLS_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = gc1_BLS_sig::gc1_BLS_Setup::keygen();
    b.iter(||{
        s1.sign(&message);
    });
}

#[bench]
fn gc1_BLS_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = gc1_BLS_sig::gc1_BLS_Setup::keygen();
    let sig1 = s1.sign(&message);
    b.iter(||{
        gc1_BLS_sig::gc1_BLS_Setup::verify(&s1.A, &sig1, &message);
    });
}

#[bench]
fn gc2_BB_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = gc2_BB_sig::gc2_BB_Setup::keygen();
    b.iter(||{
        s1.sign(&message);
    });
}

#[bench]
fn gc2_BB_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = gc2_BB_sig::gc2_BB_Setup::keygen();
    let sig1 = s1.sign(&message);
    b.iter(||{
        gc2_BB_sig::gc2_BB_Setup::verify(s1.X, &sig1, &message, &s1.A);
    });
}

#[bench]
fn gc2_BLS_sign(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = gc2_BLS_sig::gc2_BLS_Setup::keygen();
    b.iter(||{
        s1.sign(&message);
    });
}

#[bench]
fn gc2_BLS_verify(b: &mut Bencher) {
    let message = HSha256::create_hash(&[&BigInt::from(12345),]);
    let s1 = gc2_BLS_sig::gc2_BLS_Setup::keygen();
    let sig1 = s1.sign(&message);
    b.iter(||{
        gc2_BLS_sig::gc2_BLS_Setup::verify(s1.X, &sig1, &message, &s1.A);
    });
}

fn main() {
    let message: BigInt = BigInt::from(12345);
    let s1 = addr_ecdsa::Addr_Based_ECDSA_Setup::keygen();
    let sig1 = s1.sign(&message);
    let ret1 = addr_ecdsa::Addr_Based_ECDSA_Setup::verify(&sig1, &message, &s1.A);
    println!("addr_ecdsa_verify:{}",ret1); 
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
    let s10 = BB_sig::BB_Setup::keygen();
    let sig10 = s10.sign(&message);
    let ret10 = BB_sig::BB_Setup::verify(s10.X, &sig10, &message);
    println!("BB_verify:{}",ret10);

    let s11 = gc1_BB_sig::gc1_BB_Setup::keygen();
    let sig11 = s11.sign(&message);
    let ret11 = gc1_BB_sig::gc1_BB_Setup::verify(&s11.A, &sig11, &message);
    println!("GC1_BB_verify:{}",ret11);

    let s12 = gc2_BB_sig::gc2_BB_Setup::keygen();
    let sig12 = s12.sign(&message);
    let ret12 = gc2_BB_sig::gc2_BB_Setup::verify(s12.X, &sig12, &message, &s12.A);
    println!("GC2_BB_verify:{}",ret12);

    let s20 = BLS_sig::BLS_Setup::keygen();
    let sig20 = s20.sign(&message);
    let ret20 = BLS_sig::BLS_Setup::verify(s20.X, &sig20, &message);
    println!("BLS_verify:{}",ret20);

    let s21 = gc1_BLS_sig::gc1_BLS_Setup::keygen();
    let sig21 = s21.sign(&message);
    let ret21 = gc1_BLS_sig::gc1_BLS_Setup::verify(&s21.A, &sig21, &message);
    println!("GC1_BLS_verify:{}",ret21);

    let s22 = gc2_BLS_sig::gc2_BLS_Setup::keygen();
    let sig22 = s22.sign(&message);
    let ret22 = gc2_BLS_sig::gc2_BLS_Setup::verify(s22.X, &sig22, &message, &s22.A);
    println!("GC2_BLS_verify:{}",ret22);


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
    let p: BigInt = str::parse(
        "115792089237316195423570985008687907853269984665640564039457584007908834671663",
    )
    .unwrap();
    let g1 = GE::generator() * &ECScalar::from(&BigInt::from(3));
    // let g1 = GE::generator();
    let x = g1.x_coor().unwrap();//.mod_floor(&p);
    // println!("x:{}",x);
    let y2 = (&x * &x * &x + BigInt::from(7)).mod_floor(&p);
    let y_abs = solve_quadratic_root(&y2, &p); // has problem: https://www.johndcook.com/blog/quadratic_congruences/

    // println!("y_abs:{}",y_abs);
    assert_eq!(y_abs.pow(2).mod_floor(&p), y2);
    assert_eq!(g1.y_coor().unwrap().pow(2).mod_floor(&p), y2);//
    assert_eq!(g1.y_coor().unwrap().mod_floor(&p),(y_abs * BigInt::from(-1)).mod_floor(&p));

    // let mut y2_mpf = Mpf::zero();
    // Mpf::set_z(&mut y2_mpf, &y2);
    // let y = y2_mpf.sqrt();
    // // println!("y:{:?}",y);
    // let y2_revover_by_mpf = y * y;
    // assert_eq!(y_revover_by_mpf, y2_mpf);
    // // assert_eq!(y.pow(2), y2);
    // assert_eq!(g1.y_coor().unwrap().pow(2).mod_floor(&p), y2);//

    println!("Hello, world!");
}

    

