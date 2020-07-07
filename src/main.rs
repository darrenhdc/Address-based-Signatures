use curv::arithmetic::traits::Samplable;
use curv::arithmetic::traits::Modulo;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};
use serde::{Deserialize, Serialize};
use curv::arithmetic::traits::Converter;

// H: G->{0,1}*
pub fn Hash(input: &GE) -> BigInt {
    input.bytes_compressed_to_big_int()
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

// Algorithm 1
#[derive(Clone, Debug)]
pub struct Addr_Based_Setup {
    x: BigInt, // sk
    pub X: GE, // pk
    pub A: BigInt, // addr
}

#[derive(Clone, Debug)]
pub struct Addr_Based_Signature {
    pub R: GE,
    pub z: BigInt,
}

impl Addr_Based_Setup {
    pub fn keygen() -> Self {
        let x_fe: FE = FE::new_random();
        let x: BigInt = x_fe.to_big_int();
        let X: GE = GE::generator() * x_fe;
        let A: BigInt = Hash(&X);
        Self {
            x,
            X,
            A,
        }
    }

    pub fn sign(
        &self,
        m: &BigInt
    ) -> Addr_Based_Signature {
        let r_fe: FE = FE::new_random();
        let r: BigInt = r_fe.to_big_int();
        let R: GE = GE::generator() * r_fe;
        let c = HSha256::create_hash(&[
            &R.bytes_compressed_to_big_int(),
            &m,
        ])
        .mod_floor(&FE::q());
        let r_inv: BigInt = r.invert(&FE::q()).unwrap();
        let cx = BigInt::mod_add(&c, &self.x, &FE::q());
        let z = BigInt::mod_mul(&r_inv, &cx, &FE::q());

        Addr_Based_Signature {
            R,
            z,
        } 
    }

    pub fn verify(
        sig: &Addr_Based_Signature,
        m: &BigInt,
        A: &BigInt,
    ) -> bool {
        let mut flag = true;
        let c = HSha256::create_hash(&[
            &sig.R.bytes_compressed_to_big_int(),
            &m,
        ])
        .mod_floor(&FE::q()); // c = Hzp(...)
        let Rz: GE = &sig.R * &ECScalar::from(&sig.z); // R^z
        let g_inv: GE = &GE::generator() * &ECScalar::from(&BigInt::from(-1));
        let X = Rz + g_inv;
        if A != &Hash(&X) {
            flag = false;
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}

// Algorithm 2
#[derive(Clone, Debug)]
pub struct Addr_Based_ECDSA_Setup {
    x: BigInt, // sk
    pub X: GE, // pk
    pub A: BigInt, // addr
}

#[derive(Clone, Debug)]
pub struct Addr_Based_ECDSA_Signature {
    pub r: BigInt,
    pub s: BigInt,
    y: BigInt, // should be deleted, for rebuilding y.
}

impl Addr_Based_ECDSA_Setup {
    pub fn keygen() -> Self {
        let x_fe: FE = FE::new_random();
        let x: BigInt = x_fe.to_big_int();
        let X: GE = GE::generator() * x_fe;
        let A: BigInt = Hash(&X);
        Self {
            x, // sk
            X, // pk
            A, // addr
        }
    }

    pub fn sign(
        &self,
        m: &BigInt
    ) -> Addr_Based_ECDSA_Signature {
        let k_fe: FE = FE::new_random();
        let k: BigInt = k_fe.to_big_int();
        let K: GE = GE::generator() * k_fe;
        let r = K.x_coor().unwrap();
        let c = HSha256::create_hash(&[&m,]).mod_floor(&FE::q());
        let k_inv: BigInt = k.invert(&FE::q()).unwrap();
        let rx = BigInt::mod_mul(&r, &self.x, &FE::q());
        let crx = BigInt::mod_add(&c, &rx, &FE::q());
        let s = BigInt::mod_mul(&k_inv, &crx, &FE::q());
        let y = K.y_coor().unwrap();

        Addr_Based_ECDSA_Signature {
            r,
            s,
            y,
        } 
    }

    pub fn verify(
        sig: &Addr_Based_ECDSA_Signature,
        m: &BigInt,
        A: &BigInt,
    ) -> bool {
        let mut flag = true;
        let c = HSha256::create_hash(&[&m,]).mod_floor(&FE::q()); // c = Hzp(...)
        // use x-coordinator r to reconstruct secp256k1 point
        // miss the y reconstruct
        let K1: GE = GE::from_coor(&sig.r, &sig.y);
        let K2: GE = GE::from_coor(&sig.r, &(&sig.y * &BigInt::from(-1)));
        let r_inv = sig.r.invert(&FE::q());
        let k1s = &K1 * &ECScalar::from(&sig.s);
        let k2s = &K2 * &ECScalar::from(&sig.s);
        let g_inv = &GE::generator() * &&ECScalar::from(&BigInt::from(-1));
        let g_inv_c = &g_inv * &ECScalar::from(&c);
        let k1sgc = &k1s + &g_inv_c;
        let k2sgc = &k2s + &g_inv_c;
        let r_inv = sig.r.invert(&FE::q()).unwrap();
        let X1 = k1sgc * & ECScalar::from(&r_inv);
        let X2 = k2sgc * & ECScalar::from(&r_inv);
        if A != &Hash(&X1) && A != &Hash(&X2) {
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}

// Algorithm 3
#[derive(Clone, Debug)]
pub struct Addr_Based_Schnorr_Setup {
    x: BigInt, // sk
    pub X: GE, // pk
    pub A: BigInt, // addr
}

#[derive(Clone, Debug)]
pub struct Addr_Based_Schnorr_Signature {
    pub R: GE,
    pub z: BigInt,
}

impl Addr_Based_Schnorr_Setup {
    pub fn keygen() -> Self {
        let x_fe: FE = FE::new_random();
        let x: BigInt = x_fe.to_big_int();
        let X: GE = GE::generator() * x_fe;
        let A: BigInt = Hash(&X);
        Self {
            x, // sk
            X, // pk
            A, // addr
        }
    }

    pub fn sign(
        &self,
        m: &BigInt
    ) -> Addr_Based_Schnorr_Signature {
        let r_fe: FE = FE::new_random();
        let r: BigInt = r_fe.to_big_int();
        let R: GE = GE::generator() * r_fe;
        let c = HSha256::create_hash(&[
            &m,
            &R.bytes_compressed_to_big_int(),
            ])
            .mod_floor(&FE::q());
        let z = &r + &c * &self.x;

        Addr_Based_Schnorr_Signature {
            R,
            z,
        } 
    }

    pub fn verify(
        sig: &Addr_Based_Schnorr_Signature,
        m: &BigInt,
        A: &BigInt,
    ) -> bool {
        let mut flag = true;
        let c = HSha256::create_hash(&[
            &m,
            &sig.R.bytes_compressed_to_big_int(),
            ])
            .mod_floor(&FE::q());
        let gz = &GE::generator() * &ECScalar::from(&sig.z);
        let R_inv = &sig.R * &ECScalar::from(&BigInt::from(-1));
        let gzRinv = &gz + &R_inv;
        let c_inv = c.invert(&FE::q()).unwrap();
        let X = &gzRinv * &ECScalar::from(&c_inv);
        if A != &Hash(&X) {
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}

// Algorithm 6
#[derive(Clone, Debug)]
pub struct Key_prefix_Schnorr_Setup {
    x: BigInt,
    pub X: GE,
}

#[derive(Clone, Debug)]
pub struct Key_prefix_Schnorr_Signature {
    pub c: BigInt,
    pub z: BigInt,
}

impl Key_prefix_Schnorr_Setup {
    pub fn keygen() -> Self {
        let x_fe: FE = FE::new_random();
        let x: BigInt = x_fe.to_big_int();
        let X: GE = GE::generator() * x_fe;
        Self {
            x, // sk
            X, // pk
        }
    }

    pub fn sign(
        &self,
        m: &BigInt
    ) -> Key_prefix_Schnorr_Signature {
        let r_fe: FE = FE::new_random();
        let r: BigInt = r_fe.to_big_int();
        let R: GE = GE::generator() * r_fe;
        let X: GE = &GE::generator() * &ECScalar::from(&self.x);
        let c = HSha256::create_hash(&[
            &R.bytes_compressed_to_big_int(),
            &m,
            &X.bytes_compressed_to_big_int(),
            ])
            .mod_floor(&FE::q());
        let z = &r + &c * &self.x;
        Key_prefix_Schnorr_Signature {
            c,
            z,
        } 
    }

    pub fn verify(
        X: GE,
        sig: &Key_prefix_Schnorr_Signature,
        m: &BigInt,
    ) -> bool {
        let mut flag = true;
        let gz = &GE::generator() * &ECScalar::from(&sig.z);
        let X_inv = &X * &ECScalar::from(&BigInt::from(-1));
        let X_inv_c = &X_inv * &ECScalar::from(&sig.c);
        let R = &gz + &X_inv_c;
        let c_recover = HSha256::create_hash(&[
            &R.bytes_compressed_to_big_int(),
            &m,
            &X.bytes_compressed_to_big_int(),
            ])
            .mod_floor(&FE::q());
        if c_recover != sig.c {
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}

// key-prefix gc1
#[derive(Clone, Debug)]
pub struct GC1_Key_prefix_Schnorr_Setup {
    x: BigInt, // sk
    pub X: GE, // pk
    pub A: std::string::String, // addr
}

#[derive(Clone, Debug)]
pub struct GC1_Key_prefix_Schnorr_Signature {
    pub c: BigInt,
    pub z: BigInt,
}

impl GC1_Key_prefix_Schnorr_Setup {
    pub fn keygen() -> Self {
        let x_fe: FE = FE::new_random();
        let x: BigInt = x_fe.to_big_int();
        let X: GE = GE::generator() * x_fe;
        let A = reversible_hash(&X);
        Self {
            x, // sk
            X, // pk
            A,
        }
    }

    pub fn sign(
        &self,
        m: &BigInt
    ) -> GC1_Key_prefix_Schnorr_Signature {
        let r_fe: FE = FE::new_random();
        let r: BigInt = r_fe.to_big_int();
        let R: GE = GE::generator() * r_fe;
        let c = HSha256::create_hash(&[
            &R.bytes_compressed_to_big_int(),
            &m,
            &self.X.bytes_compressed_to_big_int(),
            ])
            .mod_floor(&FE::q());
        let z = &r + &c * &self.x;
        GC1_Key_prefix_Schnorr_Signature {
            c,
            z,
        } 
    }

    pub fn verify(
        A: &std::string::String,
        sig: &Key_prefix_Schnorr_Signature,
        m: &BigInt,
    ) -> bool {
        let mut flag = true;
        // recover pk =X
        let X = reversible_hash_recover_pk(&A);
        let gz = &GE::generator() * &ECScalar::from(&sig.z);
        let X_inv = X * &ECScalar::from(&BigInt::from(-1));
        let X_inv_c = &X_inv * &ECScalar::from(&sig.c);
        let R = &gz + &X_inv_c;
        let c_recover = HSha256::create_hash(&[
            &R.bytes_compressed_to_big_int(),
            &m,
            &X.bytes_compressed_to_big_int(),
            ])
            .mod_floor(&FE::q());
        if c_recover != sig.c  
        && X != reversible_hash_recover_pk(A){
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}

// key-prefix gc2
#[derive(Clone, Debug)]
pub struct GC2_Key_prefix_Schnorr_Setup {
    x: BigInt, // sk
    pub X: GE, // pk
    pub A: BigInt, // addr
}

#[derive(Clone, Debug)]
pub struct GC2_Key_prefix_Schnorr_Signature {
    pub c: BigInt,
    pub z: BigInt,
}

impl GC2_Key_prefix_Schnorr_Setup {
    pub fn keygen() -> Self {
        let x_fe: FE = FE::new_random();
        let x: BigInt = x_fe.to_big_int();
        let X: GE = GE::generator() * x_fe;
        let A = Hash(&X);
        Self {
            x, // sk
            X, // pk
            A,
        }
    }

    pub fn sign(
        &self,
        m: &BigInt
    ) -> GC2_Key_prefix_Schnorr_Signature {
        let r_fe: FE = FE::new_random();
        let r: BigInt = r_fe.to_big_int();
        let R: GE = GE::generator() * r_fe;
        let c = HSha256::create_hash(&[
            &R.bytes_compressed_to_big_int(),
            &m,
            &self.X.bytes_compressed_to_big_int(),
            ])
            .mod_floor(&FE::q());
        let z = &r + &c * &self.x;
        GC2_Key_prefix_Schnorr_Signature {
            c,
            z,
        } 
    }

    pub fn verify(
        A: &BigInt,
        X: &GE,
        sig: &Key_prefix_Schnorr_Signature,
        m: &BigInt,
    ) -> bool {
        let mut flag = true;
        let gz = &GE::generator() * &ECScalar::from(&sig.z);
        let X_inv = X * &ECScalar::from(&BigInt::from(-1));
        let X_inv_c = &X_inv * &ECScalar::from(&sig.c);
        let R = &gz + &X_inv_c;
        let c_recover = HSha256::create_hash(&[
            &R.bytes_compressed_to_big_int(),
            &m,
            &X.bytes_compressed_to_big_int(),
            ])
            .mod_floor(&FE::q());
        if c_recover != sig.c  
        && A != &Hash(&X){
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}


#[derive(Clone, Debug)]
pub struct GC2_ECDSA_Setup {
    x: BigInt, // sk
    pub X: GE, // pk
    pub A: BigInt, // addr
}

#[derive(Clone, Debug)]
pub struct GC2_ECDSA_Signature {
    pub r: BigInt,
    pub s: BigInt,
}

impl GC2_ECDSA_Setup {
    pub fn keygen() -> Self {
        let x_fe: FE = FE::new_random();
        let x: BigInt = x_fe.to_big_int();
        let X: GE = GE::generator() * x_fe;
        let A: BigInt = Hash(&X);
        Self {
            x, // sk
            X, // pk
            A, // addr
        }
    }

    pub fn sign(
        &self,
        m: &BigInt
    ) -> Addr_Based_ECDSA_Signature {
        let k_fe: FE = FE::new_random();
        let k: BigInt = k_fe.to_big_int();
        let K: GE = GE::generator() * k_fe;
        let r = K.x_coor().unwrap();
        let c = HSha256::create_hash(&[&m,]).mod_floor(&FE::q());
        let k_inv: BigInt = k.invert(&FE::q()).unwrap();
        let rx = BigInt::mod_mul(&r, &self.x, &FE::q());
        let crx = BigInt::mod_add(&c, &rx, &FE::q());
        let s = BigInt::mod_mul(&k_inv, &crx, &FE::q());

        GC2_ECDSA_Signature {
            r,
            s,
        } 
    }

    pub fn verify(
        sig: &GC2_ECDSA_Signature,
        X: &GE,
        m: &BigInt,
        A: &BigInt,
    ) -> bool {
        let mut flag = true;
        let c = HSha256::create_hash(&[&m,]).mod_floor(&FE::q()); // c = Hzp(...)
        let Xr = X * & ECScalar::from(&sig.r);
        let gc = GE::generator() * & ECScalar::from(&c);
        let xrgc = &Xr + &gc;
        let xrgc_inv = &xrgc * &ECScalar::from(
            &BigInt::from(-1)
        );
        let K = &xrgc_inv * &ECScalar::from(&sig.s);
        if K.x_coor().unwrap() != sig.r || A != &Hash(&X) {
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
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
