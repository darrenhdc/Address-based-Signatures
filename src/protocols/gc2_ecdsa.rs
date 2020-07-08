use curv::arithmetic::traits::Samplable;
use curv::arithmetic::traits::Modulo;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};
use serde::{Deserialize, Serialize};
use curv::arithmetic::traits::Converter;

#[derive(Clone, Debug)]
pub struct GC2_ECDSA_Setup {
    x: BigInt, // sk
    pub X: GE, // pk
    pub A: BigInt,
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
        let A: BigInt = crate::Hash(&X);
        Self {
            x, // sk
            X, // pk
            A, // addr
        }
    }

    pub fn sign(
        &self,
        m: &BigInt
    ) -> GC2_ECDSA_Signature {
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
        let s_inv = sig.s.invert(&FE::q()).unwrap();
        let K = &xrgc * &ECScalar::from(&s_inv);
        if K.x_coor().unwrap() != sig.r || A != &crate::Hash(&X) {
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}