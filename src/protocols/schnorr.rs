use curv::arithmetic::traits::Samplable;
use curv::arithmetic::traits::Modulo;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};
use serde::{Deserialize, Serialize};
use curv::arithmetic::traits::Converter;

// Algorithm 6
#[derive(Clone, Debug)]
pub struct Original_Schnorr_Setup {
    x: BigInt,
    pub X: GE,
}

#[derive(Clone, Debug)]
pub struct Original_Schnorr_Signature {
    pub c: BigInt,
    pub z: BigInt,
}

impl Original_Schnorr_Setup {
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
    ) -> Original_Schnorr_Signature {
        let r_fe: FE = FE::new_random();
        let r: BigInt = r_fe.to_big_int();
        let R: GE = GE::generator() * r_fe;
        let c = HSha256::create_hash(&[ // c = H(R,M)
            &R.bytes_compressed_to_big_int(),
            &m, 
            ])
            .mod_floor(&FE::q());
        let z = &r - &c * &self.x;
        Original_Schnorr_Signature {
            c,
            z,
        } 
    }

    pub fn verify(
        X: &GE,
        sig: &Original_Schnorr_Signature,
        m: &BigInt,
    ) -> bool {
        let mut flag = true;
        let gz = &GE::generator() * &ECScalar::from(&sig.z);
        let Xc = X * &ECScalar::from(&sig.c);
        let R = &gz + &Xc;
        let c_recover = HSha256::create_hash(&[
            &R.bytes_compressed_to_big_int(),
            &m,
            ])
            .mod_floor(&FE::q());
        if c_recover != sig.c {
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}