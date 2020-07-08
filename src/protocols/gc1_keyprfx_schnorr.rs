use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};

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
        let A = crate::reversible_hash(&X);
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
        sig: &GC1_Key_prefix_Schnorr_Signature,
        m: &BigInt,
    ) -> bool {
        let mut flag = true;
        // recover pk =X
        let X = crate::reversible_hash_recover_pk(&A);
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
        && X != crate::reversible_hash_recover_pk(A){
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}