
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};


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
        if A != &crate::Hash(&X) {
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}