
use curv::arithmetic::traits::Modulo;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};

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
        let A: BigInt = crate::Hash(&X);
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
        let g_inv_c = &g_inv * &&ECScalar::from(&c);
        let X = Rz + g_inv_c;
        if A != &crate::Hash(&X) {
            flag = false;
        }
        // assert_eq!(flag, true, "verify fialed.");
        flag
    }
}