
use curv::arithmetic::traits::Modulo;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};



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
        
        // p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
        let p: BigInt = str::parse(
            "115792089237316195423570985008687907853269984665640564039457584007908834671663",
        )
        .unwrap();
        // use x-coordinator r to reconstruct secp256k1 point
        let y2 = (&sig.r * &sig.r * &sig.r + BigInt::from(7)).mod_floor(&p);
        let y_abs = y2.sqrt().mod_floor(&p);
        assert_eq!(sig.y.pow(2).mod_floor(&p), y_abs);
        // let K1: GE = GE::from_coor(&sig.r, &y_abs);
        // let K2: GE = GE::from_coor(&sig.r, &y_abs);
        let K1: GE = GE::from_coor(&sig.r, &(&y_abs * &BigInt::from(-1)));
        let K2: GE = GE::from_coor(&sig.r, &(&y_abs * &BigInt::from(-1)));
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
        if A != &crate::Hash(&X1) && A != &crate::Hash(&X2) {
            flag = false
        }
        // assert_eq!(A, &crate::Hash(&X2));
        assert_eq!(flag, true, "verify fialed.");
        flag
    }
}