  
extern crate bn;
extern crate rand;
use bn::{Group, Fr, G1, G2, pairing};
use rand::{Rng,SeedableRng,StdRng};

use curv::arithmetic::traits::Modulo;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;
use curv::{FE, GE};


// Algorithm 1
#[derive(Clone)]
pub struct BB_Setup {
    x: Fr, // sk
    pub X: G1, // pk
}

#[derive(Clone)]
pub struct BB_Signature {
    pub sigma: G2,
}

impl BB_Setup{
    pub fn keygen() -> Self {
        let rng = &mut rand::thread_rng();
        let x = Fr::random(rng);
        let X = G1::one() * x; // pk = g1^sk
        Self {
            x, // sk
            X, // pk
        }
    }
    pub fn sign(
        &self,
        m: &BigInt
    ) -> BB_Signature {
        // according to: https://tools.ietf.org/id/draft-kasamatsu-bncurves-01.html
        // p = order of the group generated by G1
        let p: BigInt = str::parse(
            "16030569034403128277756688287498649515510226217719936227669524443298095169537"
        )
        .unwrap();
        let c_string = HSha256::create_hash(&[&m,]).mod_floor(&p).to_str_radix(10);
        let c: Fr = Fr::from_str(&crate::string_to_static_str(c_string)).unwrap();
        // let c = self.x.clone(); // for test
        let xc = c + self.x; // to check
        let xc_inv = xc.inverse().unwrap();
        let sigma = G2::one() * xc_inv;
        BB_Signature {
            sigma
        }
    }
    pub fn verify(   
        X: G1,
        sig: &BB_Signature,
        m: &BigInt,
    ) -> bool  {
        let mut flag = true;
        let rng = &mut rand::thread_rng();
        // let c = HSha256::create_hash(&[&m,]).mod_floor(&FE::q()); // c = Hzp(...) 
        let p: BigInt = str::parse(
            "16030569034403128277756688287498649515510226217719936227669524443298095169537"
        )
        .unwrap();
        let c_string = HSha256::create_hash(&[&m,]).mod_floor(&p).to_str_radix(10);
        let c: Fr = Fr::from_str(&crate::string_to_static_str(c_string)).unwrap();
        let g1c = G1::one() * c;
        let xg1c = X + g1c; // to check
        if pairing(G1::one(), G2::one()) != pairing(xg1c, sig.sigma) {
            flag = false
        }
        assert_eq!(flag, true, "verify fialed.");
        flag

    }
}
