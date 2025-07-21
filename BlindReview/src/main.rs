use rand_core::OsRng;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;
pub use subtle::Choice;
use curve25519_dalek::{ristretto::RistrettoPoint, ristretto::CompressedRistretto, scalar::Scalar, constants::RISTRETTO_BASEPOINT_POINT, traits::Identity};
use rand_core::{CryptoRng, RngCore};
use sha2::{Sha256, Sha512, Digest};
use std::collections::HashMap;
use std::time::Instant;

//IMACC
const N : usize = 34; //papers
const M : usize = 21; //reviewers
const L : usize = 6; // limite (>34*3/21=4,8)
const RP : usize = 3; // review by paper
const C : usize = 1; // Conflicts by papers

/*
//CSF
const N : usize = 205; //papers
const M : usize = 61; //reviewers
const L : usize = 12; // limite (>205*3/61=10,1)
const RP : usize = 3; // review by paper
const C : usize = 3; // Conflicts by papers
*/

/*
//ESORICS
const N : usize = 334; //papers
const M : usize = 124; //reviewers
const L : usize = 10; // limite (>334*3/124=8,1)
const RP : usize = 3; // review by paper
const C : usize = 3; // Conflicts by papers
*/

#[derive(Debug)]
struct ElGamalKeys { // Keys for C and R
    pk: RistrettoPoint,
    sk: Scalar,
}

impl ElGamalKeys {
    fn generate<T: CryptoRng + RngCore>(g : RistrettoPoint, rng : &mut  T) -> ElGamalKeys {
        let sk = Scalar::random(rng);
        ElGamalKeys {
            sk : sk,
            pk : sk * g,
        }
    }
}

#[derive(Debug)]
struct AuthorKeys { // Keys for C and R
    pk: (RistrettoPoint,RistrettoPoint),
    sk: (Scalar,Scalar,Scalar,Scalar),
    proof: SchnorrProof,
}

impl AuthorKeys {
    fn generate<T: CryptoRng + RngCore>(g : RistrettoPoint, rng : &mut  T) -> AuthorKeys {
        let sk = (Scalar::random(rng),Scalar::random(rng),Scalar::random(rng),Scalar::random(rng));
        let pk = (sk.0 * g, sk.1 * g);
        let proof = schnorr_prove(sk.0, &pk.0, rng);
        AuthorKeys {
            sk : sk,
            pk : pk,
            proof : proof,
        }
    }
}

#[derive(Debug)]
struct ProvedHashElGamalCipher {
    nonce : RistrettoPoint,
    proof : SchnorrProof,
    blocs : Vec<[u8; 64]>,
}

#[derive(Debug)]
struct SchnorrProof {
    com : RistrettoPoint,
    resp : Scalar,
}

impl SchnorrProof {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com));
        vec.extend_from_slice(&self.resp.to_bytes());
        vec
    }
    fn copy(&self) -> SchnorrProof {
        SchnorrProof{
            com : self.com,
            resp : self.resp,
        }
    }
}

struct SchnorrEqualityStatement {
    g : (RistrettoPoint,RistrettoPoint),
    y : (RistrettoPoint,RistrettoPoint),
}

struct SchnorrEqualityProof {
    com : (RistrettoPoint,RistrettoPoint),
    resp : Scalar,
}

impl SchnorrEqualityProof {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com.0));
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com.1));
        vec.extend_from_slice(&self.resp.to_bytes());
        vec
    }
    fn copy(&self) -> SchnorrEqualityProof {
        SchnorrEqualityProof{
            com : self.com,
            resp : self.resp,
        }
    }
}

struct SchnorrInequalityStatement {
    g : (RistrettoPoint,RistrettoPoint),
    y : (RistrettoPoint,RistrettoPoint),
}

struct SchnorrInequalityProof {
    c : RistrettoPoint,
    double_equality_proof : SchnorrDoubleEqualityProof,
}

impl SchnorrInequalityProof {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.c));
        vec.extend_from_slice(&self.double_equality_proof.to_vec());
        vec
    }

    fn copy(&self) -> SchnorrInequalityProof  {
        SchnorrInequalityProof {
            c : self.c,
            double_equality_proof : self.double_equality_proof.copy(),
        }
    }
}

struct SchnorrEqualityInequalityStatement {
    g : (RistrettoPoint,RistrettoPoint,RistrettoPoint),
    y : (RistrettoPoint,RistrettoPoint,RistrettoPoint),
}

struct SchnorrEqualityInequalityProof {
    eq : SchnorrEqualityProof,
    ineq : SchnorrInequalityProof,
}

impl SchnorrEqualityInequalityProof {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.eq.to_vec());
        vec.extend_from_slice(&self.ineq.to_vec());
        vec
    }
}

struct SchnorrDoubleEqualitySecret {
    x : Scalar,
    y : Scalar,
}

struct SchnorrDoubleEqualityStatement {
    g : (RistrettoPoint,RistrettoPoint),
    h : (RistrettoPoint,RistrettoPoint),
    y : (RistrettoPoint,RistrettoPoint),
}

struct SchnorrDoubleEqualityProof {
    com_g : (RistrettoPoint,RistrettoPoint),
    com_h : (RistrettoPoint,RistrettoPoint),
    resp : (Scalar,Scalar),
}

impl SchnorrDoubleEqualityProof {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com_g.0));
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com_g.1));
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com_h.0));
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com_h.1));
        vec.extend_from_slice(&self.resp.0.to_bytes());
        vec.extend_from_slice(&self.resp.1.to_bytes());
        vec
    }

    fn copy(&self) -> SchnorrDoubleEqualityProof  {
        SchnorrDoubleEqualityProof {
            com_g : self.com_g,
            com_h : self.com_h,
            resp : self.resp,
        }
    }
}

struct SchnorrPartialEqualitySecret {
    x : Scalar,
    partial : Vec<bool>,
}

struct SchnorrPartialEqualityStatement {
    g : Vec<RistrettoPoint>,
    y : Vec<RistrettoPoint>,
}

struct SchnorrPartialEqualityProof {
    com : Vec<(RistrettoPoint,RistrettoPoint)>,
    poly : Vec<Scalar>,
    resp : Vec<Scalar>,
}

struct SchnorrOrEqualitySecret {
    x : Scalar,
    index : usize,
}

struct SchnorrOrEqualityStatement {
    g : RistrettoPoint,
    y : RistrettoPoint,
    g_r : Vec<RistrettoPoint>,
    y_r : Vec<RistrettoPoint>,
}

struct SchnorrOrEqualityProof {
    com : Vec<(RistrettoPoint,RistrettoPoint)>,
    chal : Vec<Scalar>,
    resp : Vec<Scalar>,
}

impl SchnorrOrEqualityProof {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        for i in 0..self.com.len(){
            vec.extend_from_slice(&ristretto_point_to_bytes(&self.com[i].0));
            vec.extend_from_slice(&ristretto_point_to_bytes(&self.com[i].1));
            vec.extend_from_slice(&self.chal[i].to_bytes());
            vec.extend_from_slice(&self.resp[i].to_bytes());
        }
        vec
    }

    fn copy(&self) -> SchnorrOrEqualityProof {
        let mut new_com : Vec<(RistrettoPoint,RistrettoPoint)> = Vec::new();
        let mut new_chal : Vec<Scalar> = Vec::new();
        let mut new_resp : Vec<Scalar> = Vec::new();
        for i in 0..self.com.len(){
            new_com.push(self.com[i]);
            new_chal.push(self.chal[i]);
            new_resp.push(self.resp[i]);
        }
        SchnorrOrEqualityProof {
            com : new_com,
            chal : new_chal,
            resp : new_resp,
        }
    }
}

struct SchnorrSOK {
    com : RistrettoPoint,
    resp : Scalar,
}

impl SchnorrSOK {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com));
        vec.extend_from_slice(&self.resp.to_bytes());
        vec
    }
    fn copy(&self) -> SchnorrSOK {
        SchnorrSOK{
            com : self.com,
            resp : self.resp,
        }
    }
}

#[derive(Debug)]
struct PedersenCommitment {
    com: RistrettoPoint,
}

fn proved_hash_elgamal_encrypt<T: CryptoRng + RngCore>(g : RistrettoPoint, m : &Vec<[u8; 64]>, pk : RistrettoPoint, rng : &mut  T) -> ProvedHashElGamalCipher{

    let mut blocs: Vec<[u8; 64]> = Vec::new();
    let r: Scalar = Scalar::random(rng);
    let nonce = r * g;
    let mut base = r * pk;
    let proof = schnorr_prove(r,&nonce,rng);

    for v in m {
        let mut hasher = Sha512::new();
        let pre_hash = ristretto_point_to_bytes(&base);
        base += base;
        hasher.update(pre_hash);
        let hash = hasher.finalize();
        let mut bloc : [u8; 64] = [0; 64];
        for i in 0..64 {
            bloc[i] = hash[i] ^ v[i];
        }
        blocs.push(bloc);

    }
    ProvedHashElGamalCipher {
        nonce : nonce,
        proof : proof,
        blocs : blocs,
    }
}

fn proved_hash_elgamal_decrypt( c : &ProvedHashElGamalCipher, sk : Scalar) -> Vec<[u8; 64]>{

    let mut m: Vec<[u8; 64]> = Vec::new();
    let mut base = sk * c.nonce;

    for v in &c.blocs {
        let mut hasher = Sha512::new();
        let pre_hash = ristretto_point_to_bytes(&base);
        base += base;
        hasher.update(pre_hash);
        let hash = hasher.finalize();
        let mut bloc_m : [u8; 64] = [0; 64];
        for i in 0..64 {
            bloc_m[i] = hash[i] ^ v[i];
        }
        m.push(bloc_m);
    }
    m
}

fn proved_hash_elgamal_verify( c : &ProvedHashElGamalCipher) -> bool{
    return schnorr_verify(&c.proof,&c.nonce);
}


fn trim_trailing_zeros(vec: &Vec<u8>) -> Vec<u8> {
    if let Some(last_non_zero) = vec.iter().rposition(|&x| x != 0) {
        vec[..=last_non_zero].to_vec()
    } else {
        Vec::new()
    }
}

fn pedersen_commit(sk : Scalar, h : RistrettoPoint, m : &Vec<u8>) -> PedersenCommitment {

    let mut hasher = Sha256::new();
    let pre_hash = trim_trailing_zeros(m); // Do not consider last zeros
    hasher.update(pre_hash);
    let hash = hasher.finalize();
    let hash_s = Scalar::from_bytes_mod_order(hash.into());

    PedersenCommitment {
        com : sk * RISTRETTO_BASEPOINT_POINT + hash_s * h,
    }
}

fn pedersen_verify(h : RistrettoPoint, m : &Vec<u8>,  p : &PedersenCommitment, sk : Scalar) -> bool {
    let mut hasher = Sha256::new();
    let pre_hash = trim_trailing_zeros(m);
    hasher.update(pre_hash);
    let hash = hasher.finalize();
    let hash_s = Scalar::from_bytes_mod_order(hash.into());

    sk * RISTRETTO_BASEPOINT_POINT + hash_s * h == p.com
}

fn schnorr_prove<T: CryptoRng + RngCore>(secret : Scalar, statement : &RistrettoPoint, rng : &mut  T) -> SchnorrProof {
    let r: Scalar = Scalar::random(rng);
    let rr = r * RISTRETTO_BASEPOINT_POINT;

    let mut hasher = Sha256::new();

    // write input message
    let pre_hash = [ristretto_point_to_bytes(&RISTRETTO_BASEPOINT_POINT),
                    ristretto_point_to_bytes(&statement),
                    ristretto_point_to_bytes(&rr)].concat();

    hasher.update(pre_hash);

    // read hash digest and consume hasher
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    let z = r + (c * secret);

    SchnorrProof {
        com : rr,
        resp : z,
    }
}

fn schnorr_verify(proof : &SchnorrProof, statement : &RistrettoPoint) -> bool {
    let mut hasher = Sha256::new();

    // write input message
    let pre_hash = [ristretto_point_to_bytes(&RISTRETTO_BASEPOINT_POINT),
                    ristretto_point_to_bytes(&statement),
                    ristretto_point_to_bytes(&proof.com)].concat();

    hasher.update(pre_hash);

    // read hash digest and consume hasher
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    proof.resp * RISTRETTO_BASEPOINT_POINT == proof.com + (c * statement)
}

fn schnorr_equality_prove<T: CryptoRng + RngCore>(secret : Scalar, statement : &SchnorrEqualityStatement, rng : &mut  T) -> SchnorrEqualityProof {
    let r: Scalar = Scalar::random(rng);
    let gg = (r * statement.g.0, r * statement.g.1);

    let mut hasher = Sha256::new();

    // write input message
    let pre_hash = [ristretto_point_to_bytes(&statement.g.0),
                    ristretto_point_to_bytes(&statement.g.1),
                    ristretto_point_to_bytes(&statement.y.0),
                    ristretto_point_to_bytes(&statement.y.1),
                    ristretto_point_to_bytes(&gg.0),
                    ristretto_point_to_bytes(&gg.1)
                   ].concat();

    hasher.update(pre_hash);

    // read hash digest and consume hasher
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    let z = r + (c * secret);

    SchnorrEqualityProof {
        com : gg,
        resp : z,
    }
}

fn schnorr_equality_verify(statement : &SchnorrEqualityStatement, proof : & SchnorrEqualityProof) -> bool {

    let mut hasher = Sha256::new();

    // write input message
    let pre_hash = [ristretto_point_to_bytes(&statement.g.0),
                    ristretto_point_to_bytes(&statement.g.1),
                    ristretto_point_to_bytes(&statement.y.0),
                    ristretto_point_to_bytes(&statement.y.1),
                    ristretto_point_to_bytes(&proof.com.0),
                    ristretto_point_to_bytes(&proof.com.1)
                   ].concat();

    hasher.update(pre_hash);

    // read hash digest and consume hasher
    let h = hasher.finalize();

    let c = Scalar::from_bytes_mod_order(h.into());

    (proof.resp * statement.g.0 ==  proof.com.0 + (c * statement.y.0)) && (proof.resp * statement.g.1 ==  proof.com.1 + (c * statement.y.1))
}

fn schnorr_or_equality_prove<T: CryptoRng + RngCore>(secret : &SchnorrOrEqualitySecret, statement : &SchnorrOrEqualityStatement, rng : &mut  T) -> SchnorrOrEqualityProof {
    let mut chal : Vec<Scalar> = Vec::with_capacity(statement.g_r.len());
    let mut com : Vec<(RistrettoPoint,RistrettoPoint)> = Vec::with_capacity(statement.g_r.len());
    let mut resp : Vec<Scalar> = Vec::with_capacity(statement.g_r.len());
    let r = Scalar::random(rng);

    let mut hasher = Sha256::new();
    let mut pre_hash = [ristretto_point_to_bytes(&statement.g),
                    ristretto_point_to_bytes(&statement.y)
                   ].concat();

    for i in 0..statement.g_r.len() {
        if i == secret.index{
            com.push((r * statement.g,r * statement.g_r[i]));
            chal.push(r);
            resp.push(r);
        }
        else
        {
            let c = Scalar::random(rng);
            let z = Scalar::random(rng);
            chal.push(c);
            resp.push(z);
            com.push((
                (z * statement.g) - (c * statement.y),
                (z * statement.g_r[i]) - (c * statement.y_r[i])
            ));
        }
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement.g_r[i]));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement.y_r[i]));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&com[i].0));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&com[i].1));

    }

    hasher.update(pre_hash);

    // read hash digest and consume hasher
    let h = hasher.finalize();

    let c = Scalar::from_bytes_mod_order(h.into());
    let mut cindex : Scalar = c;
    for i in 0..chal.len() {
        if i != secret.index{
            cindex = cindex - chal[i];
        }
    }

    chal[secret.index] = cindex;
    resp[secret.index] = r + cindex * secret.x;

    SchnorrOrEqualityProof {
        com : com,
        chal : chal,
        resp : resp,
    }
}

fn schnorr_or_equality_verify(statement : &SchnorrOrEqualityStatement,  proof : & SchnorrOrEqualityProof) -> bool {
    let mut ret : bool = true;
    let mut hasher = Sha256::new();
    let mut pre_hash = [ristretto_point_to_bytes(&statement.g),
                    ristretto_point_to_bytes(&statement.y)
                   ].concat();
    for i in 0..statement.g_r.len() {
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement.g_r[i]));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement.y_r[i]));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&proof.com[i].0));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&proof.com[i].1));

        ret = ret && (proof.resp[i] * statement.g == proof.com[i].0 + (proof.chal[i] * statement.y));
        ret = ret && (proof.resp[i] * statement.g_r[i] == proof.com[i].1 + (proof.chal[i] * statement.y_r[i]));
    }

    hasher.update(pre_hash);

    // read hash digest and consume hasher
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    let mut sum : Scalar = proof.chal[0];
    for i in 1..proof.chal.len() {
        sum = sum + proof.chal[i];
    }

    ret = ret && (sum == c);
    ret
}

fn schnorr_partial_equality_prove<T: CryptoRng + RngCore>(secret : &SchnorrPartialEqualitySecret, statement : &SchnorrPartialEqualityStatement, rng : &mut  T) -> SchnorrPartialEqualityProof {
    let mut c_z_vec : Vec<Option<(Scalar,Scalar)>> = Vec::with_capacity(statement.g.len());
    let mut r_vec : Vec<Option<Scalar>> = Vec::with_capacity(statement.g.len());
    let mut com : Vec<(RistrettoPoint,RistrettoPoint)> = Vec::with_capacity(statement.g.len());

    let mut hasher = Sha256::new();
    let mut pre_hash = [ristretto_point_to_bytes(&statement.g[0]),
                    ristretto_point_to_bytes(&statement.y[0])
                   ].concat();
    for i in 1..statement.g.len() { // fisrt case corrsponds to y = g^x
        if secret.partial[i-1]{
            let r = Scalar::random(rng);
            r_vec.push(Some(r));
            c_z_vec.push(None);
            com.push((r * statement.g[0],r * statement.g[i]));
        }
        else
        {
            let c = Scalar::random(rng);
            let z = Scalar::random(rng);
            c_z_vec.push(Some((c,z)));
            r_vec.push(None);
            com.push((
                (z * statement.g[0]) - (c * statement.y[0]),
                (z * statement.g[i]) - (c * statement.y[i])
            ));
        }
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement.g[i]));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement.y[i]));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&com[i-1].0));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&com[i-1].1));

    }

    hasher.update(pre_hash);

    // read hash digest and consume hasher
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    let mut x_values : Vec<Scalar> = Vec::new();
    let mut y_values : Vec<Scalar> = Vec::new();
    x_values.push(Scalar::from(0u64));
    y_values.push(c);
    for i in 0..com.len() { // fisrt case corrsponds to y = g^x
        match c_z_vec[i] {
            Some(c_z) => {
                let x_u64 : u64 = (i+1).try_into().unwrap();
                x_values.push(Scalar::from(x_u64));
                y_values.push(c_z.0);
            }
            None =>{

            }
        }
    }
    let mut resp : Vec<Scalar> = Vec::with_capacity(statement.g.len());

    let poly =  lagrange_interpolation_polynomial(&x_values, &y_values);

    for i in 0..com.len() {
        match c_z_vec[i] {
            Some(c_z) => {
                resp.push(c_z.1);
            }
            None =>{
                let x_64 : u64= (i+1).try_into().unwrap(); // 0 correspond à y = g^x
                let x_scalar = Scalar::from(x_64);
                let c = evaluate_polynomial(&poly, x_scalar);

                match r_vec[i] {
                    Some(r) => {
                        resp.push(r + c * secret.x);
                        // c_z_vec[i] = Some((c,z));
                    }
                    None => {
                        panic!("Something wrong in a proof of partial knowledge...");
                    }
                }
            }
        }
    }

    SchnorrPartialEqualityProof {
        com : com,
        poly : poly,
        resp : resp,
    }

}

fn schnorr_partial_equality_verify(statement : &SchnorrPartialEqualityStatement, partial : usize,  proof : & SchnorrPartialEqualityProof) -> bool {

    let mut ret : bool = proof.resp.len() - polynomial_degree(&proof.poly) == partial;
    let mut hasher = Sha256::new();
    let mut pre_hash = [ristretto_point_to_bytes(&statement.g[0]),
                    ristretto_point_to_bytes(&statement.y[0])
                   ].concat();
    for i in 1..statement.g.len() { // fisrt case corrsponds to y = g^x
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement.g[i]));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement.y[i]));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&proof.com[i-1].0));
        pre_hash.extend_from_slice(&ristretto_point_to_bytes(&proof.com[i-1].1));
        let i_64 : u64= i.try_into().unwrap();
        let i_scalar = Scalar::from(i_64);
        let c = evaluate_polynomial(&proof.poly,i_scalar);
        ret = ret && (proof.resp[i-1] * statement.g[0] == proof.com[i-1].0 + (c * statement.y[0]));
        ret = ret && (proof.resp[i-1] * statement.g[i] == proof.com[i-1].1 + (c * statement.y[i]));
    }

    hasher.update(pre_hash);
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    ret = ret && (evaluate_polynomial(&proof.poly,Scalar::from(0u64)) == c);

    ret
}

fn schnorr_double_equality_prove<T: CryptoRng + RngCore>(secret : &SchnorrDoubleEqualitySecret, statement : &SchnorrDoubleEqualityStatement, rng : &mut  T) -> SchnorrDoubleEqualityProof {
    let r: Scalar = Scalar::random(rng);
    let s: Scalar = Scalar::random(rng);
    let gg = (r * statement.g.0, r * statement.g.1);
    let hh = (s * statement.h.0, s * statement.h.1);

    let mut hasher = Sha256::new();

    // write input message
    let pre_hash = [ristretto_point_to_bytes(&statement.g.0),
                    ristretto_point_to_bytes(&statement.g.1),
                    ristretto_point_to_bytes(&statement.h.0),
                    ristretto_point_to_bytes(&statement.h.1),
                    ristretto_point_to_bytes(&statement.y.0),
                    ristretto_point_to_bytes(&statement.y.1),
                    ristretto_point_to_bytes(&gg.0),
                    ristretto_point_to_bytes(&gg.1),
                    ristretto_point_to_bytes(&hh.0),
                    ristretto_point_to_bytes(&hh.1)
                   ].concat();

    hasher.update(pre_hash);
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    let z = (r + (c * secret.x),  s + (c * secret.y));

    SchnorrDoubleEqualityProof {
        com_g : gg,
        com_h : hh,
        resp : z,
    }
}

fn schnorr_double_equality_verify(statement : &SchnorrDoubleEqualityStatement, proof : & SchnorrDoubleEqualityProof) -> bool {
    let mut hasher = Sha256::new();

    // write input message
    let pre_hash = [ristretto_point_to_bytes(&statement.g.0),
                    ristretto_point_to_bytes(&statement.g.1),
                    ristretto_point_to_bytes(&statement.h.0),
                    ristretto_point_to_bytes(&statement.h.1),
                    ristretto_point_to_bytes(&statement.y.0),
                    ristretto_point_to_bytes(&statement.y.1),
                    ristretto_point_to_bytes(&proof.com_g.0),
                    ristretto_point_to_bytes(&proof.com_g.1),
                    ristretto_point_to_bytes(&proof.com_h.0),
                    ristretto_point_to_bytes(&proof.com_h.1)
                   ].concat();

    hasher.update(pre_hash);
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    proof.resp.0 * statement.g.0 + proof.resp.1 * statement.h.0 ==
    proof.com_g.0 + proof.com_h.0 + (c * statement.y.0)
    &&
    proof.resp.0 * statement.g.1 + proof.resp.1 * statement.h.1 ==
    proof.com_g.1 + proof.com_h.1 + (c * statement.y.1)
}

fn schnorr_inequality_prove<T: CryptoRng + RngCore>(secret : Scalar, statement : &SchnorrInequalityStatement, rng : &mut  T) -> SchnorrInequalityProof {
    let y: Scalar = Scalar::random(rng);
    let double_eq_secret = SchnorrDoubleEqualitySecret {
        x : secret * y,
        y : y,
    };

    let c = y * (secret * statement.g.1 - statement.y.1);

    let double_eq_statement = SchnorrDoubleEqualityStatement {
        g : (statement.g.0,statement.g.1),
        h : (-statement.y.0,-statement.y.1),
        y : (Identity::identity(),c),
    };

    let double_eq_proof = schnorr_double_equality_prove(&double_eq_secret,&double_eq_statement,rng);

    SchnorrInequalityProof {
        c : c,
        double_equality_proof : double_eq_proof,
    }
}

fn schnorr_inequality_verify(statement : &SchnorrInequalityStatement, proof : & SchnorrInequalityProof) -> bool {
    let double_eq_statement = SchnorrDoubleEqualityStatement {
        g : (statement.g.0,statement.g.1),
        h : (-statement.y.0,-statement.y.1),
        y : (Identity::identity(),proof.c),
    };

    schnorr_double_equality_verify(&double_eq_statement, &proof.double_equality_proof) &&
    (<RistrettoPoint as Identity>::identity() != proof.c)
}


fn schnorr_equality_inequality_prove<T: CryptoRng + RngCore>(secret : Scalar, statement : &SchnorrEqualityInequalityStatement, rng : &mut  T) -> SchnorrEqualityInequalityProof {

    let eq_statement = SchnorrEqualityStatement {
        g : (statement.g.0,statement.g.1),
        y : (statement.y.0,statement.y.1),
    };

    let ineq_statement = SchnorrInequalityStatement {
        g : (statement.g.0,statement.g.2),
        y : (statement.y.0,statement.y.2),
    };

    let eq_proof = schnorr_equality_prove(secret, &eq_statement, rng);
    let ineq_proof = schnorr_inequality_prove(secret, &ineq_statement, rng);

    SchnorrEqualityInequalityProof {
        eq : eq_proof,
        ineq : ineq_proof,
    }
}

fn schnorr_equality_inequality_verify(statement : &SchnorrEqualityInequalityStatement, proof : & SchnorrEqualityInequalityProof) -> bool {
    let eq_statement = SchnorrEqualityStatement {
        g : (statement.g.0,statement.g.1),
        y : (statement.y.0,statement.y.1),
    };

    let ineq_statement = SchnorrInequalityStatement {
        g : (statement.g.0,statement.g.2),
        y : (statement.y.0,statement.y.2),
    };

    schnorr_equality_verify(&eq_statement, &proof.eq) && schnorr_inequality_verify(&ineq_statement, &proof.ineq)
}

fn schnorr_sok<T: CryptoRng + RngCore>(g : RistrettoPoint, secret : Scalar, statement : RistrettoPoint, m : Vec<u8>, rng : &mut  T) -> SchnorrSOK {
    let r: Scalar = Scalar::random(rng);
    let rr = r * g;

    let mut hasher = Sha256::new();

    // write input message
    let mut pre_hash = m.clone();
    pre_hash.extend_from_slice(&ristretto_point_to_bytes(&g));
    pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement));
    pre_hash.extend_from_slice(&ristretto_point_to_bytes(&rr));

    hasher.update(pre_hash);

    // read hash digest and consume hasher
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    let z = r + (c * secret);

    SchnorrSOK{
        com : rr,
        resp : z,
    }
}

fn schnorr_sok_verify(g : RistrettoPoint, signature : &SchnorrSOK, statement : RistrettoPoint, m : Vec<u8>,) -> bool {
    let mut hasher = Sha256::new();

    // write input message
    let mut pre_hash = m.clone();
    pre_hash.extend_from_slice(&ristretto_point_to_bytes(&g));
    pre_hash.extend_from_slice(&ristretto_point_to_bytes(&statement));
    pre_hash.extend_from_slice(&ristretto_point_to_bytes(&signature.com));

    hasher.update(pre_hash);

    // read hash digest and consume hasher
    let h = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(h.into());
    signature.resp * g == signature.com + (c * statement)
}

fn ristretto_point_to_bytes(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

//Lagrange

/// Multiplies two polynomials represented as vectors of Scalars.
fn multiply_polynomials(poly1: &[Scalar], poly2: &[Scalar]) -> Vec<Scalar> {
    let mut result = vec![Scalar::from(0u64); poly1.len() + poly2.len() - 1];

    for (i, &coeff1) in poly1.iter().enumerate() {
        for (j, &coeff2) in poly2.iter().enumerate() {
            result[i + j] += coeff1 * coeff2;
        }
    }

    result
}

// Computes the Lagrange basis polynomial for a given set of x_values at index k.
fn lagrange_basis_polynomial(x_values: &[Scalar], k: usize) -> Vec<Scalar> {
    let mut numerator = vec![Scalar::from(1u64)];
    let mut denominator = Scalar::from(1u64);

    for (j, &x_j) in x_values.iter().enumerate() {
        if j != k {
            numerator = multiply_polynomials(&numerator, &[Scalar::from(0u64) - x_j, Scalar::from(1u64)]);
            denominator *= x_values[k] - x_j;
        }
    }

    numerator.iter_mut().for_each(|coeff| *coeff *= denominator.invert());
    numerator
}

// Computes the Lagrange interpolation polynomial for the given set of x_values and y_values.
fn lagrange_interpolation_polynomial(x_values: &[Scalar], y_values: &[Scalar]) -> Vec<Scalar> {
    assert!(x_values.len() == y_values.len(), "x_values and y_values must have the same length");

    let mut result = vec![Scalar::from(0u64); x_values.len()];

    for (k, &y_k) in y_values.iter().enumerate() {
        let basis_poly = lagrange_basis_polynomial(x_values, k);
        for (i, coeff) in basis_poly.iter().enumerate() {
            if i < result.len() {
                result[i] += y_k * coeff;
            } else {
                result.push(y_k * coeff);
            }
        }
    }

    result
}

// Evaluates a polynomial at a given x.
fn evaluate_polynomial(coefficients: &[Scalar], x: Scalar) -> Scalar {
    let mut result = Scalar::from(0u64);
    let mut x_power = Scalar::from(1u64);

    for &coeff in coefficients {
        result += coeff * x_power;
        x_power *= x;
    }

    result
}

// Returns the degree of a polynomial represented by a vector of Scalars.
fn polynomial_degree(coefficients: &[Scalar]) -> usize {
    for i in (0..coefficients.len()).rev() {
        if coefficients[i] != Scalar::from(0u64) {
            return i;
        }
    }
    0 // If all coefficients are zero, return degree 0 (constant polynomial).
}

fn vec_to_blocks(vec: &Vec<u8>) -> Vec<[u8; 64]> {
    let mut blocks = Vec::new();
    let mut i = 0;

    while i < vec.len() {
        let mut block = [0u8; 64];
        let end = usize::min(i + 64, vec.len());
        block[..end - i].copy_from_slice(&vec[i..end]);
        blocks.push(block);
        i += 64;
    }

    blocks
}

fn blocks_to_vec(blocks: &Vec<[u8; 64]>) -> Vec<u8> {
    let mut vec = Vec::new();

    for i in  0..blocks.len() {
        for j in 0..64 {
            vec.push(blocks[i][j]);
        }
    }

    vec
}

struct Paper {
    com_author : PedersenCommitment,
    com_content : PedersenCommitment,
    enc_keys_content : ProvedHashElGamalCipher,
    conflict_tokens : Vec<RistrettoPoint>,
    sig : SchnorrSOK,
}

impl Paper {

    fn to_vec(&self) -> Vec<u8>{
        let mut vec = Vec::new();
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com_author.com));
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.com_content.com));
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.enc_keys_content.nonce));
        for x in &self.enc_keys_content.blocs {
            vec.extend_from_slice(x);
        }
        for conf in &self.conflict_tokens {
            vec.extend_from_slice(&ristretto_point_to_bytes(conf));
        }
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.sig.com));
        vec.extend_from_slice(&self.sig.resp.to_bytes());
        vec
    }

    fn hash_on_curve(&self) -> RistrettoPoint{
        RistrettoPoint::hash_from_bytes::<Sha512>(&self.to_vec())
    }
}

fn get_h() -> RistrettoPoint {
    let htab : [u8; 32] = [244, 185, 72, 81, 63, 182, 22, 143, 52, 183, 204, 17, 28, 6, 76, 23, 115, 56, 192, 179, 93, 38, 1, 178, 242, 126, 166, 117, 49, 236, 30, 103]; // point généré aléatoirement
    let hc = CompressedRistretto::from_slice(&htab).expect("Erreur lors de la convertion du tableau en CompressedRistretto pour instancier h");
    hc.decompress().expect("Erreur lors de la convertion du CompressedRistretto ent RistrettoPoint pour instancier h")
}

fn submit<T: CryptoRng + RngCore>(pkc : RistrettoPoint, ka : &AuthorKeys,  pkr : &Vec<RistrettoPoint>, authors : &Vec<u8>, content : &Vec<u8>, conflicts : &Vec<u8>, rng : &mut  T) -> Paper {
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = get_h();

    //commitments
    let com_c = pedersen_commit(ka.sk.2,h,content);

    let com_a = pedersen_commit(ka.sk.3,h,authors);

    //encryption of ska1 and ska2
    let ska0_bytes_32 : [u8; 32] = (ka.sk.0).to_bytes();
    let ska2_bytes_32 : [u8; 32] = (ka.sk.2).to_bytes();
    let mut ska_bytes_64 : [u8; 64] = [0;64];
    for i in 0..32 {
        ska_bytes_64[i] = ska0_bytes_32[i];
    }
    for i in 0..32 {
        ska_bytes_64[32 + i] = ska2_bytes_32[i];
    }
    let mut to_encrypt : Vec<[u8; 64]> = Vec::new();
    to_encrypt.push(ska_bytes_64);
    to_encrypt.extend(vec_to_blocks(content));

    let enc_k_c = proved_hash_elgamal_encrypt(g, &to_encrypt , pkc,rng);

    let mut conflict_t : Vec<RistrettoPoint> = Vec::new();
    for i in 0..pkr.len(){
        if conflicts[i] == 1 {
            conflict_t.push(ka.sk.0 * pkr[i]);
        }
        else {
            conflict_t.push(RistrettoPoint::random(rng));
        }
    }
    let mut rng_shuffle = thread_rng();
    conflict_t.shuffle(&mut rng_shuffle);

    let mut to_sign = Vec::new();

    to_sign.extend_from_slice(&ristretto_point_to_bytes(&com_a.com));
    to_sign.extend_from_slice(&ristretto_point_to_bytes(&com_c.com));
    to_sign.extend_from_slice(&ristretto_point_to_bytes(&enc_k_c.nonce));
    to_sign.extend_from_slice(&(enc_k_c.proof.to_vec()));
    for x in &enc_k_c.blocs {
        to_sign.extend_from_slice(x);
    }
    for conf in &conflict_t {
        to_sign.extend_from_slice(&ristretto_point_to_bytes(conf));
    }

    let final_sig = schnorr_sok(g, ka.sk.1, ka.pk.1, to_sign, rng);

    Paper {
        com_author : com_a,
        com_content : com_c,
        enc_keys_content : enc_k_c,
        conflict_tokens : conflict_t,
        sig : final_sig,
    }
}


fn submit_verify(pka : (RistrettoPoint,RistrettoPoint), p : &Paper) -> bool {
    // conflict is used as a boolean vector
    let g = RISTRETTO_BASEPOINT_POINT;

    let mut signed_m = Vec::new();

    signed_m.extend_from_slice(&ristretto_point_to_bytes(&p.com_author.com));
    signed_m.extend_from_slice(&ristretto_point_to_bytes(&p.com_content.com));
    signed_m.extend_from_slice(&ristretto_point_to_bytes(&p.enc_keys_content.nonce));
    signed_m.extend_from_slice(&(p.enc_keys_content.proof.to_vec()));
    for x in &p.enc_keys_content.blocs {
        signed_m.extend_from_slice(x);
    }
    for conf in &p.conflict_tokens {
        signed_m.extend_from_slice(&ristretto_point_to_bytes(conf));
    }

    schnorr_sok_verify(g, &p.sig, pka.1, signed_m) && proved_hash_elgamal_verify(&p.enc_keys_content)
}

enum Distribution {
    Conflict,
    NoConflict(Vec<u8>,Scalar),
}

fn distribute(skc : Scalar, papers : &Vec<Paper>, pkr : RistrettoPoint) -> Vec<Distribution> {
    let mut dist : Vec<Distribution> = Vec::new();

    for i in 0..papers.len() {
        let keys_content : Vec<u8> = blocks_to_vec(&proved_hash_elgamal_decrypt(&papers[i].enc_keys_content,skc));

        let mut ska0_bytes_32 : [u8; 32] = [0;32];

        for i in 0..32 {
            ska0_bytes_32[i] = keys_content[i];
        }

        let ska0 : Scalar = Scalar::from_bytes_mod_order(ska0_bytes_32);
        let token = ska0 * pkr;

        if papers[i].conflict_tokens.contains(&token) {
            dist.push(Distribution::Conflict);
        }
        else {
            let mut ska2_bytes_32 : [u8; 32] = [0;32];
            for i in 0..32 {
                ska2_bytes_32[i] = keys_content[32+i];
            }
            let ska2 : Scalar = Scalar::from_bytes_mod_order(ska2_bytes_32);

            let mut content = Vec::new();

            for i in 64..keys_content.len() {
                content.push(keys_content[i]);
            }

            dist.push(Distribution::NoConflict(content,ska2));
        }
    }
    dist
}

fn distribution_verify(skr : Scalar, distribution_vector : &Vec<Distribution>, papers : &Vec<Paper>, pka : &Vec<(RistrettoPoint,RistrettoPoint)>) -> bool {

    let h = get_h();
    let mut ret = true;
    for i in 0..papers.len() {
        let token = skr * pka[i].0;

        ret = ret && match &distribution_vector[i] {
            Distribution::NoConflict(content,ska) => {
                pedersen_verify(h, content, &papers[i].com_content, * ska)
            }
            Distribution::Conflict => {
                papers[i].conflict_tokens.contains(&token)
            }
        };
    }
    ret

}

struct Bid {
    base : RistrettoPoint,
    gamma : RistrettoPoint,
    pk : RistrettoPoint,
    proof : Option<Vec<SchnorrEqualityInequalityProof>>,
    proof_or : SchnorrOrEqualityProof, // Proof that the bid author is one of the reviewers
    mark : u8,
    sok : SchnorrSOK,
}

impl Bid {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.base));
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.gamma));
        vec.extend_from_slice(&ristretto_point_to_bytes(&self.pk));

        match &self.proof {
            Some(vec_proof) => {
                for v in vec_proof {
                    vec.extend_from_slice(&v.to_vec());
                }
            }
            None => ()
        }
        vec.extend_from_slice(&self.proof_or.to_vec());
        vec.push(self.mark);
        vec.extend_from_slice(&self.sok.to_vec());
        vec
    }
    fn copy(&self) -> Bid{
        let n_proof : Option<Vec<SchnorrEqualityInequalityProof>> = match &self.proof {
            Some(vec_proof) => {
                let mut n_p : Vec<SchnorrEqualityInequalityProof> = Vec::new();
                for v in vec_proof {
                    n_p.push(
                        SchnorrEqualityInequalityProof {
                            eq : v.eq.copy(),
                            ineq : v.ineq.copy(),
                        }
                    );
                }
                Some(n_p)
            }
            None => {
                None
            }
        };
        Bid{
            base : self.base,
            gamma : self.gamma,
            pk : self.pk,
            proof : n_proof,
            proof_or : self.proof_or.copy(), // Proof that the bid author is one of the reviewers
            mark : self.mark,
            sok : self.sok.copy(),
        }
    }
}

fn bid_paper<T: CryptoRng + RngCore>(skr : Scalar, index : usize, pka : (RistrettoPoint,RistrettoPoint), pkr : &Vec<RistrettoPoint>, p : &Paper, mark : u8, rng : &mut T) -> Bid {
    let g = RISTRETTO_BASEPOINT_POINT;
    let p_point = p.hash_on_curve();
    let gamma = skr * p_point;
    let base = RistrettoPoint::random(rng);
    let pk = skr * base;
    let token = skr * pka.0;

    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(&p.to_vec());
    to_sign.extend_from_slice(&ristretto_point_to_bytes(&base));
    to_sign.extend_from_slice(&ristretto_point_to_bytes(&gamma));
    to_sign.extend_from_slice(&ristretto_point_to_bytes(&pk));

    let proof : Option<Vec<SchnorrEqualityInequalityProof>> = if p.conflict_tokens.contains(&token) {
        None
    }
    else {
        let mut vec : Vec<SchnorrEqualityInequalityProof> = Vec::new();
        for t in &p.conflict_tokens {
            let statement = SchnorrEqualityInequalityStatement{
                g : (base,p_point,pka.0),
                y : (pk,gamma,*t),
            };
            let proof = schnorr_equality_inequality_prove(skr,&statement,rng);
            // println!("ret : {}",schnorr_equality_inequality_verify(&statement,&proof));
            to_sign.extend_from_slice(&proof.to_vec());
            vec.push(proof);
        }
        Some(vec)
    };

    let mut base_vec : Vec<RistrettoPoint> = Vec::new();
    for _i in 0..pkr.len(){
        base_vec.push(g);
    }

    let proof_orsec = SchnorrOrEqualitySecret {
        x : skr,
        index : index,
    };

    let proof_orstat = SchnorrOrEqualityStatement {
        g : base,
        y : pk,
        g_r : base_vec,
        y_r : pkr.to_vec(),
    };

    let proof_or = schnorr_or_equality_prove(&proof_orsec,&proof_orstat,rng);

    to_sign.extend_from_slice(&proof_or.to_vec());

    to_sign.push(mark);
    let sok = schnorr_sok(base,skr,pk,to_sign,rng);

    Bid {
        base : base,
        gamma : gamma,
        pk : pk,
        proof : proof,
        proof_or : proof_or,
        mark : mark,
        sok : sok,
    }
}

fn bid_verify(pka : (RistrettoPoint,RistrettoPoint), pkr : &Vec<RistrettoPoint>, p : &Paper,b : &Bid) -> bool {
    let mut ret : bool = true;
    let g = RISTRETTO_BASEPOINT_POINT;
    let p_point = p.hash_on_curve();
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(&p.to_vec());
    to_sign.extend_from_slice(&ristretto_point_to_bytes(&b.base));
    to_sign.extend_from_slice(&ristretto_point_to_bytes(&b.gamma));
    to_sign.extend_from_slice(&ristretto_point_to_bytes(&b.pk));

    match &b.proof {
        Some(vec) => {
            for i in 0..vec.len() {
                let statement = SchnorrEqualityInequalityStatement{
                    g : (b.base,p_point,pka.0),
                    y : (b.pk,b.gamma,p.conflict_tokens[i]),
                };
                ret = ret && schnorr_equality_inequality_verify(&statement,&vec[i]);

                to_sign.extend_from_slice(&vec[i].to_vec());
            }
        }
        None => ()
    }

    to_sign.extend_from_slice(&b.proof_or.to_vec());
    to_sign.push(b.mark);
    ret = ret && schnorr_sok_verify(b.base,&b.sok,b.pk,to_sign);

    let mut base_vec : Vec<RistrettoPoint> = Vec::new();
    for _i in 0..pkr.len(){
        base_vec.push(g);
    }
    let proof_orstat = SchnorrOrEqualityStatement {
        g : b.base,
        y : b.pk,
        g_r : base_vec,
        y_r : pkr.to_vec(),
    };

    ret = ret && schnorr_or_equality_verify(&proof_orstat,&b.proof_or);

    ret
}

fn bid_pool_verify(pka : &Vec<(RistrettoPoint,RistrettoPoint)>, pkr : &Vec<RistrettoPoint>, p : &Vec<Paper>,b : &Vec<Vec<Bid>>) -> bool {
    if pka.len() != p.len() || pka.len() != b.len() {
        return false
    }
    for v in b{
        if v.len() != pkr.len(){
            return false
        }
    }
    let mut ret = true;
    for i in 0..pka.len() {
        for j in 0..pkr.len(){
            ret = ret && bid_verify(pka[i], pkr, &p[i],&b[i][j]);
            for k in j+1..pkr.len(){
                ret = ret && &b[i][j].gamma != &b[i][k].gamma
            }
        }
    }
    ret
}

struct Assignment {
    sok : SchnorrSOK,
}

impl Assignment {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.sok.to_vec());
        vec
    }
}

fn assign<T: CryptoRng + RngCore>(kc : &ElGamalKeys,p : &Paper,b : &Bid, rng : &mut T) -> Assignment {
    let mut to_sign : Vec<u8> = Vec::new();
    to_sign.extend_from_slice(&p.to_vec());
    to_sign.extend_from_slice(&b.to_vec());

    let sok = schnorr_sok(RISTRETTO_BASEPOINT_POINT,kc.sk,kc.pk,to_sign,rng);

    Assignment {
        sok : sok,
    }
}

fn assign_verify(pkc : RistrettoPoint, p : &Paper,b : &Bid, a : &Assignment) -> bool {
    let mut to_sign : Vec<u8> = Vec::new();
    to_sign.extend_from_slice(&p.to_vec());
    to_sign.extend_from_slice(&b.to_vec());

    schnorr_sok_verify(RISTRETTO_BASEPOINT_POINT,&a.sok,pkc,to_sign)
}

struct Acceptance {
    accept : bool,
    sok : SchnorrSOK,
    proof : Option<SchnorrPartialEqualityProof>,
}

fn accept_assign<T: CryptoRng + RngCore>(skr : Scalar, a : &Assignment, _p : &Paper, b : &Bid, b_accepted : &mut Vec<(RistrettoPoint,RistrettoPoint)>, limite : usize, rng : &mut T) -> Acceptance {
    let mut n = 0;
    let mut vec : Vec<bool> = Vec::new();
    for i in 0..b_accepted.len() {
        if b_accepted[i].1 == skr * b_accepted[i].0 {
            vec.push(true);
            n += 1;
        }
        else {
            vec.push(false);
        }
    }
    let accept = n < limite;
    let proof : Option<SchnorrPartialEqualityProof> = if !accept {
        let mut g : Vec<RistrettoPoint> = Vec::new();
        let mut y : Vec<RistrettoPoint> = Vec::new();
        g.push(b.base);
        y.push(b.pk);
        for bid in b_accepted {
            g.push(bid.0);
            y.push(bid.1);
        }
        let statement = SchnorrPartialEqualityStatement {
            g : g,
            y : y,
        };
        let secret = SchnorrPartialEqualitySecret {
            x : skr,
            partial : vec,
        };
        Some(schnorr_partial_equality_prove(&secret,&statement,rng))
    }
    else {
        None
    };

    let mut to_sign : Vec<u8> = Vec::new();

    to_sign.extend_from_slice(&a.to_vec());
    to_sign.extend_from_slice(&b.to_vec());
    to_sign.push(if accept { 1 } else { 0 });
    let sok = schnorr_sok(b.base,skr,b.pk,to_sign,rng);

    Acceptance {
        accept : accept,
        sok : sok,
        proof : proof,
    }
}


fn accept_assign_verify(acc : &Acceptance, a : &Assignment, _p : &Paper, b : &Bid, b_accepted : &mut Vec<(RistrettoPoint,RistrettoPoint)>, limite : usize) -> bool {
    if !acc.accept {
        match &acc.proof {

            Some(proof) => {
                let mut g : Vec<RistrettoPoint> = Vec::new();
                let mut y : Vec<RistrettoPoint> = Vec::new();
                g.push(b.base);
                y.push(b.pk);
                for bid in b_accepted {
                    g.push(bid.0);
                    y.push(bid.1);
                }
                let statement = SchnorrPartialEqualityStatement {
                    g : g,
                    y : y,
                };
                if !schnorr_partial_equality_verify(&statement, limite,  &proof){
                    return false;
                }
            }

            None    => return false,
        }
    }

    let mut to_sign : Vec<u8> = Vec::new();

    to_sign.extend_from_slice(&a.to_vec());
    to_sign.extend_from_slice(&b.to_vec());
    to_sign.push(if acc.accept { 1 } else { 0 });
    if !schnorr_sok_verify(b.base, &acc.sok, b.pk,to_sign){
        return false;
    }
    return true;
}

struct Review {
    w : Vec<u8>,
    sok : SchnorrSOK,
}

impl Review {
    fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend(self.w.clone());
        vec.extend(self.sok.to_vec());

        vec
    }

    fn copy(&self) -> Review {
        Review{
            w : self.w.clone(),
            sok : self.sok.copy(),
        }
    }
}

fn review<T: CryptoRng + RngCore>(skr : Scalar, _pkr : &Vec<RistrettoPoint>, _pka : (RistrettoPoint,RistrettoPoint), _p : &Paper, b : &Bid, w : &Vec<u8>, rng : &mut T) -> Review {
    let sok = schnorr_sok(b.base, skr, b.pk, w.to_vec(), rng);

    Review {
        w : w.to_vec(),
        sok : sok,
    }
}

fn review_verify(pkr : &Vec<RistrettoPoint>, pka : (RistrettoPoint,RistrettoPoint), p : &Paper, b : &Bid, rev : &Review) -> bool {
    let mut ret = schnorr_sok_verify(b.base, &rev.sok, b.pk, rev.w.to_vec());
    ret = ret && bid_verify(pka, &pkr, &p, &b);

    ret
}

struct Decision{
    w : Vec<u8>,
    sok : SchnorrSOK,
}

fn decision<T: CryptoRng + RngCore>(skc : Scalar, pkc : RistrettoPoint, p : &Paper, pka : (RistrettoPoint,RistrettoPoint), rev : &Vec<Review>, w : &Vec<u8>, rng : &mut T) -> Decision  {
    let g = RISTRETTO_BASEPOINT_POINT;
    let mut vec = Vec::new();
    vec.extend(p.to_vec());
    vec.extend_from_slice(&ristretto_point_to_bytes(&pka.0));
    vec.extend_from_slice(&ristretto_point_to_bytes(&pka.1));
    for i in 0..rev.len(){
        vec.extend(rev[i].to_vec());
    }
    vec.extend_from_slice(w);
    let sok = schnorr_sok(g, skc, pkc, vec, rng);

    Decision {
        w : w.to_vec(),
        sok : sok,
    }
}

fn decision_verify( pkc : RistrettoPoint, pkr : &Vec<RistrettoPoint>, p : &Paper, pka : (RistrettoPoint,RistrettoPoint), rev : &Vec<Review>, bids : &Vec<Bid>, d : &Decision) -> bool  {
    let g = RISTRETTO_BASEPOINT_POINT;
    let mut vec = Vec::new();
    vec.extend(p.to_vec());
    vec.extend_from_slice(&ristretto_point_to_bytes(&pka.0));
    vec.extend_from_slice(&ristretto_point_to_bytes(&pka.1));
    for i in 0..rev.len(){
        vec.extend(rev[i].to_vec());
    }
    vec.extend_from_slice(&d.w);
    let mut ret = schnorr_sok_verify(g, &d.sok, pkc, vec);

    for b in bids{
        ret = ret && bid_verify(pka, &pkr, &p ,b);
    }
    for i in 0..bids.len(){
        for j in 0..bids.len(){
            if i != j{
                ret = ret && (bids[i].gamma != bids[j].gamma);
            }
        }
    }
    ret
}

struct CameraReady {
    keys : (Scalar,Scalar),
    sig : SchnorrSOK,
}

fn camera_ready<T: CryptoRng + RngCore>(ka : &AuthorKeys,  p : &Paper, authors : &Vec<u8>, content : &Vec<u8>, cr_content : &Vec<u8>, rng : &mut  T) -> CameraReady {

    let g = RISTRETTO_BASEPOINT_POINT;

    let mut vec = Vec::new();
    vec.extend(p.to_vec());
    vec.extend_from_slice(authors);
    vec.extend_from_slice(content);
    vec.extend_from_slice(cr_content);

    let sig = schnorr_sok(g, ka.sk.1 , ka.pk.1 , vec, rng);
    let keys = (ka.sk.2, ka.sk.3);

    CameraReady {
        keys : keys,
        sig : sig,
    }
}

fn camera_ready_verify(pka : (RistrettoPoint,RistrettoPoint),  p : &Paper, authors : &Vec<u8>, content : &Vec<u8>, cr_content : &Vec<u8>, cr : &CameraReady) -> bool {
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = get_h();

    let mut vec = Vec::new();
    vec.extend(p.to_vec());
    vec.extend_from_slice(authors);
    vec.extend_from_slice(content);
    vec.extend_from_slice(cr_content);

    let mut ret : bool = schnorr_sok_verify(g, &cr.sig , pka.1 , vec);

    ret = ret && pedersen_verify(h, content, &p.com_content, cr.keys.0);
    ret = ret && pedersen_verify(h, authors, &p.com_author, cr.keys.1);

    ret
}

fn main() {

    println!("=======================================");
    println!("=======================================");
    println!("    Reviewers : {}", M);
    println!("    Papers : {}", N);
    println!("    Reviews by paper : {}", RP);
    println!("    Reviews by reviewer : {}", L);
    println!("    Conflict by paper : {}", C);
    println!("=======================================");
    println!("=======================================");

    //++++++++++++++++++++++++++++
    let full_protocol_start = Instant::now();
    //++++++++++++++++++++++++++++

    let mut csprng = OsRng;
    let mut rng = rand::thread_rng();

    let mut authors : Vec<AuthorKeys> = Vec::with_capacity(N); // Storage of the N author keys

    // (pk1,pk2) for each N auteurs
    let mut public_authors : Vec<(RistrettoPoint,RistrettoPoint)> = Vec::with_capacity(N);
    let mut authors_proof : Vec<SchnorrProof> = Vec::with_capacity(N);
    let mut authors_name : Vec<Vec<u8>> = Vec::new();

    for i in 0..N{
        let name = "Auteur ".to_string() + &i.to_string();
        let name = (name.as_bytes()).to_vec();
        authors_name.push(name);
    }

    let mut papers_content : Vec<Vec<u8>> = Vec::new(); // Papers contents
    for i in 0..N{
        let content = "paper content ".to_string() + &i.to_string();
        let content = (content.as_bytes()).to_vec();
        papers_content.push(content);
    }

    println!("=======================================");
    println!("Keys generation");
    println!("=======================================");

    let mut reviewers : Vec<ElGamalKeys> = Vec::with_capacity(M); // M reviewer keys
    let mut reviewers_proofs : Vec<SchnorrProof> = Vec::with_capacity(M);
    let mut public_reviewers : Vec<RistrettoPoint> = Vec::with_capacity(M); // Clés publiques des M reviewers

    //++++++++++++++++++++++++++++
    let start = Instant::now();
    //++++++++++++++++++++++++++++
    let chair = ElGamalKeys::generate(RISTRETTO_BASEPOINT_POINT,&mut csprng); // Chair key
    //****************************
    let duration = start.elapsed();
    println!("Chair keys generation : {:?} micros", duration.as_micros());
    //****************************

    let mut time_ms = 0;
    for i in 0..N { // Authors keys generation
        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        authors.push(AuthorKeys::generate(RISTRETTO_BASEPOINT_POINT,&mut csprng));
        //****************************
        let duration = start.elapsed();
        time_ms = time_ms + duration.as_micros();
        //****************************
        public_authors.push(authors[i].pk);
        authors_proof.push(authors[i].proof.copy());
    }

    let mut v_time_ms = 0;
    for i in 0..N { // Authors keys generation
        //++++++++++++++++++++++++++++
        let v_start = Instant::now();
        //++++++++++++++++++++++++++++
        if schnorr_verify(&authors_proof[i],&public_authors[i].0){

        }
        else {
            println!("Key proof of author {} not verified...", i);
        }
        //****************************
        let v_duration = v_start.elapsed();
        v_time_ms = v_time_ms + v_duration.as_micros();
        //****************************
    }

    let avg_ms = time_ms as f64 / N as f64;
    println!("Author keys generation (average) : {:?} micros", avg_ms);
    let v_avg_ms = v_time_ms as f64 / N as f64;
    println!("Author keys verification (average) : {:?} micros", v_avg_ms);

    let mut time_ms = 0;
    let mut v_time_ms = 0;
    for i in 0..M { // Reviewers keys generation
        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        reviewers.push(ElGamalKeys::generate(RISTRETTO_BASEPOINT_POINT,&mut csprng));
        reviewers_proofs.push(schnorr_prove(reviewers[i].sk, &reviewers[i].pk,&mut csprng));
        //****************************
        let duration = start.elapsed();
        time_ms = time_ms + duration.as_micros();
        //****************************

        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        if schnorr_verify(&reviewers_proofs[i],&reviewers[i].pk) {
            // println!("Key proof of reviewer {} verified!", i);
        }
        else {
            println!("Key proof of reviewer {} not verified...", i);
        }
        //****************************
        let duration = start.elapsed();
        v_time_ms = v_time_ms + duration.as_micros();
        //****************************
        public_reviewers.push(reviewers[i].pk);
    }
    let avg_ms = time_ms as f64 / M as f64;
    let v_avg_ms = v_time_ms as f64 / M as f64;
    println!("Reviewer keys generation (average) : {:?} micros", avg_ms);
    println!("Reviewer keys verification (average) : {:?} micros", v_avg_ms);


    println!("=======================================");
    println!("Submission phase");
    println!("=======================================");


    // Papers
    let mut papers : Vec<Paper> = Vec::with_capacity(N);

    //conflicts vectors (1 = conflict, 0 = no conflict)

    let mut conflicts : Vec<Vec<u8>> = Vec::new();
    for i in 0..N {
        conflicts.push(Vec::new());
        for _j in 0..M {
            conflicts[i].push(0);
        }
        for _j in 0..C {
            let rand = rng.gen_range(0..M);
            conflicts[i][rand] = 1;
        }
    }

    let mut time_ms = 0;
    for i in 0..N {
        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        papers.push(submit(chair.pk, &authors[i], &public_reviewers, &authors_name[i], &papers_content[i], &conflicts[i], &mut csprng));
        //****************************
        let duration = start.elapsed();
        time_ms = time_ms + duration.as_micros();
        //****************************
    }

    let avg_ms = time_ms as f64 / N as f64;
    println!("Submit paper (average) : {:?} micros", avg_ms);

    let mut v_time_ms = 0;
    for i in 0..N {
        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        if submit_verify(authors[i].pk, &papers[i]) {
            // println!("Paper {} verified!", i);
        }
        else {
            println!("Paper {} not verified...", i);
        }
        //****************************
        let duration = start.elapsed();
        v_time_ms = v_time_ms + duration.as_micros();
        //****************************
    }

    let v_avg_ms = v_time_ms as f64 / N as f64;
    println!("Paper verification (average) : {:?} micros", v_avg_ms);

    println!("=======================================");
    println!("Distribution phase");
    println!("=======================================");

    let mut time_ms = 0;
    let mut distributions : Vec<Vec<Distribution>> = Vec::with_capacity(M);
    for i in 0..M {
        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        distributions.push(distribute(chair.sk, &papers, public_reviewers[i]));
        //****************************
        let duration = start.elapsed();
        time_ms = time_ms + duration.as_micros();
        //****************************
    }

    let avg_ms = time_ms as f64 / M as f64;
    println!("Distribution (average) : {:?} micros", avg_ms);

    let mut v_time_ms = 0;
    for i in 0..M {
        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        if distribution_verify(reviewers[i].sk, &distributions[i], &papers, &public_authors) {

        }
        else {
            println!("Distribution for R{} not verified",i);
        }

        //****************************
        let duration = start.elapsed();
        v_time_ms = v_time_ms + duration.as_micros();
        //****************************
    }

    let v_avg_ms = v_time_ms as f64 / M as f64;
    println!("Distirbution verification (average) : {:?} micros", v_avg_ms);



    println!("=======================================");
    println!("Bidding phase");
    println!("=======================================");

    let mut bids : Vec<Vec<Bid>> = Vec::with_capacity(N);
    let mut annonymous_rev_key: HashMap<[u8; 32], Scalar> = HashMap::new();

    let mut time_ms = 0;

    for j in 0..N {
        let mut bid_pap : Vec<Bid> = Vec::with_capacity(M);
        for i in 0..M {
            let mark: u8 = rng.gen_range(1..=5);
            //++++++++++++++++++++++++++++
            let start = Instant::now();
            //++++++++++++++++++++++++++++
            bid_pap.push(bid_paper(reviewers[i].sk,i,authors[j].pk,&public_reviewers,&papers[j],mark,&mut csprng));
            //****************************
            let duration = start.elapsed();
            time_ms = time_ms + duration.as_micros();
            //****************************

            annonymous_rev_key.insert(ristretto_point_to_bytes(&bid_pap[i].gamma),reviewers[i].sk);
            //storage for anonymous reviewer keys
        }
        bids.push(bid_pap);
    }
    let avg_ms = time_ms as f64 / (M*N) as f64;
    println!("Bid (average) : {:?} micros", avg_ms);

    // Verification of each bid
    // let mut v_time_ms = 0;
    // for i in 0..M {
    //     for j in 0..N {
    //         //++++++++++++++++++++++++++++
    //         let start = Instant::now();
    //         //++++++++++++++++++++++++++++
    //         if bid_verify(authors[j].pk,&public_reviewers,&papers[j],&bids[j][i]) {
    //             // println!("Bid {} on paper {} verified!", i, j);
    //         }
    //         else {
    //             println!("Bid {} on paper {} not verified...", i, j);
    //         }
    //         //****************************
    //         let duration = start.elapsed();
    //         v_time_ms = v_time_ms + duration.as_micros();
    //         //****************************
    //     }
    // }

    //++++++++++++++++++++++++++++
    let start = Instant::now();
    //++++++++++++++++++++++++++++
    if bid_pool_verify(&public_authors, &public_reviewers, &papers, &bids) {
        // println!("Bid pool verified!");
    }
        else {
        println!("Bid pool not verified...");
    }
    //****************************
    let duration = start.elapsed();
    //****************************

    // let v_avg_ms = v_time_ms as f64 / (M*N) as f64;
    println!("Bid pool verification (average) : {:?} micros (={:?} seconds, {:?} minutes)", duration.as_micros(),duration.as_secs(),duration.as_secs()/60);

    println!("=======================================");
    println!("Assignation/acceptence phase");
    println!("=======================================");

    let mut ite = 0;
    let mut acc_ite = 0;
    let mut rej_ite = 0;
    let mut b_accepted : Vec<(RistrettoPoint,RistrettoPoint)> = Vec::new(); // store the anonymes pk of accepted bids
    let mut b_accepted_indices : Vec<(usize,usize)> = Vec::new(); // store the corresponding reviewer/paper indices


    let mut assign_time_ms = 0;
    let mut v_assign_time_ms = 0;
    let mut acc_as_time_ms = 0;
    let mut v_acc_as_time_ms = 0;
    let mut accept_time_ms = 0;
    let mut v_accept_time_ms = 0;
    let mut reject_time_ms = 0;
    let mut max_reject_time_ms = 0;
    let mut v_reject_time_ms = 0;

    //++++++++++++++++++++++++++++
    let assigns_start = Instant::now();
    //++++++++++++++++++++++++++++

    for i in 0..N {
        let mut num_rev = 0;
        let mut limite = L;
        let mut rev_accept : Vec<usize> = Vec::new(); // store accepting reviewers for this paper
        while num_rev < RP {
            'outer: for max in (1..=5).rev() {
                let mut rand_i: Vec<usize> = (0..M).collect();
                rand_i.shuffle(&mut thread_rng());
                for j in rand_i {//0..M {

                    if bids[i][j].mark == max && bids[i][j].proof.is_some() && !rev_accept.contains(&j){
                        // propose a paper

                        ite = ite + 1;

                        //++++++++++++++++++++++++++++
                        let start = Instant::now();
                        //++++++++++++++++++++++++++++
                        let a = assign(&chair, &papers[i], &bids[i][j], &mut csprng);
                        //****************************
                        let duration = start.elapsed();
                        assign_time_ms = assign_time_ms + duration.as_micros();
                        //****************************

                        //++++++++++++++++++++++++++++
                        let start = Instant::now();
                        //++++++++++++++++++++++++++++
                        if assign_verify(chair.pk, &papers[i], &bids[i][j], &a) {
                            // println!("Asign verification OK");
                        }
                        else {
                            println!("Asign verification not OK");
                        }
                        //****************************
                        let duration = start.elapsed();
                        v_assign_time_ms = v_assign_time_ms + duration.as_micros();
                        //****************************

                        //++++++++++++++++++++++++++++
                        let acc_as_start = Instant::now();
                        //++++++++++++++++++++++++++++
                        let acc = accept_assign(annonymous_rev_key[&ristretto_point_to_bytes(&bids[i][j].gamma)], &a , &papers[i], &bids[i][j], &mut b_accepted, limite, &mut csprng);
                        //****************************
                        let acc_as_duration = acc_as_start.elapsed();
                        //****************************
                        acc_as_time_ms = acc_as_time_ms + acc_as_duration.as_micros();

                        if acc.accept {

                            acc_ite = acc_ite + 1;
                            accept_time_ms = accept_time_ms + acc_as_duration.as_micros();

                            //++++++++++++++++++++++++++++
                            let v_acc_as_start = Instant::now();
                            //++++++++++++++++++++++++++++
                            if accept_assign_verify(&acc, &a , &papers[i], &bids[i][j], &mut b_accepted, limite) {
                                // println!("acceptance verification OK (response {})", acc.accept);
                            }
                            else {
                                println!("acceptance verification not OK......");
                            }
                            //****************************
                            let v_acc_as_duration = v_acc_as_start.elapsed();
                            //****************************

                            v_acc_as_time_ms = v_acc_as_time_ms + v_acc_as_duration.as_micros();
                            v_accept_time_ms = v_accept_time_ms + v_acc_as_duration.as_micros();

                            // println!("=======================================");
                            // println!("(Anonymous) reviwer {} accept to review paper {} !!", j, i);
                            // println!("=======================================");
                            b_accepted.push((bids[i][j].base,bids[i][j].pk));
                            rev_accept.push(j);
                            b_accepted_indices.push((j,i));
                            num_rev += 1;
                            if num_rev == RP {
                                break 'outer;
                            }
                        }
                        else {
                            rej_ite = rej_ite + 1;
                            reject_time_ms = reject_time_ms + acc_as_duration.as_micros();

                            if max_reject_time_ms < acc_as_duration.as_micros(){
                                max_reject_time_ms = acc_as_duration.as_micros();
                            }

                            //++++++++++++++++++++++++++++
                            let v_acc_as_start = Instant::now();
                            //++++++++++++++++++++++++++++

                            if accept_assign_verify(&acc, &a , &papers[i], &bids[i][j], &mut b_accepted, limite) {
                                // println!("acceptance verification OK (response {})", acc.accept);
                            }
                            else {
                                println!("acceptance verification not OK......");
                            }
                            //****************************
                            let v_acc_as_duration = v_acc_as_start.elapsed();
                            //****************************

                            v_acc_as_time_ms = v_acc_as_time_ms + v_acc_as_duration.as_micros();
                            v_reject_time_ms = v_reject_time_ms + v_acc_as_duration.as_micros();

                            // println!("=======================================");
                            // println!("(Anonymous) reviwer {} refuse to review paper {} ....", j, i);
                            // println!("=======================================");
                        }
                    }
                }
            }
            limite += 1;
            // println!("++++++++++ limite + 1 +++++++++");
        }
    }
    //****************************
    let duration = assigns_start.elapsed();
    //****************************
    println!("===> Full assignation process takes {} itterations and {} micros ({} seconds / {} minutes)",ite,duration.as_micros(),duration.as_secs(),duration.as_secs()/60);
    println!("===> Assignement accepted : {}", acc_ite);
    println!("===> Assignement rejected : {}", rej_ite);

    println!("");

    let assign_avg_ms = assign_time_ms as f64 / ite as f64;
    println!("Assignation (average) : {:?} micros", assign_avg_ms);
    let v_assign_avg_ms = v_assign_time_ms as f64 / ite as f64;
    println!("Assignation verification (average) : {:?} micros", v_assign_avg_ms);

    println!("");

    let acc_as_avg_ms = acc_as_time_ms as f64 / ite as f64;
    println!("Reviewer decision on assignement (average) : {:?} micros ({} secs)", acc_as_avg_ms,(acc_as_avg_ms/1000000.0).trunc() as i64);

    let v_acc_as_avg_ms = v_acc_as_time_ms as f64 / ite as f64;
    println!("Reviewer decision on assignement verification (average) : {:?} micros ({} secs)", v_acc_as_avg_ms,(v_acc_as_avg_ms/1000000.0).trunc() as i64);

    println!("");

    println!("Detailed results :");
    let accept_avg_ms = accept_time_ms as f64 / acc_ite as f64;
    println!("Assignement acceptence (average) : {:?} micros ({} secs)", accept_avg_ms,(accept_avg_ms/1000000.0).trunc() as i64);
    let v_accept_avg_ms = v_accept_time_ms as f64 / acc_ite as f64;
    println!("Assignement acceptence verification (average) : {:?} micros ({} secs)", v_accept_avg_ms,(v_accept_avg_ms/1000000.0).trunc() as i64);

    println!("");

    let reject_avg_ms = reject_time_ms as f64 / rej_ite as f64;
    println!("Assignement reject (average) : {:?} micros ({} secs)", reject_avg_ms,(reject_avg_ms/1000000.0).trunc() as i64);
    println!("Worst case assignement reject : {:?} micros ({} secs)", max_reject_time_ms,(max_reject_time_ms as f64/1000000.0).trunc() as i64);
    let v_reject_avg_ms = v_reject_time_ms as f64 / rej_ite as f64;
    println!("Assignement reject verification (average) : {:?} micros ({} secs)", v_reject_avg_ms,(v_reject_avg_ms/1000000.0).trunc() as i64);
    println!("");

    println!("=======================================");
    println!("Reviewing phase");
    println!("=======================================");

    let mut review_time_ms = 0;
    let mut v_review_time_ms = 0;
    let mut reviews : Vec<Review> = Vec::new();
    let mut bids_reviews : Vec<Bid> = Vec::new();

    for i in 0..b_accepted.len(){
        let w = "Review on paper ".to_string() + &b_accepted_indices[i].1.to_string() + &" by (Anonymous) reviwer ".to_string() + &b_accepted_indices[i].0.to_string() ;
        let w_vec = (w.as_bytes()).to_vec();

        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        let rev = review(reviewers[b_accepted_indices[i].0].sk, &public_reviewers, public_authors[b_accepted_indices[i].1], &papers[b_accepted_indices[i].1], &bids[b_accepted_indices[i].1][b_accepted_indices[i].0], &w_vec , &mut csprng);
        //****************************
        let duration = start.elapsed();
        //****************************

        review_time_ms = review_time_ms + duration.as_micros();
        reviews.push(rev);
        bids_reviews.push(bids[b_accepted_indices[i].1][b_accepted_indices[i].0].copy());

        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        if review_verify(&public_reviewers, public_authors[b_accepted_indices[i].1], &papers[b_accepted_indices[i].1], &bids[b_accepted_indices[i].1][b_accepted_indices[i].0], &reviews[i]) {
            // println!("Review of R{} on paper {} verified!", b_accepted_indices[i].0, b_accepted_indices[i].1);
        }
        else {
            println!("Review of R{} on paper {} not verified ...", b_accepted_indices[i].0, b_accepted_indices[i].1);
        }
        //****************************
        let duration = start.elapsed();
        //****************************
        v_review_time_ms = v_review_time_ms + duration.as_micros();
    }

    let avg_ms = review_time_ms as f64 / (b_accepted.len()) as f64;
    println!("Reviewing (average) : {:?} micros ({} secs)", avg_ms, (avg_ms/1000000.0).trunc() as i64);

    let v_avg_ms = v_review_time_ms as f64 / (b_accepted.len()) as f64;
    println!("Reviewing verification (average) : {:?} micros ({} secs)", v_avg_ms, (v_avg_ms/1000000.0).trunc() as i64);

    println!("=======================================");
    println!("Decision phase");
    println!("=======================================");

    let mut d_time_ms = 0;
    let mut v_d_time_ms = 0;

    let mut decisions : Vec<Decision> = Vec::new();
    for i in (0..reviews.len()).step_by(RP) {

        let p_i = i / RP;
        let w = "Decision on paper ".to_string() + &p_i.to_string();
        let w_vec = (w.as_bytes()).to_vec();
        let mut paper_reviews : Vec<Review> = Vec::new();
        let mut paper_bids : Vec<Bid> = Vec::new();
        for j in 0..RP {
            paper_reviews.push(reviews[i+j].copy());
            paper_bids.push(bids_reviews[i+j].copy());
        }

        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        let d = decision(chair.sk, chair.pk, &papers[p_i], public_authors[p_i], &paper_reviews, &w_vec, &mut csprng);
        decisions.push(d);
        //****************************
        let duration = start.elapsed();
        //****************************

        d_time_ms = d_time_ms + duration.as_micros();

        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        if decision_verify(chair.pk, &public_reviewers, &papers[p_i], public_authors[p_i], &paper_reviews, &paper_bids, &decisions[p_i]) {
            // println!("Decision on paper {} verified!", p_i);
        }
        else {
            println!("Decision on paper {} not verified ...", p_i);
        }
        //****************************
        let duration = start.elapsed();
        //****************************

        v_d_time_ms = v_d_time_ms + duration.as_micros();
    }

    let avg_ms = d_time_ms as f64 / (N) as f64;
    println!("Decision (average) : {:?} micros", avg_ms);

    let v_avg_ms = v_d_time_ms as f64 / (N) as f64;
    println!("Decision verification (average) : {:?} micros", v_avg_ms);

    println!("=======================================");
    println!("Camera ready phase");
    println!("=======================================");

    let mut cr_time_ms = 0;
    let mut v_cr_time_ms = 0;

    for i in 0..N{

        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        let cr = camera_ready(&authors[i],  &papers[i], &authors_name[i], &papers_content[i], &papers_content[i], &mut csprng);
        //****************************
        let duration = start.elapsed();
        //****************************

        cr_time_ms = cr_time_ms + duration.as_micros();

        //++++++++++++++++++++++++++++
        let start = Instant::now();
        //++++++++++++++++++++++++++++
        if camera_ready_verify(public_authors[i],  &papers[i], &authors_name[i], &papers_content[i], &papers_content[i], &cr) {
            // println!("Camera ready on paper {} verified!", i);
        }
        else {
            println!("Camera ready on paper {} not verified ...", i);
        }
        //****************************
        let duration = start.elapsed();
        //****************************

        v_cr_time_ms = v_cr_time_ms + duration.as_micros();

    }
    let avg_ms = cr_time_ms as f64 / (N) as f64;
    println!("Camera ready (average) : {:?} micros", avg_ms);

    let v_avg_ms = v_cr_time_ms as f64 / (N) as f64;
    println!("Camera ready verification (average) : {:?} micros", v_avg_ms);

    //****************************
    let full_protocol_duration = full_protocol_start.elapsed();
    //****************************
    println!("");
    println!("Done!");
    println!("");
    println!("===> Full process takes {} micros ({} seconds / {} minutes)",full_protocol_duration.as_micros(),full_protocol_duration.as_secs(),full_protocol_duration.as_secs()/60);
    println!("");
}


