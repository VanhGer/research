// benchmark the time of compute cq

use ark_bn254::{Bn254, Fr};
use ark_serialize::Compress;
use ark_std::UniformRand;
use sha2::Sha256;
use cq::cq::Cq;
use cq::prover::Prover;

pub fn proof_size(f_i_size: usize, t_i_size: usize) -> usize{
        let big_n = 2_usize.pow(t_i_size as u32);
        let small_n = 2_usize.pow(f_i_size as u32);
        let mut rng = ark_std::test_rng();

        let t_i: Vec<Fr> = (0..big_n).map(|_| Fr::rand(&mut rng)).collect();
        let f_i: Vec<Fr> = (0..small_n).map(|_| {
            let index = rand::random::<usize>() % big_n;
            t_i[index]
        }).collect();
        let cq = Cq::<Bn254>::new(&t_i).unwrap();
        let mut prover = Prover::<Sha256, Bn254>::new(f_i.clone()).unwrap();
        let proof = prover.prove(&cq, &t_i).unwrap();
        proof.serialized_size(Compress::No)
}

fn main() {
    for (f_i_sz, t_i_sz) in [(5_usize, 6_usize), (8, 10), (12, 15)] {
        println!("Proof size for f_i size = {} and t_i size = {} is {}", f_i_sz, t_i_sz, proof_size(f_i_sz, t_i_sz));
    }
}
