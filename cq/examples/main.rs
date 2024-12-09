use ark_bn254::{Bn254, Fr};
use ark_std::UniformRand;
use sha2::Sha256;
use cq::cq::Cq;
use cq::prover::Prover;
use cq::verifier::Verifier;

fn main() {
    
    let big_n = 2_usize.pow(6);
    let small_n = 2_usize.pow(3);
    let mut rng = ark_std::test_rng();

    let t_i: Vec<Fr> = (0..big_n).map(|_| Fr::rand(&mut rng)).collect();
    let f_i: Vec<Fr> = (0..small_n).map(|_| {
        let index = rand::random::<usize>() % big_n;
        t_i[index]
    }).collect();
    
    
    // let t_i = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];
    // let f_i = vec![Fr::from(1), Fr::from(3), Fr::from(3), Fr::from(3)];
    let start = std::time::Instant::now();
    let cq = Cq::<Bn254>::new(&t_i).unwrap();
    println!("Time to create Cq: {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let mut prover = Prover::<Sha256, Bn254>::new(f_i).unwrap();
    println!("Time to create Prover: {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let proof = prover.prove(&cq, &t_i).unwrap();
    println!("Time to generate proof: {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let mut verifier = Verifier::<Sha256, Bn254>::new();
    println!("Time to create Verifier: {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let result = verifier.batched_verify(&t_i, &cq, proof);
    println!("Time to verify proof: {:?}", start.elapsed());
    assert!(result.is_ok());
    assert!(result.unwrap());
    println!("Accepted");
}