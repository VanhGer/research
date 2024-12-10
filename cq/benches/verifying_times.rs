// benchmark the time of compute cq

use ark_bn254::{Bn254, Fr};
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use sha2::Sha256;
use cq::cq::Cq;
use cq::prover::Prover;
use cq::verifier::Verifier;

pub fn verify(c: &mut Criterion) {
    for size in [6, 10, 15] {
        let big_n = 2_usize.pow(size);
        let small_n = 2_usize.pow(size/2);
        let mut rng = ark_std::test_rng();

        let t_i: Vec<Fr> = (0..big_n).map(|_| Fr::rand(&mut rng)).collect();
        let f_i: Vec<Fr> = (0..small_n).map(|_| {
            let index = rand::random::<usize>() % big_n;
            t_i[index]
        }).collect();
        let cq = Cq::<Bn254>::new(&t_i).unwrap();
        let mut prover = Prover::<Sha256, Bn254>::new(f_i.clone()).unwrap();
        let proof = prover.prove(&cq, &t_i).unwrap();
        
        c.bench_with_input(BenchmarkId::new("[verify]: t_i size = ", size), &size, |b, _| {
            b.iter(|| {
                let mut verifier = Verifier::<Sha256, Bn254>::new();
                let result = verifier.verify(&t_i, &cq, proof.clone());
                result
            });
        });
    }
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = verify
}
criterion_main!(benches);