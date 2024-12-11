// benchmark the time of compute cq

use ark_bn254::{Bn254, Fr};
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use cq::cq::Cq;

pub fn cq(c: &mut Criterion) {
    for size in [6, 10, 15] {
        c.bench_with_input(BenchmarkId::new("[cq]: t_i size = ", size), &size, |b, size| {
            let big_n = 2_u64.pow(*size);
            let mut rng = ark_std::test_rng();

            let t_i: Vec<Fr> = (0..big_n).map(|_| Fr::rand(&mut rng)).collect();
            
            b.iter(|| {
                let cq = Cq::<Bn254>::new(&t_i).unwrap();
                cq
            });
        });
    }
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = cq
}
criterion_main!(benches);