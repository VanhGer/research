use std::collections::HashMap;
use std::ops::{Mul, Sub};
use ark_bls12_381::Fr;
use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DensePolynomial;
use sha2::Digest;
use crate::cq::Cq;
use crate::fiat_shamir::Script;
use crate::prover::Proof;

pub struct Verifier<T: Digest + Default, P: Pairing> {
    script: Script<T, P>
}

impl <T: Digest + Default, P: Pairing> Verifier<T, P> {
    pub fn new() -> Self {
        Self {
            script: Script::<T, P>::new()
        }
    }
    
    pub fn verify(&mut self, t_i: &[P::ScalarField], cq: &Cq<P>, proof: Proof<P>) {
        let Proof {
            small_n,
            cm1_f,
            cm1_m,
            cm1_a,
            cm1_q_a,
            cm1_b_0,
            cm1_q_b,
            cm1_p,
            b_0_gamma,
            f_gamma,
            a_0,
            cm1_pi_eta,
            cm1_a_0,
        } = proof;
        
        self.script.feed_with_commitments(&[cm1_f]);
        self.script.feed_with_commitments(&[cm1_m]);

        // Round 2
        let [beta] = self.script.generate_challenges();
        
        self.script.feed_with_commitments(&[
            cm1_a,
            cm1_q_a,
            cm1_b_0,
            cm1_q_b,
            cm1_p,
        ]);

        // verify e(a, [T(x)]_2) = e(q_a, [Zv(x)]_2) · e(m − β · a, [1]_2)
        let cm2_1 = cq.kzg.commit_g2(&DensePolynomial::from_coefficients_vec(vec![P::ScalarField::one()]));
        let lhs = P::pairing(cm1_a, cq.t_x_2);
        let tmp = cm1_m - cm1_a.into_group().mul(beta).into();
        let rhs = P::multi_pairing([cm1_q_a, tmp.into()], [cq.z_v_2, cm2_1]);
       
        // let rhs = P::multi_pairing([cm1_q_a, tmp], [cq.z_v_2, cm2_1]);

        // let mut x = vec![P::ScalarField::zero(); cq.big_n - 1 - (small_n - 2)];
        // x.push(P::ScalarField::one());
        // let x_poly = DensePolynomial::from_coefficients_vec(x);
        // let cm2_x = cq.kzg.commit_g2(&x_poly);
        // 
        // let lhs = P::pairing(cm1_b_0, cm2_x);
        // let rhs = P::pairing(cm1_p, cm2_1);
        assert_eq!(lhs, rhs);

        // assert_eq!(lhs, rhs);
        // let [gamma] = self.script.generate_challenges();

    }
    
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_poly::{DenseUVPolynomial, Evaluations};
    use ark_poly::univariate::DensePolynomial;
    use sha2::Sha256;
    use crate::kzg::Kzg;
    use crate::prover::Prover;
    use super::*;

    #[test]
    fn test_verify() {
        let t_i = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];
        let f_i = vec![Fr::from(1), Fr::from(2)];
        let cq = Cq::<Bls12_381>::new(&t_i);
        let mut prover = Prover::<Sha256, Bls12_381>::new(f_i);
        let proof = prover.prove(&cq, &t_i).unwrap();

        let mut verifier = Verifier::<Sha256, Bls12_381>::new();
        verifier.verify(&t_i, &cq, proof);
    }
}