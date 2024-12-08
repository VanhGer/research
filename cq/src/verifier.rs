use std::ops::Add;
use ark_ec::CurveGroup;
use std::ops::{Mul, Sub};
use ark_ec::pairing::{Pairing};
use ark_ff::{Field, One, Zero};
use ark_poly::{DenseUVPolynomial};
use ark_poly::univariate::DensePolynomial;
use sha2::Digest;
use crate::cq::Cq;
use crate::errors::VerifierError;
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
    
    pub fn verify(&mut self, t_i: &[P::ScalarField], cq: &Cq<P>, proof: Proof<P>) -> Result<bool, VerifierError> {
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
            cm1_a_0_x,
        } = proof;
        
        if !small_n.is_power_of_two() {
            return Err(VerifierError::WitnessSizeNotPowerOf2);
        } else if !t_i.len().is_power_of_two() {
            return Err(VerifierError::TableSizeNotPowerOf2);
        }
        
        
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
        let tmp = cm1_m - cm1_a.mul(beta).into_affine();
        let rhs = P::multi_pairing([cm1_q_a, tmp.into()], [cq.z_v_2, cm2_1]);
        assert_eq!(lhs, rhs, "Failed to verify e(a, [T(x)]_2) = e(q_a, [Zv(x)]_2) · e(m − β · a, [1]_2)");


        // verify that B0 has the appropriate degree
        // e(b_0, [X^{N-1 - (n-2)}]_2) = e(p, [1]_2)

        let mut x_pow = vec![P::ScalarField::zero(); cq.big_n - 1 - (small_n - 2)];
        x_pow.push(P::ScalarField::one());
        let x_pow_poly = DensePolynomial::from_coefficients_vec(x_pow);
        let cm2_x_pow = cq.kzg.commit_g2(&x_pow_poly);
        let lhs = P::pairing(cm1_b_0, cm2_x_pow);
        let rhs = P::pairing(cm1_p, cm2_1);
        assert_eq!(lhs, rhs, "Failed to verify e(b_0, [X^(N-1 - (n-2))]_2) = e(p, [1]_2)");

        // Round 3
        let [gamma] = self.script.generate_challenges();
        self.script.feed_with_commitments(&[b_0_gamma, f_gamma, a_0]);
        // compute b_0:
        let n_inv = P::ScalarField::from(small_n as u128).inverse().unwrap();
        let b_0 = P::ScalarField::from(cq.big_n as u128) * a_0 * n_inv;

        // compute z_h(gamma), b_gamma, q_b_gamma
        let z_h_gamma = gamma.pow(&[small_n as u64]) - P::ScalarField::one();

        let z_h_gamma_inv = z_h_gamma.inverse().unwrap();
        let b_gamma = b_0_gamma * gamma + b_0;
        let q_b_gamma = (b_gamma * (f_gamma + beta) - P::ScalarField::one()) * z_h_gamma_inv;

        // Step 6
        let [eta] = self.script.generate_challenges();
        let v = b_0_gamma + eta * f_gamma + eta * eta * q_b_gamma;

        let cm1_c = cm1_b_0 + cm1_f.mul(eta) + cm1_q_b.mul(eta * eta);

        // check e(c - [v]_1 + gamma * [pi_eta]_1, [1]_2) = e([pi_gamma]_1, [x]_2)
        let x_poly = DensePolynomial::from_coefficients_vec(vec![P::ScalarField::zero(), P::ScalarField::one()]);
        let cm2_x = cq.kzg.commit_g2(&x_poly);
        let cm1_v = cq.kzg.commit_g1(&DensePolynomial::from_coefficients_vec(vec![v]));
        let lhs = P::pairing(cm1_c.sub(cm1_v).add(cm1_pi_eta.mul(gamma).into()), cm2_1);
        let rhs = P::pairing(cm1_pi_eta, cm2_x);
        assert_eq!(lhs, rhs, "Failed to verify e(c - [v]_1 + gamma * [pi_eta]_1, [1]_2) = e([pi_gamma]_1, [x]_2)");

        // check e(a_1 - [a_0]_1, [1]_2) = e(a0_1, [x]_2)
        let a_0_poly = DensePolynomial::from_coefficients_vec(vec![a_0]);
        let cm1_a_0 = cq.kzg.commit_g1(&a_0_poly);

        let lhs = P::pairing(cm1_a.sub(cm1_a_0), cm2_1);
        let rhs = P::pairing(cm1_a_0_x, cm2_x);
        assert_eq!(lhs, rhs, "Failed to verify e(a_1 - [a_0]_1, [1]_2) = e(a0_1, [x]_2)");
        
        Ok(true)
    }
    
}

#[cfg(test)]
mod tests {
    use ark_poly::EvaluationDomain;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_ec::CurveGroup;
    use ark_ff::Field;
    use ark_poly::{DenseUVPolynomial, GeneralEvaluationDomain};
    use ark_poly::univariate::DensePolynomial;
    use sha2::Sha256;
    use crate::kzg::Kzg;
    use crate::prover::Prover;
    use super::*;

    #[test]
    fn test_verify() {
        let t_i = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];
        let f_i = vec![Fr::from(1), Fr::from(3), Fr::from(3), Fr::from(3)];
        let cq = Cq::<Bls12_381>::new(&t_i).unwrap();
        let mut prover = Prover::<Sha256, Bls12_381>::new(f_i).unwrap();
        let proof = prover.prove(&cq, &t_i).unwrap();

        let mut verifier = Verifier::<Sha256, Bls12_381>::new();
        let result = verifier.verify(&t_i, &cq, proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    #[test]
    fn dummy_test_02() {
        let t_i = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];
        let f_i = vec![Fr::from(1), Fr::from(3), Fr::from(3)];
        let m_i = vec![Fr::from(1), Fr::from(0), Fr::from(2), Fr::from(0)];

        let kzg = Kzg::<Bls12_381>::new(4);
        let mut vec_a = vec![];
        let beta = Fr::one();
        let mut res1 = Fr::zero();
        let mut res2 = Fr::zero();
        for (index, value) in m_i.iter().enumerate() {
            let tmp = t_i[index] + beta;
            let v = tmp.inverse().unwrap() * (*value);
            res1 += v;
            vec_a.push(v);
        }
        for value in f_i {
            let tmp = (value + beta).inverse().unwrap();
            res2 += tmp;
        }
        assert_eq!(res1, res2);

        let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();
        let a_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&vec_a));
        let z_v_x = DensePolynomial::from_coefficients_vec(vec![Fr::from(-1), Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(1)]);
        let z_v_2 = kzg.commit_g2(&z_v_x);
        let t_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&t_i));
        let t_x_2 = kzg.commit_g2(&t_x);
        let m_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&m_i));
        let tmp = a_x.clone().mul(t_x.clone() + DensePolynomial::from_coefficients_vec(vec![beta]))
            .sub(m_x.clone());

        let (q_a_x, rem) = tmp.divide_by_vanishing_poly(domain);
        assert!(rem.is_zero());

        let rhs = q_a_x.clone().mul(&z_v_x);
        let lhs = a_x.clone().mul(t_x + DensePolynomial::from_coefficients_vec(vec![beta])) - m_x.clone();
        assert_eq!(rhs, lhs);

        let cm_m = kzg.commit_g1(&m_x);
        let cm = kzg.commit_g1(&a_x);
        let cm2 = kzg.commit_g1(&q_a_x);
        let cm2_1 =  kzg.commit_g2(&DensePolynomial::from_coefficients_vec(vec![Fr::one()]));

        // let beta_2 = cq.kzg.commit_g2(&DensePolynomial::from_coefficients_vec(vec![beta]));
        let lhs = Bls12_381::pairing(cm, t_x_2);
        let tmp = cm_m - cm.mul(beta).into_affine();
        let rhs = Bls12_381::multi_pairing([cm2, tmp.into()], [z_v_2, cm2_1]);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn dummy_test() {
        let a_x = DensePolynomial::from_coefficients_vec(vec![Fr::from(0), Fr::from(0), Fr::from(1)]);
        let t_x = DensePolynomial::from_coefficients_vec(vec![Fr::from(3), Fr::from(1)]);
        let q_a_x = DensePolynomial::from_coefficients_vec(vec![Fr::from(1), Fr::from(1)]);
        let z_v_x = DensePolynomial::from_coefficients_vec(vec![Fr::from(-1), Fr::from(0), Fr::from(1)]);
        let m_x = DensePolynomial::from_coefficients_vec(vec![Fr::from(1), Fr::from(1), Fr::from(3)]);
        let beta = Fr::from(1);

        let domain = GeneralEvaluationDomain::<Fr>::new(2).unwrap();
        let z_v_x2 = domain.vanishing_polynomial();
        assert_eq!(z_v_x2, z_v_x.clone().into());

        let tmp = a_x.clone().mul(t_x.clone() + DensePolynomial::from_coefficients_vec(vec![beta]))
            .sub(m_x.clone());

        let (q_a_x_2, rem) = tmp.divide_by_vanishing_poly(domain);
        assert!(rem.is_zero());
        assert_eq!(q_a_x, q_a_x_2);

        let kzg = Kzg::<Bls12_381>::new(3);
        let cm1_a = kzg.commit_g1(&a_x);
        let t_x_2 = kzg.commit_g2(&t_x);
        let cm1_q_a = kzg.commit_g1(&q_a_x);
        let cm2_z_v = kzg.commit_g2(&z_v_x);
        let cm1_m = kzg.commit_g1(&m_x);
        let cm2_1 = kzg.commit_g2(&DensePolynomial::from_coefficients_vec(vec![Fr::one()]));

        let lhs = Bls12_381::pairing(cm1_a, t_x_2);
        let tmp = cm1_m - cm1_a.mul(beta);

        let rhs = Bls12_381::multi_pairing([cm1_q_a, tmp.into_affine()], [cm2_z_v, cm2_1]);
        assert_eq!(lhs, rhs);
    }
}