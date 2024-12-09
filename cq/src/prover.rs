use ark_ff::{Field, One};
use std::collections::HashMap;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial};
use std::ops::{AddAssign, Mul, };
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_poly::GeneralEvaluationDomain;
use ark_poly::univariate::DensePolynomial;
use sha2::Digest;
use crate::cq::Cq;
use crate::errors::GeneralError;
use crate::fiat_shamir::Script;

pub struct Prover<T: Digest + Default, P: Pairing> {
    f_i: Vec<P::ScalarField>,
    f_i_map: HashMap<P::ScalarField, usize>,
    script: Script<T, P>,
    
}

struct RoundTwoResponse<P: Pairing> {
    b_x: DensePolynomial<P::ScalarField>,
    b_0_x: DensePolynomial<P::ScalarField>,
    q_b_x: DensePolynomial<P::ScalarField>,
    // p_x: DensePolynomial<P::ScalarField>,
    a_sparse: Vec<(P::ScalarField, usize)>,
    cm1_a: P::G1Affine,
    cm1_q_a: P::G1Affine,
    cm1_b_0: P::G1Affine,
    cm1_q_b: P::G1Affine,
    cm1_p: P::G1Affine,
}

struct RoundThreeResponse<P: Pairing> {
    b_0_gamma: P::ScalarField,
    f_gamma: P::ScalarField,
    a_0: P::ScalarField,
    cm1_pi_eta: P::G1Affine,
    cm1_a_0_x: P::G1Affine,
}

pub struct Proof<P: Pairing> {
    pub small_n: usize, 
    pub cm1_f: P::G1Affine,
    pub cm1_m: P::G1Affine,
    pub cm1_a: P::G1Affine,
    pub cm1_q_a: P::G1Affine,
    pub cm1_b_0: P::G1Affine,
    pub cm1_q_b: P::G1Affine,
    pub cm1_p: P::G1Affine,
    pub b_0_gamma: P::ScalarField,
    pub f_gamma: P::ScalarField,
    pub a_0: P::ScalarField,
    pub cm1_pi_eta: P::G1Affine,
    pub cm1_a_0_x: P::G1Affine,
}


impl <T: Digest + Default, P: Pairing> Prover<T, P> {
    pub fn new(f_i: Vec<P::ScalarField>) -> Result<Self, GeneralError> {
        if !f_i.len().is_power_of_two() {
            return Err(GeneralError::WitnessSizeNotPowerOf2);
        }
        let mut hash_map = HashMap::<P::ScalarField, usize>::new();
        for (_, f) in f_i.iter().enumerate() {
            let value = hash_map.get(f);
            if value.is_none() {
                hash_map.insert(*f, 1);
            } else {
                hash_map.insert(*f, value.unwrap() + 1);
            }
        }
        
        Ok(Self {
            f_i,
            f_i_map: hash_map,
            script: Script::new(),
        })
    }
    
    fn compute_cm1_fx(&self, cq: &Cq<P>) -> (DensePolynomial<P::ScalarField>, P::G1Affine) {
        let n = self.f_i.len();
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(n).unwrap();
        
        let f_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&self.f_i));
        let cm1_fx = cq.kzg.commit_g1(&f_x);
        (f_x, cm1_fx)
    }

    // compute cm1_mx = Σ cm1_li * m_i
    fn compute_cm1_mx(&self, cq: &Cq<P>, m_i_vec: &[(usize, usize)]) -> P::G1Affine {
        let mut cm1_mx = P::G1::zero();
        for (index, value) in m_i_vec {
            let value = P::ScalarField::from(*value as u64);
            let tmp = cq.cm1_li[*index].mul(value);
            cm1_mx.add_assign(tmp);
        }

        cm1_mx.into_affine()
    }

    fn compute_round_2(
        &self,
        cq: &Cq<P>, f_x: &DensePolynomial<P::ScalarField>,
        m_i_vec: &[(usize, usize)], t_i: &[P::ScalarField], beta: P::ScalarField
    ) -> Result<RoundTwoResponse<P>, GeneralError>
    {
        // Step 2 3 4
        // A_1 = Σ cm1_li * m_i / (t_i + beta) =  Σ cm1_li * a_i
        // Q_1 = Σ cm1_qi * m_i / (t_i + beta) =  Σ cm1_qi * a_i

        let mut a_sparse: Vec<(P::ScalarField, usize)> = vec![];

        let mut cm1_a = P::G1::zero();
        let mut cm1_q_a = P::G1::zero();
        for (index, value) in m_i_vec {
            let value = P::ScalarField::from(*value as u64);
            let tmp = t_i[*index] + beta;
            let a_i = tmp.inverse().unwrap() * value;
            a_sparse.push((a_i, *index));
            cm1_a.add_assign(cq.cm1_li[*index].mul(a_i));
            cm1_q_a.add_assign(cq.cm1_qi[*index].mul(a_i));
        }

        // Step 5 & 6
        // B_i = 1 / (f_i + beta)
        // B_0_x = (b_x - b[0]) / X
        let b_evals = self.f_i.iter().map(|f_i| {
            (*f_i + beta).inverse().unwrap()
        }).collect::<Vec<P::ScalarField>>();

        let small_n = self.f_i.len();
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(small_n).unwrap();

        let b_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&b_evals));
        let b_0_x = DensePolynomial::from_coefficients_slice(&b_x.coeffs[1..]);

        // Step 7
        let cm1_b_0 = cq.kzg.commit_g1(&b_0_x);

        // Step 8
        let mut f_x_plus_beta = f_x.clone();
        f_x_plus_beta.coeffs[0] += beta;

        // b_x(f_x + beta) - 1
        let tmp = b_x.clone().mul(&f_x_plus_beta) - DensePolynomial::from_coefficients_slice(&vec![P::ScalarField::one()]);
        let (q_b_x, rem) = tmp.divide_by_vanishing_poly(domain);

        if !rem.is_zero() {
            return Err(GeneralError::CannotDivideByVanishingPolynomial);
        }

        // Step 9
        let cm1_q_b = cq.kzg.commit_g1(&q_b_x);

        // Step 10
        let mut p_x_coeffs = vec![P::ScalarField::zero(); cq.big_n - 1 - (small_n - 2)];
        p_x_coeffs.extend_from_slice(&b_0_x.coeffs);
        let p_x = DensePolynomial::from_coefficients_slice(&p_x_coeffs);
        let cm1_p = cq.kzg.commit_g1(&p_x);

        Ok(RoundTwoResponse {
            b_x,
            b_0_x,
            q_b_x,
            // p_x,
            a_sparse,
            cm1_a: cm1_a.into_affine(),
            cm1_q_a: cm1_q_a.into_affine(),
            cm1_b_0,
            cm1_q_b,
            cm1_p,
        })




    }

    fn compute_round_3(
        &mut self,
        cq: &Cq<P>, gamma: P::ScalarField, b_0: P::ScalarField,
        q_b_x: &DensePolynomial<P::ScalarField>,
        f_x: &DensePolynomial<P::ScalarField>, b_0_x: &DensePolynomial<P::ScalarField>,
        a_sparse: &[(P::ScalarField, usize)]
    ) -> Result<RoundThreeResponse<P>, GeneralError> 
    {
        let small_n = self.f_i.len();

        // Step 2, 3
        let b_0_gamma = b_0_x.evaluate(&gamma);
        let f_gamma = f_x.evaluate(&gamma);

        // Step 4
        // small_n * B[0] = big_n * A[0] (via Aurora lemma)
        let big_n_inv = P::ScalarField::from(cq.big_n as u128).inverse().unwrap();
        let a_0 = b_0 * P::ScalarField::from(small_n as u128) * big_n_inv;
        // Batch KZG checks
        // Prover needs to send above values to verifier to receive a challenge.
        self.script.feed_with_field_elements(&[b_0_gamma, f_gamma, a_0]);
        let [eta] = self.script.generate_challenges();

        // Step 6a
        let q_b_gamma = q_b_x.evaluate(&gamma);
        let v = b_0_gamma + eta * f_gamma + eta * eta * q_b_gamma;
        // Step 6b
        let tmp = b_0_x + f_x.mul(eta) + q_b_x.mul(eta * eta) - DensePolynomial::from_coefficients_slice(&vec![v]);
        let h_x = tmp / DensePolynomial::from_coefficients_vec(vec![-gamma, P::ScalarField::one()]);
        let cm1_pi_eta = cq.kzg.commit_g1(&h_x);

        // Step 7
        // [A_0_X]_1 = ∑ cm1_l_i_quotient * a_i
        let mut cm1_a_0_x = P::G1::zero();
        for (a_i, index) in a_sparse {
            cm1_a_0_x.add_assign(cq.cm1_l_i_quotient[*index].mul(a_i));
        }

        Ok(RoundThreeResponse {
            b_0_gamma,
            f_gamma,
            a_0,
            cm1_pi_eta,
            cm1_a_0_x: cm1_a_0_x.into_affine(),
        })

    }
    pub fn prove(&mut self, cq: &Cq<P>, t_i: &[P::ScalarField]) -> Result<Proof<P>, GeneralError>{
        
        let (f_x, cm1_f) = self.compute_cm1_fx(cq);

        self.script.feed_with_commitments(&[cm1_f]);
        let mut m_i_vec: Vec<(usize, usize)> = vec![];
        
        for (f_i, value) in self.f_i_map.clone() {
            if let Some(&index) = cq.t_hash_map.get(&f_i) {
                m_i_vec.push((index, value));
            } else {
                return Err(GeneralError::WitnessNotInTable);
            }
        }

        // Round 1
        // compute m_x_1
        let cm1_m = self.compute_cm1_mx(cq, &m_i_vec);
        // send m_x_1 to verifier
        self.script.feed_with_commitments(&[cm1_m]);

        // Round 2
        let [beta] = self.script.generate_challenges();
        // let beta = P::ScalarField::one();
        let proof_2 = self.compute_round_2(cq, &f_x, &m_i_vec, t_i, beta)?;

        // send cm1_a, cm1_q_a, cm1_b_0, cm1_q_b, cm1_p to verifier
        self.script.feed_with_commitments(&[
            proof_2.cm1_a,
            proof_2.cm1_q_a,
            proof_2.cm1_b_0,
            proof_2.cm1_q_b,
            proof_2.cm1_p,
        ]);


        // Round 3
        let [gamma] = self.script.generate_challenges();

        let b_0 = proof_2.b_x.evaluate(&P::ScalarField::zero());
        let proof_3 = self.compute_round_3(cq, gamma, b_0, &proof_2.q_b_x, &f_x, &proof_2.b_0_x, &proof_2.a_sparse).unwrap();

        Ok(Proof {
            small_n: self.f_i.len(),
            cm1_f,
            cm1_m,
            cm1_a: proof_2.cm1_a,
            cm1_q_a: proof_2.cm1_q_a,
            cm1_b_0: proof_2.cm1_b_0,
            cm1_q_b: proof_2.cm1_q_b,
            cm1_p: proof_2.cm1_p,
            b_0_gamma: proof_3.b_0_gamma,
            f_gamma: proof_3.f_gamma,
            a_0: proof_3.a_0,
            cm1_pi_eta: proof_3.cm1_pi_eta,
            cm1_a_0_x: proof_3.cm1_a_0_x,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::{Div, Mul, Sub};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
    use ark_poly::univariate::DensePolynomial;
    use crate::cq::Cq;
    use crate::prover::Prover;
    use crate::fiat_shamir::Script;
    use ark_ec::pairing::Pairing;
    use ark_ff::One;
    use sha2::Sha256;

    #[test]
    fn test_prover_initialization() {
        let f_i = vec![Fr::from(1), Fr::from(3), Fr::from(2), Fr::from(3)];
        let prover = Prover::<Sha256, Bls12_381>::new(f_i).unwrap();

        assert_eq!(prover.f_i.len(), 4);
        assert_eq!(prover.f_i_map.len(), 3);
        for (k, v) in prover.f_i_map {
            if k == Fr::from(1) {
                assert_eq!(v, 1);
            } else if k == Fr::from(2) {
                assert_eq!(v, 1);
            } else if k == Fr::from(3) {
                assert_eq!(v, 2);
            }
        }
    }

    #[test]
    fn test_round_1() {
        let t_i = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];
        let f_i = vec![Fr::from(1), Fr::from(3), Fr::from(3), Fr::from(3)];
        let cq = Cq::<Bls12_381>::new(&t_i).unwrap();
        let mut prover = Prover::<Sha256, Bls12_381>::new(f_i).unwrap();
        let proof = prover.prove(&cq, &t_i).unwrap();

        let m_i = vec![Fr::from(1), Fr::from(0), Fr::from(3), Fr::from(0)];
        let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();
        let m_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&m_i));
        let cm1_mx2 = cq.kzg.commit_g1(&m_x);

        assert_eq!(proof.cm1_m, cm1_mx2);
    }

    #[test]
    fn test_round_2() {
        let t_i = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)];
        let f_i = vec![Fr::from(1), Fr::from(3), Fr::from(3), Fr::from(3)];
        let cq = Cq::<Bls12_381>::new(&t_i).unwrap();
        let mut prover = Prover::<Sha256, Bls12_381>::new(f_i).unwrap();
        let proof = prover.prove(&cq, &t_i).unwrap();

        let m_i = vec![Fr::from(1), Fr::from(0), Fr::from(3), Fr::from(0)];

        let mut script = Script::<Sha256, Bls12_381>::new();
        script.feed_with_commitments(&[proof.cm1_f]);
        script.feed_with_commitments(&[proof.cm1_m]);
        let [beta] = script.generate_challenges();
        let mut vec_a = vec![];
        for (index, value) in m_i.iter().enumerate() {
            let v = (*value).div(t_i[index] + beta);
            vec_a.push(v);
        }
        let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();
        let a_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&vec_a));
        let z_v_x: DensePolynomial<Fr> = domain.vanishing_polynomial().into();
        let z_v_2 = cq.kzg.commit_g2(&z_v_x);
        let t_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&t_i));
        let t_x_2 = cq.kzg.commit_g2(&t_x);
        let m_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&m_i));
        let q_a_x = a_x.clone().mul(t_x + DensePolynomial::from_coefficients_vec(vec![beta])).sub(m_x).div(z_v_x);
        let m_x = DensePolynomial::from_coefficients_slice(&domain.ifft(&m_i));
        let cm_m = cq.kzg.commit_g1(&m_x);
        let cm = cq.kzg.commit_g1(&a_x);
        let cm2 = cq.kzg.commit_g1(&q_a_x);
        let cm2_1 = cq.kzg.commit_g2(&DensePolynomial::from_coefficients_vec(vec![Fr::one()]));

        assert_eq!(proof.cm1_a, cm);
        assert_eq!(proof.cm1_q_a, cm2);

        let lhs = Bls12_381::pairing(proof.cm1_a, t_x_2);
        let tmp = cm_m - cm.mul(beta);
        let rhs = Bls12_381::multi_pairing([proof.cm1_q_a, tmp.into()], [z_v_2, cm2_1]);
        assert_eq!(lhs, rhs);
    }
}