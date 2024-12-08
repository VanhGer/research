use std::ops::{Mul, Sub};
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_poly::univariate::DensePolynomial;
use crate::feist_khovratovich_alg::ToeplitzMatrix;
use crate::kzg::Kzg;
use crate::pre_compute::{compute_quotient_lagrange_basic_commitments, fast_lagrange_basis_commitments_computation};

pub struct Cq<P: Pairing> {
    kzg: Kzg<P>,
    big_n: usize,
    z_v_2: P::G2Affine,
    t_x: DensePolynomial<P::ScalarField>,
    t_x_2: P::G2Affine,
    q_i_1: Vec<P::G1Affine>,
    l_i_1: Vec<P::G1Affine>,
    l_i_quotient_1: Vec<P::G1Affine>,
}

impl <P: Pairing> Cq<P> {
    pub fn new(t_i: &[P::ScalarField]) -> Self {

        let big_n = t_i.len();
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(big_n).unwrap();

        let kzg = Kzg::<P>::new(big_n);

        let z_v_2: P::G2Affine = kzg.g2_srs[big_n].sub(kzg.g2_srs[0]).into();

        let t_x_coeffs = domain.ifft(t_i);
        let t_x = DensePolynomial::from_coefficients_vec(t_x_coeffs);
        let t_x_2 = kzg.commit_g2(&t_x);

        let q_i_1 = Self::compute_q_i_1(&domain, &t_x, &kzg.g1_srs);

        let l_i_1 = fast_lagrange_basis_commitments_computation::<P>(&kzg.g1_srs, big_n);

        let l_i_quotient_1 = compute_quotient_lagrange_basic_commitments::<P>(&l_i_1, &kzg.g1_srs, big_n);

        Self {
            kzg,
            big_n,
            z_v_2,
            t_x,
            t_x_2,
            q_i_1,
            l_i_1,
            l_i_quotient_1,
        }
    }

    fn compute_q_i_1(domain: &GeneralEvaluationDomain<P::ScalarField>, t_x: &DensePolynomial<P::ScalarField>, srs_g1: &[P::G1Affine]) -> Vec<P::G1Affine> {
        let big_n_inv = domain.size_as_field_element().inverse().unwrap();
        let toeplitz = ToeplitzMatrix::<P>::new(t_x);
        let hs: Vec<P::G1> = toeplitz.compute_h_coefficients(srs_g1);

        let ks = domain.fft(&hs[..domain.size()]);

        let tmp: Vec<P::G1> = ks.iter().zip(domain.elements()).map(|(k_s_i, g_i)| {
            k_s_i.mul(g_i * big_n_inv)
        }).collect();

        let res = P::G1::normalize_batch(&tmp);
        res
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use crate::cq::Cq;

    #[test]
    fn test_cq() {
        let t_i = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4), Fr::from(5), Fr::from(6), Fr::from(7), Fr::from(8)];
        let cq = Cq::<Bls12_381>::new(&t_i);

        assert_eq!(cq.big_n, 8);
    }
}