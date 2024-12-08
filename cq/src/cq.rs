use std::collections::HashMap;
use std::ops::{Mul, Sub};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_poly::univariate::DensePolynomial;
use crate::errors::CqError;
use crate::feist_khovratovich_alg::ToeplitzMatrix;
use crate::kzg::Kzg;
use crate::pre_compute::{compute_quotient_lagrange_basic_commitments, fast_lagrange_basis_commitments_computation};

pub struct Cq<P: Pairing> {
    pub kzg: Kzg<P>,
    pub big_n: usize,
    pub z_v_2: P::G2Affine,
    pub t_hash_map: HashMap<P::ScalarField, usize>,
    pub t_x_2: P::G2Affine,
    pub cm1_qi: Vec<P::G1Affine>,
    pub cm1_li: Vec<P::G1Affine>,
    pub cm1_l_i_quotient: Vec<P::G1Affine>,
}

impl <P: Pairing> Cq<P> {
    pub fn new(t_i: &[P::ScalarField]) -> Result<Self, CqError> {
        let big_n = t_i.len();
        if !big_n.is_power_of_two() {
            return Err(CqError::TableSizeNotPowerOf2);
        }
        
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(big_n).unwrap();
        let kzg = Kzg::<P>::new(big_n);
        
        let z_v_2: P::G2Affine = kzg.g2_srs[big_n].sub(kzg.g2_srs[0]).into();
        
        let mut t_hash_map = HashMap::<P::ScalarField, usize>::new();
        for (i, x) in t_i.iter().enumerate() {
            t_hash_map.insert(*x, i);
        }
        
        let t_x_coeffs = domain.ifft(t_i);
        let t_x = DensePolynomial::from_coefficients_vec(t_x_coeffs);
        let t_x_2 = kzg.commit_g2(&t_x);

        let cm1_qi = Self::compute_cm1_qi(&domain, &t_x, &kzg.g1_srs);

        let cm1_li = fast_lagrange_basis_commitments_computation::<P>(&kzg.g1_srs, big_n);

        let cm1_l_i_quotient = compute_quotient_lagrange_basic_commitments::<P>(&cm1_li, &kzg.g1_srs, big_n);

        Ok(Self {
            kzg,
            big_n,
            z_v_2,
            t_hash_map,
            t_x_2,
            cm1_qi,
            cm1_li,
            cm1_l_i_quotient,
        })
    }

    fn compute_cm1_qi(domain: &GeneralEvaluationDomain<P::ScalarField>, t_x: &DensePolynomial<P::ScalarField>, srs_g1: &[P::G1Affine]) -> Vec<P::G1Affine> {
        let big_n_inv = domain.size_as_field_element().inverse().unwrap();
        let toeplitz = ToeplitzMatrix::<P>::new(t_x);
        let hs: Vec<P::G1> = toeplitz.compute_h_coefficients(srs_g1);
        
        // assert_eq!(hs.len(), 2 * domain.size());
        let ks = domain.fft(&hs[..domain.size()]);

        let res: Vec<P::G1Affine> = ks.iter().zip(domain.elements()).map(|(k_s_i, g_i)| {
            k_s_i.mul(g_i * big_n_inv).into()
        }).collect();

        // let res = P::G1::normalize_batch(&tmp);
        res
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use crate::cq::Cq;

    #[test]
    fn test_cq() {
        let t_i = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4), Fr::from(5), Fr::from(6), Fr::from(7), Fr::from(8)];
        let cq = Cq::<Bls12_381>::new(&t_i).unwrap();
        let domain = GeneralEvaluationDomain::<Fr>::new(cq.big_n).unwrap();
        let vanish_poly = domain.vanishing_polynomial();

        let cm2_vanish  = cq.kzg.commit_g2(&vanish_poly.into());
        assert_eq!(cm2_vanish, cq.z_v_2);
        assert_eq!(cq.big_n, 8);
        assert_eq!(cq.t_hash_map.len(), t_i.len());
    }
}