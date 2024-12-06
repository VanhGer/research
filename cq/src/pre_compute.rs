use std::ops::Mul;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

// Compute the commitments of the Lagrange basis polynomials
// in O(NLogN) curve operations using FFT
// The algorithm in the section 3.3 of: https://eprint.iacr.org/2017/602.pdf
pub fn fast_lagrange_basis_commitments_computation<P: Pairing>(srs: &[P::G1Affine]) -> Vec<P::G1Affine>{
    let coefficients = &srs[0..].iter().map(|s| s.into_group()).collect::<Vec<_>>();
    let n = srs.len();
    let domain = GeneralEvaluationDomain::<P::ScalarField>::new(n).unwrap();
    
    let n_inv = domain.size_as_field_element().inverse().unwrap();
    
    let mut evals = domain.fft(&coefficients);
    // do reordering
    evals.reverse();
    
    let last = evals.pop().unwrap();
    let mut reordered_evals = vec![last];
    reordered_evals.extend(&evals);
    
    let lagrange_basis_commitments: Vec<P::G1> = reordered_evals.iter().map(|li| li.mul(n_inv)).collect();
    let lagrange_basis_commitment_affines = P::G1::normalize_batch(&lagrange_basis_commitments);
    lagrange_basis_commitment_affines
}

// compute [(l_i(X) - l_i(0)) / X]_1 = g^-i· [L_i(X)]_1 - (1/N)·[x^(N-1)]_1
pub fn compute_quotient_lagrange_basic_commitments<P: Pairing>(l_i_commitments: &[P::G1Affine], srs: &[P::G1Affine]) -> Vec<P::G1Affine> {
    let n = l_i_commitments.len();
    let domain = GeneralEvaluationDomain::<P::ScalarField>::new(n).unwrap();
    let n_inv = domain.size_as_field_element().inverse().unwrap();
    let sub = srs[n-1].mul(-n_inv);
    
    let mut res: Vec<P::G1Affine> = Vec::new();
    
    for (i, l_i_commitment) in l_i_commitments.iter().enumerate() {
        let mut quotient_com = l_i_commitment.mul(domain.element(n - i));
        res.push((quotient_com + sub).into());
    }
    
    res
    
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_poly::{DenseUVPolynomial, Evaluations};
    use ark_poly::univariate::DensePolynomial;
    use crate::kzg::Kzg;
    use super::*;

    #[test]
    fn test_fast_lagrange_basis_commitments_computation() {
        let kzg = Kzg::<Bls12_381>::new(8);
        let lagrange_basis_commitment_affines = fast_lagrange_basis_commitments_computation::<Bls12_381>(&kzg.g1_srs);

        let domain = GeneralEvaluationDomain::<Fr>::new(8).unwrap();

        let n = 8;
        let mut lagrange_basis_evals = vec![Fr::from(0); n];
        for i in 0..8 {
            lagrange_basis_evals[i] = Fr::from(1);
            let lagrange_basis_poly = Evaluations::from_vec_and_domain(lagrange_basis_evals.clone(), domain).interpolate();
            let largrange_basis_commitment = kzg.commit_g1(&lagrange_basis_poly);
            assert_eq!(lagrange_basis_commitment_affines[i], largrange_basis_commitment);
            lagrange_basis_evals[i] = Fr::from(0);
        }
    }
    
    #[test]
    fn test_quotient_lagrange_basis() {
        let kzg = Kzg::<Bls12_381>::new(8);
        let lagrange_basis_commitment_affines = fast_lagrange_basis_commitments_computation::<Bls12_381>(&kzg.g1_srs);
        let quotient_lagrange_basis_commitments = compute_quotient_lagrange_basic_commitments::<Bls12_381>(&lagrange_basis_commitment_affines, &kzg.g1_srs);
        
        let domain = GeneralEvaluationDomain::<Fr>::new(8).unwrap();
        let n = 8;
        let mut lagrange_basis_evals = vec![Fr::from(0); n];
        for i in 0..8 {
            lagrange_basis_evals[i] = Fr::from(1);
            let lagrange_basis_poly = Evaluations::from_vec_and_domain(lagrange_basis_evals.clone(), domain).interpolate();
            let l_0 = DensePolynomial::from_coefficients_vec(vec![lagrange_basis_evals[0]]);
            let quotient_poly = (lagrange_basis_poly - l_0) / DensePolynomial::from_coefficients_vec(vec![-Fr::from(0), Fr::from(1)]);
            let quotient_commitment = kzg.commit_g1(&quotient_poly);
            let quotient_lagrange_basis_commitment = quotient_lagrange_basis_commitments[i];
            assert_eq!(quotient_lagrange_basis_commitment, quotient_commitment);
            lagrange_basis_evals[i] = Fr::from(0);
        }
    }
}