use std::ops::{Add, Sub};
use ark_ec::CurveGroup;
use std::ops::Mul;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{UniformRand, Zero, One};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_poly::univariate::DensePolynomial;
use rand::thread_rng;

pub struct Kzg<P: Pairing> {
    pub g1_srs: Vec<P::G1Affine>,
    pub g2_srs: Vec<P::G2Affine>,
}

impl <P: Pairing> Kzg<P> {

    // Generate SRS
    pub fn new(len: usize) -> Self {
        let s = P::ScalarField::rand(&mut thread_rng());
        Self::new_from_secret(s, len)
    }
    
    pub fn new_from_secret(s: P::ScalarField, len: usize) -> Self {
        let g1_gen = P::G1Affine::generator();
        let g2_gen = P::G2Affine::generator();

        let mut g1_srs = Vec::new();
        let mut g2_srs = Vec::new();

        let mut s_pow = P::ScalarField::one();
        for i in 0..len {
            let g1_point = g1_gen.mul(s_pow);
            let g2_point = g2_gen.mul(s_pow);
            g1_srs.push(g1_point.into());
            g2_srs.push(g2_point.into());
            s_pow = s_pow * s;
        }

        Self {
            g1_srs,
            g2_srs
        }
    }
    
    // Commit a polynomial with SRS in G1
    pub fn commit_g1(&self, dense_polynomial: &DensePolynomial<P::ScalarField>) -> P::G1Affine {
        assert!(self.g1_srs.len() > dense_polynomial.degree());
        let poly_coeffs = dense_polynomial.coeffs.iter();
        let g1_points = self.g1_srs.iter();
        let res = poly_coeffs.zip(g1_points).map(|(coeff, point)| {
            point.mul(coeff).into()
        }).reduce(|acc, point| acc.add(point).into()).unwrap_or(P::G1Affine::zero());
        res
    }

    // Commit a polynomial with SRS in G2
    pub fn commit_g2(&self, dense_polynomial: &DensePolynomial<P::ScalarField>) -> P::G2Affine {
        assert!(self.g2_srs.len() > dense_polynomial.degree());
        let poly_coeffs = dense_polynomial.coeffs.iter();
        let g2_points = self.g2_srs.iter();
        let res = poly_coeffs.zip(g2_points).map(|(coeff, point)| {
            point.mul(coeff).into()
        }).reduce(|acc, point| acc.add(point).into()).unwrap_or(P::G2Affine::zero());
        res
    }

    // Open a polynomial at a point z
    pub fn open_g1(&self, f_x: &DensePolynomial<P::ScalarField>, z: P::ScalarField) -> (P::G1Affine, P::ScalarField) {
        let f_z = f_x.evaluate(&z);
        let f_z_poly = DensePolynomial::from_coefficients_slice(&vec![f_z]);
        let x_minus_z_poly = DensePolynomial::from_coefficients_slice(&vec![-z, 1.into()]);
        let f_q = (f_x - f_z_poly) / x_minus_z_poly;
        let opening = self.commit_g1(&f_q);
        (opening, f_z)
    }

    // Verify the opening
    pub fn verify(&self, commitment: P::G1Affine, opening: P::G1Affine, z: P::ScalarField, f_z: P::ScalarField) -> bool {
        let x_minus_z_g2 = self.g2_srs[1].sub(self.g2_srs[0].mul(z).into()).into();
        let f_z_g1 = self.g1_srs[0].mul(f_z).into();

        let left_side = P::pairing(opening, x_minus_z_g2);
        let right_side = P::pairing(commitment.sub(f_z_g1).into(), self.g2_srs[0]);
        left_side == right_side
    }


}

#[cfg(test)]
mod tests {
    use ark_poly::DenseUVPolynomial;
    use ark_poly::univariate::DensePolynomial;
    use crate::kzg::Kzg;
    use ark_bls12_381::{Fr, Bls12_381};
    use ark_ff::One;

    #[test]
    pub fn test_kzg_commitment() {
        let kzg = Kzg::<Bls12_381>::new(10);
        let poly = DensePolynomial::from_coefficients_slice(&[Fr::one(), Fr::one(), Fr::one()]);
        let commitment = kzg.commit_g1(&poly);
        let challenge = Fr::from(5);
        let (opening, f_z) = kzg.open_g1(&poly, challenge);

        assert!(kzg.verify(commitment, opening, challenge, f_z));
    }
}