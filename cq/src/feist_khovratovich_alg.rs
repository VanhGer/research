// This algorithm is mentioned here: https://eprint.iacr.org/2023/033.pdf
use std::ops::Mul;
use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use ark_poly::univariate::DensePolynomial;
use ark_ff::Zero;
pub struct ToeplitzMatrix <P: Pairing> {
    vec_f: Vec<P::ScalarField>,
}

impl<P: Pairing> ToeplitzMatrix<P> {
    pub fn new(dense_polynomial: &DensePolynomial<P::ScalarField>) -> Self {
        let coeffs = dense_polynomial.coeffs().to_vec();
        let mut res = coeffs[1..].to_vec();
        let len = res.len();
        let pow2_len = len.next_power_of_two();
        res.extend(vec![P::ScalarField::zero(); pow2_len - len]);
        Self {
            vec_f: res
        }
    }

    pub fn compute_h_coefficients(&self, g1_points: &[P::G1Affine]) -> Vec<P::G1>{
        let f_degree = self.vec_f.len();
        let domain: GeneralEvaluationDomain<P::ScalarField> = GeneralEvaluationDomain::new(2 * f_degree).unwrap();
        // compute ^s.
        let mut hat_s: Vec<P::G1> = g1_points[0..].iter().map(|p| {
            p.into_group()
        }).collect();
        hat_s.reverse();
        hat_s.extend(vec![P::G1::zero(); f_degree]);
        // y = FFT(^s)
        let mut y = domain.fft(&hat_s);

        // compute ^c
        let mut hat_c = vec![P::ScalarField::zero(); f_degree + 1];
        // the vec_f.last element is zero, and it is not actual the coefficient value.
        hat_c.extend_from_slice(&self.vec_f[..f_degree-1]);

        // V = FFT(^C)
        let v = domain.fft(&hat_c);

        // U = y ◦ v
        for (i, _) in hat_c.iter().enumerate() {
            y[i] = y[i].mul(v[i]);
        }

        // ^h = iFFT(U)
        domain.ifft(&y)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::One;
    use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
    use ark_poly::univariate::DensePolynomial;
    use crate::feist_khovratovich_alg::ToeplitzMatrix;
    use crate::kzg::Kzg;

    #[test]
    pub fn test_compute_h_coeffs() {
        let kzg = Kzg::<Bls12_381>::new(4);
        let poly = DensePolynomial::from_coefficients_slice(&[Fr::one(), Fr::one(), Fr::one(), Fr::one()]);

        let toeplitz = ToeplitzMatrix::<Bls12_381>::new(&poly);
        let hs = toeplitz.compute_h_coefficients(&kzg.g1_srs);

        let domain = GeneralEvaluationDomain::<Fr>::new(4).unwrap();
        let openings_1 = domain.fft(&hs[..4]);


        let openings_2: Vec<_> = domain
            .elements()
            .map(|omega_pow_i| kzg.open_g1(&poly, omega_pow_i).0)
            .collect();

        assert_eq!(openings_1, openings_2);

    }
}