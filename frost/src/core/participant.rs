use ark_poly::univariate::DensePolynomial;
use ark_secp256k1::Fr;
use crate::core::traits::{Field, Group};

pub struct Participant <G: Group, F: Field>{
    f_i: DensePolynomial<F::Scalar>,
    pub commitments: Vec<G::Element>,
    random_k: <G::Field as Field>::Scalar,
}

// impl <G: Group, F: Field>Participant<G, F> {
//     pub fn vjp(&self) {
//         let d = self.f_i.
//     }
// }