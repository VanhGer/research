use ark_ec::{PrimeGroup};
use rand::{CryptoRng, RngCore};
use crate::core::errors::FieldError;
use crate::core::traits::{Field, Frost, Group};
use ark_secp256k1::{Fr, Projective};
use ark_ff::{One, PrimeField, UniformRand, Zero};

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Secp256k1Frost;

#[derive(Clone, Copy)]
pub struct Secp256k1Field;
#[derive(Clone, Copy)]
pub struct Secp256k1Group;

impl Field for Secp256k1Field{
    type Scalar = Fr;

    fn zero() -> Self::Scalar {
        Self::Scalar::zero()
    }

    fn one() -> Self::Scalar {
        Self::Scalar::one()
    }

    fn invert(number: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
        if *number == Self::Scalar::zero() {
            return Err(FieldError::CannotDivideByZero);
        }
        Ok(Self::Scalar::one())
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::rand(rng)
    }
}

impl Group for Secp256k1Group {
    type Field = Secp256k1Field;
    type Element = Projective;

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Self::Field::one()
    }

    fn identity() -> Self::Element {
        Self::Element::zero()
    }

    fn generator() -> Self::Element {
        Self::Element::generator()
    }
}

impl Frost for Secp256k1Frost {
    const CONTEXT_STR: &'static str = "Secp256k1";
    type Group = Secp256k1Group;

    type HashFunction = Sha256;

    fn hash_function_1(msg: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let nonce = b"rho";
        let mut new_msg = Vec::with_capacity(msg.len() + nonce.len());
        new_msg.extend_from_slice(msg);
        new_msg.extend_from_slice(nonce);
        <<Self::Group as Group>::Field as Field>::Scalar::from_be_bytes_mod_order(&new_msg)
    }

    fn hash_function_2(msg: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let nonce = b"cha";
        let mut new_msg = Vec::with_capacity(msg.len() + nonce.len());
        new_msg.extend_from_slice(msg);
        new_msg.extend_from_slice(nonce);
        <<Self::Group as Group>::Field as Field>::Scalar::from_be_bytes_mod_order(&new_msg)
    }
}

pub fn hash_to_bytes(inputs: &[u8]) -> [u8; 32] {
    let mut hash_func = Sha256::new();
    hash_func.update(inputs);
    let mut output = [0u8; 32];
    output.copy_from_slice(hash_func.finalize().as_slice());
    output
}