use std::fmt::Debug;
use std::ops::{Add, Mul, Sub};
use ark_ff::{LegendreSymbol, SqrtPrecomputation};
use rand::{CryptoRng, RngCore};
use crate::core::errors::FieldError;

pub trait Field: Copy + Clone {
    type Scalar: Add<Output = Self::Scalar>
    + Mul<Output = Self::Scalar>
    + Sub<Output = Self::Scalar>
    + Eq + PartialEq + Copy + Clone;

    /// The additive identity
    fn zero() -> Self::Scalar;

    /// The multiplicative identity
    fn one() -> Self::Scalar;

    /// The inversion
    fn invert(number: &Self::Scalar) -> Result<Self::Scalar, FieldError>;

    /// Random function
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;
}

pub trait Group: Copy + Clone {
    type Field: Field;
    type Element: Add<Output = Self::Element>
    + Mul<<Self::Field as Field>::Scalar, Output = Self::Element>
    + Sub<Output = Self::Element>
    + Eq + PartialEq + Clone + Copy;


    /// If using a prime order elliptic curve, the cofactor should be 1 in the scalar field.
    fn cofactor() -> <Self::Field as Field>::Scalar;

    /// Additive identity of the prime order group
    fn identity() -> Self::Element;

    /// The generator of the prime order group
    fn generator() -> Self::Element;
}

pub trait Frost: Copy + Clone + PartialEq + Debug + 'static {
    const CONTEXT_STR: &'static str;
    type Group: Group;
    type HashFunction;

    fn hash_function_1(msg: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar;

    fn hash_function_2(msg: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar;


}