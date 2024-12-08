use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Cannot divide by vanishing polynomial.")]
    CannotDivideByVanishingPolynomial,
    
    
}