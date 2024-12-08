use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Cannot divide by vanishing polynomial.")]
    CannotDivideByVanishingPolynomial,
    
    #[error("The size of witness f must be power of 2")]
    WitnessSizeNotPowerOf2,

    #[error("Witness must be in the table")]
    WitnessNotInTable,
}

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("The size of table t must be power of 2")]
    TableSizeNotPowerOf2,
    #[error("The size of witness f must be power of 2")]
    WitnessSizeNotPowerOf2,
}

#[derive(Debug, Error)]
pub enum CqError {
    #[error("The size of table t must be power of 2")]
    TableSizeNotPowerOf2,
}

