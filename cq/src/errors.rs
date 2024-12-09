use thiserror::Error;

#[derive(Debug, Error)]
pub enum GeneralError {
    #[error("Cannot divide by vanishing polynomial.")]
    CannotDivideByVanishingPolynomial,
    
    #[error("The size of witness f must be power of 2")]
    WitnessSizeNotPowerOf2,

    #[error("The size of table t must be power of 2")]
    TableSizeNotPowerOf2,
    
    #[error("Witness must be in the table")]
    WitnessNotInTable,

    #[error("Elements in t_i must be unique")]
    ElementsNotUnique,
}
