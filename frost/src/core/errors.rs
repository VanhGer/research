use thiserror::Error;

#[derive(Error, Debug)]
pub enum FieldError {
    #[error("Divide by zero")]
    CannotDivideByZero,
}