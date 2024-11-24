use thiserror::Error;
use rrsa_lib::error::RsaError;

#[derive(Debug, Error)]
pub enum OTError{
    #[error("The response encrypted passwords is insufficient to choose.")]
    InsufficientEncryptedPassword,

    #[error("Decryption passwords failed in OT.")]
    DecryptionFailed(RsaError),

    #[error("Encryption passwords failed in OT.")]
    EncryptionFailed(RsaError),

    #[error("The length of each gate maximum output is not matching.")]
    LengthNotMatch,

    #[error("n public key sent by a party is invalid")]
    InvalidNKeys,
}