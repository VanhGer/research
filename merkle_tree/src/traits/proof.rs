use ark_ff::PrimeField;
use digest::Digest;

pub trait MerkleProof {}

/// Merkle View contains information needed to verify multiple Merkle paths.
///
/// Inspired by Starkware's Solidity verifier
/// <https://etherscan.io/address/0xe9664D230490d5A515ef7Ef30033d8075a8D0E24#code#F24#L1>
pub struct MerkleView<F: PrimeField, D: Digest> {
    pub indices: Vec<usize>,
    pub queues: Vec<F>,
    pub nodes: Vec<D>,
    pub height: usize,
}

impl <F: PrimeField, D: Digest> MerkleProof for MerkleView<F, D> {}