use digest::Digest;
use ark_ff::PrimeField;
use crate::errors::MerkleError;
use crate::traits::proof::{MerkleProof, MerkleView};

pub trait MerkleTree {
    type Root: Digest;
    type Node: Digest;
    type Proof: MerkleProof;
    type Leaf: PrimeField;

    fn prove(&self, indices: &[usize]) -> Result<Self::Proof, MerkleError>;

    fn verify(&self, proof: Self::Proof) -> Result<(),MerkleError>;

    fn get_root(&self) -> Self::Root;

    fn get_leaf(&self, index: usize) -> Result<Self::Leaf, MerkleError>;

    fn get_node(&self, index: usize) -> Result<Self::Node, MerkleError>;

    fn get_height(&self) -> usize;

    fn build_tree(leaves: &[Self::Leaf]) -> Self;
}

pub struct MerkleTreeImpl<F: PrimeField, D: Digest> {
    pub leaves: Vec<F>,
    pub nodes: Vec<D>,
}

impl <F: PrimeField, D: Digest> MerkleTree for MerkleTreeImpl<F, D> {
    type Root = D;
    type Node = D;
    type Proof = MerkleView<F, D>;
    type Leaf = F;

    fn prove(&self, indices: &[usize]) -> Result<Self::Proof, MerkleError> {
        todo!()
    }

    fn verify(&self, proof: Self::Proof) -> Result<(), MerkleError> {
        todo!()
    }

    fn get_root(&self) -> Self::Root {
        self.nodes.last().clone();
    }

    fn get_leaf(&self, index: usize) -> Result<Self::Leaf, MerkleError> {
        if index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfRange);
        }
        Ok(self.leaves[index])
    }

    fn get_node(&self, index: usize) -> Result<Self::Node, MerkleError> {
        if index >= self.nodes.len() {
            return Err(MerkleError::IndexOutOfRange);
        }
        Ok(self.nodes[index].clone())
    }

    fn get_height(&self) -> usize {
        (self.leaves.len() as f32).log2().ceil() as usize
    }

    fn build_tree(leaves: &[Self::Leaf]) -> Self {
        todo!()
    }
}
