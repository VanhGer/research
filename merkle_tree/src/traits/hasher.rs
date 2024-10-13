use digest::Digest;
pub trait Hasher<F: > {
    type Digest: Digest;
    fn hash(bytes: &[u8]) -> Self::Digest;

    fn hash_two_digests(digests: &[Self::Digest; 2]) -> Self::Digest;
}