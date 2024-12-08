// Generates Fiat-Shamir challenges for the KZG scheme.

use std::marker::PhantomData;
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_serialize::{CanonicalSerialize, Write};
use ark_std::rand::rngs::StdRng;
use ark_std::UniformRand;
use rand::SeedableRng;
use sha2::Digest;

pub struct Script<T: Digest + Default, P: Pairing> {
    data: Option<Vec<u8>>,
    generated: bool,
    _phantom_data_t: PhantomData<T>,
    _phantom_data_p: PhantomData<P>,
}

impl <T: Digest + Default, P: Pairing> Script<T, P> {
    pub fn new() -> Self {
        Self {
            data: None,
            generated: false,
            _phantom_data_t: PhantomData,
            _phantom_data_p: PhantomData,
        }
    }

    
    pub fn feed_with_commitments(&mut self, commitments: &[impl CanonicalSerialize]) {
        let mut hasher = T::default();
        hasher.update(self.data.take().unwrap_or_default());
        for commitment in commitments {
            commitment.serialize_uncompressed(HashMarshaller(&mut hasher))
                .expect("HashMarshaller::serialize_uncompressed should be infallible!");
        }
        self.data = Some(hasher.finalize().to_vec());
        self.generated = false;
    }

    fn generate_rng_with_seed(&mut self) -> StdRng {
        if self.generated {
            panic!("I'm hungry! Feed me something first");
        }
        self.generated = true;
        let seed = self
            .data
            .clone()
            .map(|data| u64::from_le_bytes(data[..8].try_into().unwrap()))
            .expect("No data to generate seed from");
        StdRng::seed_from_u64(seed)
    }

    pub fn generate_challenges<const N: usize>(&mut self) -> [P::ScalarField; N] {
        let mut rng = self.generate_rng_with_seed();
        let mut points = [P::ScalarField::zero(); N];
        for point in &mut points {
            *point = P::ScalarField::rand(&mut rng);
        }
        points
    }


}

// This private struct works around Serialize taking the pre-existing
// std::io::Write instance of most digest::Digest implementations by value
struct HashMarshaller<'a, H: Digest>(&'a mut H);

impl<'a, H: Digest> Write for HashMarshaller<'a, H> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> ark_std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> ark_std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr, CurveGroup};
    use sha2::Sha256;
    use std::ops::Mul;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use crate::fiat_shamir::Script;

    #[test]
    fn aggregation_digest_test() {
        let commitment1 =  G1Affine::generator().mul(Fr::from(1)).into_affine();
        let commitment2 =  G1Affine::generator().mul(Fr::from(2)).into_affine();
      
        let commitments= [commitment1.clone(), commitment2.clone()];
        let mut script1 = Script::<Sha256, Bls12_381>::new();
        let mut script2 = Script::<Sha256, Bls12_381>::new();
        let mut script3 = Script::<Sha256, Bls12_381>::new();
        let mut script4 = Script::<Sha256, Bls12_381>::new();
        
        
        script1.feed_with_commitments(&commitments);
        let [a, aa, aaa] = script1.generate_challenges();

        let commitments1 = [commitment1.clone()];
        let commitments2 = [commitment2.clone()];
        script2.feed_with_commitments(&commitments2);
        let [b] =  script2.generate_challenges();
        println!("b: {:?}", b);
        assert_ne!(a, b, "should be different");

        script3.feed_with_commitments(&commitments);
        let [c, cc, ccc] = script3.generate_challenges();
        assert_eq!(a, c, "should be equal");
        assert_eq!(aa, cc, "should be equal");
        assert_eq!(aaa, ccc, "should be equal");
        
        script4.feed_with_commitments(&commitments1);
        script4.feed_with_commitments(&commitments2);
        let [d, dd, ddd] = script4.generate_challenges();
        assert_ne!(a, d, "should be different");
        assert_ne!(aa, dd, "should be different");
        assert_ne!(aaa, ddd, "should be different");
    }

    #[test]
    #[should_panic]
    fn safe_guard() {
        let commitment1 = G1Affine::generator().mul(Fr::from(1)).into_affine();
        let mut script1 = Script::<Sha256, Bls12_381>::new();
        script1.feed_with_commitments(&[commitment1]);
        let [_a, _aa, _aaa] = script1.generate_challenges();
        let [_a, _aa, _aaa] = script1.generate_challenges();
    }
}
