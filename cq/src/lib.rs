pub mod kzg;
pub mod feist_khovratovich_alg;
mod pre_compute;
mod cq;
mod prover;
mod fiat_shamir;
mod errors;
mod verifier;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
