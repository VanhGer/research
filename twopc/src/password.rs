use ecies::SecretKey;
use rand::{CryptoRng, RngCore};
// Password $P_0$ or $P_1$ for each input.
#[derive(Clone, Debug, PartialEq)]
pub struct Password {
    pub pass: SecretKey,
    pub position: u8,
}

// Pair of passwords for each input.
#[derive(Clone)]
pub struct PasswordPair {
    pub pair: [Password; 2]
}

impl Password {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, position: u8) -> Self {
        let d = SecretKey::random(rng);
        Self {
            pass: d,
            position,
        }
    }

    pub fn serialize(&self) -> [u8;33] {
        let mut res = [0_u8;33];
        let sk_serialize = self.pass.serialize();
        res[1..33].copy_from_slice(&sk_serialize);
        res[0] = self.position;
        res
    }

    pub fn deserialize(bytes: &[u8;33]) -> Self {
        let pass = SecretKey::parse(<&[u8; 32]>::try_from(&bytes[1..33]).unwrap()).expect("Failed to deserialize SecretKey");
        let position = bytes[0];
        Self { pass, position }
    }
}

impl PasswordPair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let p0 = Password::new(rng, 0);
        let p1 = Password::new(rng, 1);
        Self {
            pair: [p0, p1]
        }
    }
}

// Generate a list of passwords for each party
pub fn party_input_passwords<R: RngCore + CryptoRng>(rng: &mut R, num_inputs: u32) -> Vec<PasswordPair> {
    let mut passwords = Vec::new();
    for _ in 0..num_inputs {
        passwords.push(PasswordPair::new(rng));
    }
    passwords
}









