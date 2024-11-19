use ecies::SecretKey;
use rand::{CryptoRng, RngCore};

// Password $P_0$ or $P_1$ for each input.
pub struct Password {
    pass: SecretKey,
    position: u8,
}

// Pair of passwords for each input.
pub struct PasswordPair {
    p0: Password,
    p1: Password,
}

impl Password {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, position: u8) -> Self {
        let d = SecretKey::random(rng);
        Self {
            pass: d,
            position,
        }
    }
}

impl PasswordPair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let p0 = Password::new(rng, 0);
        let p1 = Password::new(rng, 1);
        Self { p0, p1 }
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









