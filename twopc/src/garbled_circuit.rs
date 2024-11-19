use ecies::SecretKey;
use rand::{CryptoRng, RngCore};
use crate::circuit::{get_number_of_inputs, Circuit};
use crate::password::{party_input_passwords, PasswordPair};

// Encrypted value for the output of the garbled gate.
pub struct EncryptedValue(pub Vec<u8>);

// Represents the rows of the lookup table.
pub struct Rows {
    pub col1: SecretKey,
    pub col2: SecretKey,
    pub col3: EncryptedValue
}

// Represents the garbled circuit.
pub struct GarbledCircuit {
    pub tables: Vec<[Rows; 4]>,
    pub encrypted_outputs: (EncryptedValue, EncryptedValue)
}

impl GarbledCircuit {
    pub fn new<R: RngCore + CryptoRng>(circuit: &Circuit, rng: &mut R) -> Self {

        let (num_a, num_b) = get_number_of_inputs(circuit);
        let password_a = party_input_passwords(rng, num_a);
        let password_b = party_input_passwords(rng, num_b);

        let garbler = garble_circuit(rng, circuit, &password_a, &password_b);

        Self {
            tables: Vec::new(),
            encrypted_outputs: (EncryptedValue(Vec::new()), EncryptedValue(Vec::new()))
        }
    }
}

// Garble the circuit from the original circuit and parties inputs.
pub fn garble_circuit<R: RngCore + CryptoRng>(rng: &mut R, circuit: &Circuit, password_a: &[PasswordPair], password_b: &[PasswordPair]) {
     // TODO: Implement this function
}