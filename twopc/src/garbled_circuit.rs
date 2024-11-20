use rand::{thread_rng, CryptoRng, RngCore};
use crate::circuit::{get_number_of_inputs, Circuit, GateInfo, PartyInput};
use crate::circuit::Circuit::{Gate, Input};
use crate::decryption::{decrypt_to_password, garbled_gate_decryption};
use crate::encryption::{encrypt_password};
use crate::password::{party_input_passwords, Password, PasswordPair};

// Encrypted value for the output of the garbled gate.
#[derive(Default, Clone, Debug)]
pub struct EncryptedValue(pub Vec<u8>);

// Represents the rows of the lookup table.
#[derive(Default, Clone)]
pub struct Rows {
    pub value: EncryptedValue
}


// Garble any gate by turning it into a table
pub struct GarbledGate {
    pub table: [Rows; 4]
}

impl GarbledGate {
    pub fn new(
        gate_info: &GateInfo,
        left: &PasswordPair,
        right: &PasswordPair,
        output: &PasswordPair
    ) -> Self {

        let mut table = [Rows::default(), Rows::default(), Rows::default(), Rows::default()];
        let out = output.pair.clone();
        for i  in 0_u8..2 {
            for j in 0_u8..2 {
                let out_value = Self::get_value(gate_info, i, j);
                let mut out_pass = out[0].clone();
                if out_value == 1 {
                    out_pass = out[1].clone();
                }
                table[(i*2 + j) as usize] = Rows {value: encrypt_password(&left.pair[i as usize], &right.pair[j as usize], &out_pass)};
            }
        }
        Self {
            table
        }
    }

    // Get the value of bit
    fn get_bit(x: u8, bit: u8) -> u8{
        (x>>bit) & 1
    }

    // Get the output value of the gate from the gate info
    fn get_value(gate_info: &GateInfo, bit_left: u8, bit_right: u8) -> u8 {
        let bit = bit_left  * 2 + bit_right;
        Self::get_bit(gate_info.0, bit)
    }
}

// Represents the garbled circuit.
pub struct GarbledCircuit {
    pub tables: Vec<GarbledGate>,
    pub index: u32,
}

impl GarbledCircuit {
    pub fn new() -> Self {
        Self {
            tables: Vec::new(),
            index: 0,
        }
    }

    // Garble the circuit
    pub fn garble<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        circuit: &Circuit,
        passwords_a: &[PasswordPair],
        passwords_b: &[PasswordPair]
    ) -> PasswordPair {
       match circuit {
           Input(PartyInput::A(x)) => passwords_a[*x as usize].clone(),
           Input(PartyInput::B(x)) => passwords_b[*x as usize].clone(),

           Gate(gate_info, left, right) => {
               let left_password_pair = self.garble(rng, left, passwords_a, passwords_b);
               let right_password_pair = self.garble(rng, right, passwords_a, passwords_b);
               let out_password_pair = PasswordPair::new(rng);

               // add new garbled gate to the tables
               let garbled_gate = GarbledGate::new(gate_info, &left_password_pair, &right_password_pair, &out_password_pair);
               self.tables.push(garbled_gate);
               out_password_pair
           }

       }
    }

    pub fn ungarbled(&mut self, circuit: &Circuit, key_passwords_a: &[Password], key_passwords_b: &[Password]) -> Password {
        match circuit {
            Input(PartyInput::A(x)) => key_passwords_a[*x as usize].clone(),
            Input(PartyInput::B(x)) => key_passwords_b[*x as usize].clone(),
            Gate(_, left, right) => {
                let left_password = self.ungarbled(left, key_passwords_a, key_passwords_b);
                let right_password = self.ungarbled(right, key_passwords_a, key_passwords_b);

                let garbled_gate = self.tables.get(self.index as usize).unwrap();
                self.index += 1;
                garbled_gate_decryption(garbled_gate, &left_password, &right_password)
            }

        }
    }

    // Evaluate the garbled circuit  with the key passwords from parties.
    // Return a boolean value
    pub fn evaluate(&mut self, circuit: &Circuit, key_passwords_a: &[Password], key_passwords_b: &[Password]) -> bool{
        let final_password = self.ungarbled(&circuit, key_passwords_a, key_passwords_b);
        final_password.position == 1
    }
}

// Garble the circuit from the original circuit and parties inputs.
pub fn garble_circuit<R: RngCore + CryptoRng>(rng: &mut R, circuit: &Circuit)
-> (GarbledCircuit, Vec<PasswordPair>, Vec<PasswordPair>, PasswordPair){
    let mut garbled_circuit = GarbledCircuit::new();
    let (mut num_a, mut num_b) = get_number_of_inputs(circuit);
    num_a += 1;
    num_b += 1;
    let passwords_a = party_input_passwords(rng, num_a);
    let passwords_b = party_input_passwords(rng, num_b);

    let final_output = garbled_circuit.garble(rng, circuit, &passwords_a, &passwords_b);

    (garbled_circuit, passwords_a, passwords_b, final_output)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_garble_circuit() {
        let and_circuit = Gate(GateInfo(0b1000), Box::new(Input(PartyInput::A(0))), Box::new(Input(PartyInput::B(0))));
        let mut rng = thread_rng();
        let (garbled_circuit, passwords_a, passwords_b, final_password_pair) = garble_circuit(&mut rng, &and_circuit);
        assert_eq!(garbled_circuit.tables.len(), 1);
        let final_table = garbled_circuit.tables.get(0).unwrap().table.clone();

        let a0 = passwords_a.get(0).unwrap().pair[0].clone();
        let a1 = passwords_a.get(0).unwrap().pair[1].clone();
        let b0 = passwords_b.get(0).unwrap().pair[0].clone();
        let b1 = passwords_b.get(0).unwrap().pair[1].clone();

        // 0 & 0 = 0
        let encrypt_out0 = final_table[0].value.clone();
        let out0 = decrypt_to_password(&encrypt_out0, &a0, &b0);
        assert_eq!(out0, final_password_pair.pair[0]);

        // 0 & 1 = 0
        let encrypt_out0 = final_table[1].value.clone();
        let out0 = decrypt_to_password(&encrypt_out0, &a0, &b1);
        assert_eq!(out0, final_password_pair.pair[0]);

        // 1 & 0 = 0
        let encrypt_out0 = final_table[2].value.clone();
        let out0 = decrypt_to_password(&encrypt_out0, &a1, &b0);
        assert_eq!(out0, final_password_pair.pair[0]);

        // 1 & 1 = 1
        let encrypt_out1 = final_table[3].value.clone();
        let out1 = decrypt_to_password(&encrypt_out1, &a1, &b1);
        assert_eq!(out1, final_password_pair.pair[1]);
    }

    // Get passwords from each secret bit of parties.
    fn passwords_from_secret_values(
        passwords_a: Vec<PasswordPair>,
        passwords_b: Vec<PasswordPair>,
        values_a: Vec<u8>,
        values_b: Vec<u8>,
    ) -> (Vec<Password>, Vec<Password>) {
        let mut res_a = Vec::new();
        let mut res_b = Vec::new();
        for i in 0..values_a.len() {
            if values_a[i] == 0 {
                res_a.push(passwords_a[i].pair[0].clone());
            } else {
                res_a.push(passwords_a[i].pair[1].clone());
            }
        }

        for i in 0..values_b.len() {
            if values_b[i] == 0 {
                res_b.push(passwords_b[i].pair[0].clone());
            } else {
                res_b.push(passwords_b[i].pair[1].clone());
            }
        }

        (res_a, res_b)
    }
    #[test]
    pub fn test_evaluate_garbled_circuit() {
        let and_circuit = Gate(GateInfo(0b1000), Box::new(Input(PartyInput::A(0))), Box::new(Input(PartyInput::B(0))));
        let mut rng = thread_rng();
        let (mut garbled_circuit, passwords_a, passwords_b, _) = garble_circuit(&mut rng, &and_circuit);

        let a_value = vec![1_u8];
        let b_value = vec![0_u8];
        let (key_passwords_a, key_passwords_b) = passwords_from_secret_values(passwords_a, passwords_b, a_value, b_value);
        let res = garbled_circuit.evaluate(&and_circuit, &key_passwords_a, &key_passwords_b);
        assert_eq!(res, false);
    }

}