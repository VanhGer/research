use rand::thread_rng;
use twopc::circuit::Circuit::{Gate, Input};
use twopc::circuit::{GateInfo, PartyInput};
use twopc::garbled_circuit::garble_circuit;
use twopc::ot::{ot_encryption_passwords, NKeysList};
use twopc::password::{Password, PasswordPair};

fn get_key_passwords(
    passwords_a: &[PasswordPair],
    values_a: &[u8]
) -> Vec<Password> {
    let mut res_a = Vec::new();
    for i in 0..values_a.len() {
        if values_a[i] == 0 {
            res_a.push(passwords_a[i].pair[0].clone());
        } else {
            res_a.push(passwords_a[i].pair[1].clone());
        }
    }
    res_a
}

fn main() {
    // we design a circuit that: x AND y - 4 = 0, where x and y are 4-bit numbers
    // from Alice and Bob

    println!("2-pc validate equation: x AND y - 4 = 0");
    let circuit =
        Gate(
            GateInfo(0b1000),
            Box::new(Gate(
                GateInfo(0b0010),
                Box::new(Gate(
                    GateInfo(0b1000),
                    Box::new(Input(PartyInput::A(0))),
                    Box::new(Input(PartyInput::B(0)))
                )),
                Box::new(Gate(
                    GateInfo(0b1000),
                    Box::new(Input(PartyInput::A(1))),
                    Box::new(Input(PartyInput::B(1)))
                ))
            )),

            Box::new(Gate(
                GateInfo(0b0001),
                Box::new(Gate(
                    GateInfo(0b1000),
                    Box::new(Input(PartyInput::A(2))),
                    Box::new(Input(PartyInput::B(2)))
                )),
                Box::new(Gate(
                    GateInfo(0b1000),
                    Box::new(Input(PartyInput::A(3))),
                    Box::new(Input(PartyInput::B(3)))
                ))
            )),

        );

    let mut rng = thread_rng();

    // Alice garbles circuit with the passwords for each input of Alice and Bob

    println!("Garble circuit...");
    let (mut garbled_circuit, passwords_a, passwords_b, _) = garble_circuit(&mut rng, &circuit);

    println!("x = 12, y = 7");
    // x = 12, y = 7
    let a_value = vec![1_u8, 1, 0, 0];
    let b_value = vec![0_u8, 1, 1, 1];

    // Alice chooses her key passwords from her input
    let key_passwords_a = get_key_passwords(&passwords_a, &a_value);

    // Bob generates public keys
    let nkey_list = NKeysList::new(&b_value);

    // Bob sends public keys for Alice, and Alice encrypts passwords with these keys
    let encryption_passwords = ot_encryption_passwords(&passwords_b, &nkey_list.nkeys).unwrap();

    // Bob encrypts all needed passwords
    let key_passwords_b = nkey_list.decrypt(encryption_passwords).unwrap();

    let res = garbled_circuit.evaluate(&circuit, &key_passwords_a, &key_passwords_b);
    if res {
        println!("equal");
    } else {
        println!("not equal")
    }

}