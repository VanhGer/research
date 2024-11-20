use ecies::{decrypt, SecretKey};
use crate::garbled_circuit::{EncryptedValue, GarbledGate};
use crate::password::Password;

// Decrypt the cipher text using secret key.
pub fn decrypt_with_sk(encrypted_value: &EncryptedValue, secret_key: &SecretKey) -> Password{
    let cipher_text = encrypted_value.0.clone();
    let sk = &secret_key.serialize();
    let plain_text = decrypt(sk, &cipher_text).unwrap();
    let password = Password::deserialize(<&[u8; 33]>::try_from(plain_text.as_slice()).unwrap());
    password
}

// Decrypt the Enc(P_out) using the secret key from P_left and P_right
pub fn decrypt_to_password(encrypted_value: &EncryptedValue, left: &Password, right: &Password) -> Password {
    let left_scalar = left.pass.serialize();
    let right_scalar = right.pass.serialize();
    let mut out_scalar = [0_u8; 32];

    for (i, (l_i, r_i)) in left_scalar.iter().zip(right_scalar.iter()).enumerate() {
        out_scalar[i] = l_i ^ r_i;
    }
    let secret_key = SecretKey::parse_slice(&out_scalar).unwrap();
    decrypt_with_sk(encrypted_value, &secret_key)
}

// Find and decrypt the Enc(P_out) from the table, using P_left and P_right
pub fn garbled_gate_decryption(garbled_gate: &GarbledGate, left: &Password, right: &Password) -> Password {
    let pos = left.position * 2 + right.position;
    let encrypted_value = garbled_gate.table.get(pos as usize).unwrap().value.clone();
    decrypt_to_password(&encrypted_value, left, right)
}