// Oblivious Transfer

use std::io::Cursor;
use num_bigint::BigUint;
use rrsa_lib::key::{Key, KeyPair};
use crate::error::OTError;
use crate::error::OTError::{DecryptionFailed, EncryptionFailed, InsufficientEncryptedPassword, LengthNotMatch};
use crate::garbled_circuit::EncryptedValue;
use crate::password::{Password, PasswordPair};

// R = Random number which is agreed by both parties.
const R: u128 = 10;
const N: u32 = 2;

// N public keys generated by Bob in One-step-OT protocol
pub struct NKey(pub [Key; N as usize]);


// Provides a collection of elements, where each element contains a list of N public keys.
// For each list, only one public key has an associated private key.
// The private key and its position in the list are provided for the corresponding public key
pub struct NKeysList {
    pub nkeys: Vec<NKey>,
    pub positions: Vec<u8>,
    pub private_keys: Vec<Key>
}


impl NKeysList {
    // This function create lists of n public keys. Each (n public keys) list presents for a secret input.
    pub fn new(secret_value: &[u8]) -> Self {
        let mut positions = Vec::new();
        let mut private_keys = Vec::new();
        let mut nkey_list = Vec::new();
        let diff = BigUint::from(R);
        let dummy_key_pair = KeyPair::generate(Some(32), true, true, true);
        let mut nkey = vec![dummy_key_pair.public_key.clone(); N as usize];

        for i in 0..secret_value.len() {
            // generate the original priv-pub key pair.
            let key_pair = KeyPair::generate(Some(512), true, true, true);
            let pub_key = key_pair.public_key;
            let priv_key = key_pair.private_key;
            positions.push(secret_value[i]);
            private_keys.push(priv_key.clone());
            nkey[secret_value[i] as usize] = pub_key.clone();

            // create N-1 public keys from the original public key
            // each byte of new public key can be computed by:
            // $ new_pk[j]_n = pk[j]_n - (i - j) * R $
            // $ new_pk[j]_e = pk[j]_e - (i - j) * R $


            for j in 0..secret_value[i] {
                let mut new_pk = pub_key.clone();
                new_pk.modulus -= BigUint::from(secret_value[i] - j) * diff.clone();
                new_pk.exponent -= BigUint::from(secret_value[i] - j) * diff.clone();

                nkey[j as usize] = new_pk;
            }

            for j in (secret_value[i] + 1) ..N as u8{
                let mut new_pk = pub_key.clone();
                new_pk.modulus += BigUint::from(j - secret_value[i]) * diff.clone();
                new_pk.exponent += BigUint::from(j - secret_value[i]) * diff.clone();

                nkey[j as usize] = new_pk;
            }
            nkey_list.push(NKey(nkey.clone().try_into().expect("Failed to convert Vec<Key> to [Key; N as usize]")));
        }

        Self {
            nkeys: nkey_list,
            positions,
            private_keys
        }
    }

    // Decrypts the encrypted passwords from a party
    pub fn decrypt(&self, encrypted_value_list: Vec<[EncryptedValue; N as usize]>) -> Result<Vec<Password>, OTError>{
        if encrypted_value_list.len() != self.private_keys.len() {
            return Err(InsufficientEncryptedPassword);
        }

        let mut res = Vec::new();

        for (i, item) in encrypted_value_list.iter().enumerate()  {
            let pos = self.positions[i];
            let encrypted_value = item[pos as usize].clone().0;
            let mut passwords_byte = vec![];
            self.private_keys[i].decode(&mut Cursor::new(encrypted_value), &mut passwords_byte).map_err(DecryptionFailed)?;

            let password = Password::deserialize(<&[u8; 33]>::try_from(passwords_byte.as_slice()).unwrap());
            res.push(password);
        }

        Ok(res)
    }
}


impl NKey {
    // Verifies that the nkeys form an arithmetic progression, with a consistent common difference in each byte.
    pub fn verify(&self) -> bool {
        for i in 0..N - 1 {
            let current_pk = self.0[i as usize].clone();
            let next_pk = self.0[(i + 1) as usize].clone();

            if current_pk.exponent + BigUint::from(R) != next_pk.exponent {
                return false;
            }

            if current_pk.modulus + BigUint::from(R) != next_pk.modulus {
                return false;
            }
        }

        true
    }
}

// Encrypts the passwords, with the public keys from another party.
pub fn ot_encryption_passwords(passwords_b: &[PasswordPair], nkeys_list: &[NKey]) -> Result<Vec<[EncryptedValue; N as usize]>, OTError> {
    if passwords_b.len() != nkeys_list.len() {
        return Err(LengthNotMatch);
    }
    let mut res = Vec::new();
    for i in 0..passwords_b.len() {

        if nkeys_list[i].0.len() != N as usize || passwords_b[i].pair.len() != N as usize{
            return Err(LengthNotMatch);
        }

        if !nkeys_list[i].verify() {
            return Err(OTError::InvalidNKeys)
        }
        let mut enc_gate_value = vec![EncryptedValue::default(); N as usize];
        for (j, enc_gate_value) in enc_gate_value.iter_mut().enumerate().take(nkeys_list[i].0.len()) {
            let serialized_password = passwords_b[i].pair[j].serialize();
            let mut encrypted_value = Vec::new();
            nkeys_list[i].0[j].encode(&mut Cursor::new(serialized_password), &mut encrypted_value).map_err(EncryptionFailed)?;
            *enc_gate_value = EncryptedValue(encrypted_value);
        }
        res.push(enc_gate_value.clone().try_into().expect("Failed to convert to [Passsword; N as usize]"));

    }

    Ok(res)
}

mod test {
    use std::io::Cursor;
    use rand::thread_rng;
    use rrsa_lib::key::KeyPair;
    use crate::circuit::Circuit::{Gate, Input};
    use crate::circuit::{GateInfo, PartyInput};
    use crate::garbled_circuit::garble_circuit;
    use crate::ot::{ot_encryption_passwords, NKeysList};
    use crate::password::Password;

    #[test]
    pub fn test_gen_key() {
        let secret_value = vec![0, 1, 1];
        let nkeylist = NKeysList::new(&secret_value);
        for nkey in nkeylist.nkeys {
            assert!(nkey.verify());
        }
    }

    #[test]
    pub fn test_encryption_and_decryption_passwords() {
        let mut rng = thread_rng();
        let pass = Password::new(&mut rng, 0);
        let serialized_pass = pass.serialize();
        println!("pass: {:?}", serialized_pass);

        let key_pair = KeyPair::generate(Some(512), true, true, true);
        let pub_key = key_pair.public_key;
        let priv_key = key_pair.private_key;
        let mut encrypted_value = Vec::new();

        pub_key.encode(&mut Cursor::new(serialized_pass), &mut encrypted_value).unwrap();
        println!("{:?}", encrypted_value);

        let mut decrypted_value = Vec::new();
        priv_key.decode(&mut Cursor::new(encrypted_value), &mut decrypted_value).unwrap();

        println!("{:?}", decrypted_value);

        assert_eq!(decrypted_value, serialized_pass);

    }

    #[test]
    pub fn test_ot_flow() {
        let circuit = Gate(
            GateInfo(0b1000),
            Box::new(Gate(GateInfo(0b1001), Box::new(Input(PartyInput::A(0))), Box::new(Input(PartyInput::B(0))))),
            Box::new(Gate(GateInfo(0b1001), Box::new(Input(PartyInput::A(1))), Box::new(Input(PartyInput::B(1))))),
        );
        let mut rng = thread_rng();
        let (_, _, passwords_b, _) = garble_circuit(&mut rng, &circuit);

        let b_value = vec![0_u8, 0_u8];

        // Bob generates public keys
        let nkey_list = NKeysList::new(&b_value);

        // Bob sends public keys for Alice, and Alice encrypts passwords with these keys
        let res_encryption_passwords = ot_encryption_passwords(&passwords_b, &nkey_list.nkeys);
        assert!(res_encryption_passwords.is_ok());
        let encryption_passwords = res_encryption_passwords.unwrap();

        // Bob encrypts all needed passwords
        let res_passwords = nkey_list.decrypt(encryption_passwords);
        assert!(res_passwords.is_ok());
        let passwords = res_passwords.unwrap();

        // Check the encrypted passwords are correct.
        assert_eq!(passwords[0], passwords_b[0].pair[0]);
        assert_eq!(passwords[1], passwords_b[1].pair[0]);
    }
}
