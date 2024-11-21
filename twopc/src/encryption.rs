use ecies::{encrypt, PublicKey, SecretKey};
use crate::garbled_circuit::EncryptedValue;
use crate::password::Password;


// Construct the secret key from P_left, P_right and encrypt the P_out.
pub fn encrypt_password(
    left: &Password,
    right: &Password,
    out: &Password
) -> EncryptedValue {

    let left_scalar = left.pass.serialize();
    let right_scalar = right.pass.serialize();
    let mut out_scalar = [0_u8; 32];

    for (i, (l_i, r_i)) in left_scalar.iter().zip(right_scalar.iter()).enumerate() {
        out_scalar[i] = *l_i ^ *r_i;
    }

    let secret_key = SecretKey::parse_slice(&out_scalar).unwrap();
    let public_key = PublicKey::from_secret_key(&secret_key);
    let pk=  &public_key.serialize();
    let out_msg = out.serialize();
    let encrypted_value = encrypt(pk, &out_msg).unwrap();

    EncryptedValue(encrypted_value)
}
#[test]
pub fn test_encryption() {
    let mut rng = rand::thread_rng();
    let sk1 = SecretKey::random(&mut rng);
    let sk2 = SecretKey::random(&mut rng);

    let left_scalar = sk1.serialize();
    let right_scalar = sk2.serialize();
    let mut encrypt_scalar = [0_u8; 32];
    for (i, (l_i, r_i)) in left_scalar.iter().zip(right_scalar.iter()).enumerate() {
        encrypt_scalar[i] = *l_i ^ *r_i;
    }

    let secret_key = SecretKey::parse_slice(&encrypt_scalar).unwrap();
    let public_key = PublicKey::from_secret_key(&secret_key);
    let (sk, pk) = (&secret_key.serialize(), &public_key.serialize());
    let out = Password::new(&mut rng, 1);
    let out_msg = out.serialize();
    println!("out: {:?}", out_msg);
    let encrypted_value = encrypt(pk, &out_msg).unwrap();
    println!("encrypted_value: {:?}", encrypted_value);
    let plain_text_value = ecies::decrypt(sk, &encrypted_value).unwrap();
    println!("plain text: {:?}", plain_text_value);
    assert_eq!(out_msg.as_slice(), plain_text_value.as_slice());
    let password = Password::deserialize(<&[u8; 33]>::try_from(plain_text_value.as_slice()).unwrap());
    println!("password: {:?}", password);
    assert_eq!(password, out);
}