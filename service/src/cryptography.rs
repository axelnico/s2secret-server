use rand::distr::Alphanumeric;
use rand::Rng;
use aes_gcm::{AeadCore,Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::aead::consts::U12;

pub fn one_time_secret_code() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

pub fn decrypt_using_nonce(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ()> {
    let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce[..12]);
    cipher.decrypt(nonce,ciphertext).map_err(|_| ())
}

pub fn encrypt_with_nonce(key: &[u8], plaintext: &[u8], nonce: Nonce<U12>) -> Result<Vec<u8>, ()> {
    let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).map_err(|_| ())?;
    Ok(ciphertext)
}