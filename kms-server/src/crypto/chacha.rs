use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;

#[derive(Serialize)]
pub struct WrappedPayload {
    pub ephemeral_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn wrap_dek(aes_dek: &[u8]) -> Result<WrappedPayload, String> {
    let mut ephemeral_key = [0u8; 32];
    OsRng.fill_bytes(&mut ephemeral_key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(&ephemeral_key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, aes_dek)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(WrappedPayload {
        ephemeral_key: ephemeral_key.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_dek_success() {
        let dummy_dek = b"dummy_256bit_aes_key_data_here!!";
        let result = wrap_dek(dummy_dek);
        assert!(result.is_ok());

        let payload = result.unwrap();
        assert_eq!(payload.ephemeral_key.len(), 32);
        assert_eq!(payload.nonce.len(), 12);
        assert!(!payload.ciphertext.is_empty());
    }
}
