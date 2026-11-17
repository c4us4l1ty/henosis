//! Versioned password-encrypted bytes.
//!
//! V1 is `magic (8) || salt (16) || nonce (24) || ciphertext || tag (16)`.
//! The entire header is authenticated. The key is derived with Argon2id v1.3,
//! 19 MiB, 2 passes, 1 lane. These parameters are fixed by the format version,
//! not accepted from an untrusted file. No metadata or size is concealed.
//!
//! This is unaudited and does not protect against weak passwords, malware,
//! rollback, memory inspection, swap, or the caller's plaintext copies.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use std::fmt;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"HNVLT\x01\r\n";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
pub(crate) const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;
pub(crate) const TAG_LEN: usize = 16;
/// Maximum bytes accepted as plaintext by this format.
pub const MAX_PLAINTEXT_LEN: usize = 1024 * 1024;
const MAX_PASSWORD_LEN: usize = 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidPassword,
    TooLarge,
    InvalidEnvelope,
    AuthenticationFailed,
    RandomnessUnavailable,
    CryptoFailure,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPassword => "password must be nonempty and at most 1024 bytes",
            Self::TooLarge => "payload exceeds the size limit",
            Self::InvalidEnvelope => "invalid or unsupported envelope",
            Self::AuthenticationFailed => "incorrect password or corrupted envelope",
            Self::RandomnessUnavailable => "system randomness unavailable",
            Self::CryptoFailure => "cryptographic operation failed",
        })
    }
}

impl std::error::Error for EnvelopeError {}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
        return Err(EnvelopeError::InvalidPassword);
    }
    let params = Params::new(19 * 1024, 2, 1, Some(32)).map_err(|_| EnvelopeError::CryptoFailure)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password, salt, key.as_mut()).map_err(|_| EnvelopeError::CryptoFailure)?;
    Ok(key)
}

/// Encrypt bytes using a fresh random salt and nonce. A separate high-entropy
/// password is strongly recommended; a BIP-39 passphrase is not required here.
pub fn seal(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN { return Err(EnvelopeError::TooLarge); }
    if password.is_empty() || password.len() > MAX_PASSWORD_LEN { return Err(EnvelopeError::InvalidPassword); }
    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    getrandom::getrandom(&mut header[MAGIC.len()..]).map_err(|_| EnvelopeError::RandomnessUnavailable)?;
    let key = derive_key(password, &header[MAGIC.len()..MAGIC.len() + SALT_LEN])?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| EnvelopeError::CryptoFailure)?;
    let nonce = XNonce::from_slice(&header[MAGIC.len() + SALT_LEN..]);
    let mut ciphertext = Zeroizing::new(plaintext.to_vec());
    cipher.encrypt_in_place(nonce, &header, &mut *ciphertext).map_err(|_| EnvelopeError::CryptoFailure)?;
    let mut result = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    result.extend_from_slice(&header);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Authenticate and decrypt. No plaintext is returned on authentication failure.
/// The caller owns and must protect the password and returned plaintext.
pub fn open(password: &[u8], envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if envelope.len() < HEADER_LEN + TAG_LEN || &envelope[..MAGIC.len()] != MAGIC {
        return Err(EnvelopeError::InvalidEnvelope);
    }
    if envelope.len() > HEADER_LEN + TAG_LEN + MAX_PLAINTEXT_LEN { return Err(EnvelopeError::TooLarge); }
    let (header, body) = envelope.split_at(HEADER_LEN);
    let key = derive_key(password, &header[MAGIC.len()..MAGIC.len() + SALT_LEN])?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| EnvelopeError::CryptoFailure)?;
    let nonce = XNonce::from_slice(&header[MAGIC.len() + SALT_LEN..]);
    let mut plaintext = Zeroizing::new(body.to_vec());
    cipher.decrypt_in_place(nonce, header, &mut *plaintext).map_err(|_| EnvelopeError::AuthenticationFailed)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_randomizes_envelopes_and_authenticates_contents() {
        let password = b"test password, not a production secret";
        let message = b"sensitive bytes";
        let first = seal(password, message).unwrap();
        let second = seal(password, message).unwrap();
        assert_ne!(first, second);
        assert_eq!(&open(password, &first).unwrap()[..], message);
        assert_eq!(open(b"wrong", &first).unwrap_err(), EnvelopeError::AuthenticationFailed);
        for index in [MAGIC.len(), MAGIC.len() + SALT_LEN, HEADER_LEN, first.len() - 1] {
            let mut modified = first.clone();
            modified[index] ^= 1;
            assert_eq!(open(password, &modified).unwrap_err(), EnvelopeError::AuthenticationFailed);
        }
    }

    #[test]
    fn rejects_invalid_versions_truncation_and_oversized_inputs() {
        assert_eq!(open(b"password", b"short").unwrap_err(), EnvelopeError::InvalidEnvelope);
        let mut bad = vec![0; HEADER_LEN + TAG_LEN];
        bad[..MAGIC.len()].copy_from_slice(MAGIC);
        bad[5] ^= 1;
        assert_eq!(open(b"password", &bad).unwrap_err(), EnvelopeError::InvalidEnvelope);
        assert_eq!(seal(b"", b"data").unwrap_err(), EnvelopeError::InvalidPassword);
        assert_eq!(seal(b"password", &vec![0; MAX_PLAINTEXT_LEN + 1]).unwrap_err(), EnvelopeError::TooLarge);
        let mut huge = vec![0; HEADER_LEN + TAG_LEN + MAX_PLAINTEXT_LEN + 1];
        huge[..MAGIC.len()].copy_from_slice(MAGIC);
        assert_eq!(open(b"password", &huge).unwrap_err(), EnvelopeError::TooLarge);
    }
}
