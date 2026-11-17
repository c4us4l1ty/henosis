#![deny(unsafe_code)]
//! Early identity primitives, **not a secure vault**.
//!
//! There is no encrypted storage, memory locking, process isolation, or trusted
//! display. Avoid using real funds, production credentials, or a mnemonic used
//! elsewhere. Mnemonics and passphrases are still exposed to the caller and OS.

use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

// These constants define identity derivation v1. Changing them changes every
// recovered identity. This is Henosis-specific, not a BIP-32/SLIP-10 wallet.
const IDENTITY_SALT: &[u8] = b"henosis.identity.v1";
const IDENTITY_INFO: &[u8] = b"ed25519.signing-key";

#[derive(Debug)]
pub enum IdentityError {
    Randomness(getrandom::Error),
    InvalidMnemonic(bip39::Error),
    WrongWordCount,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Randomness(_) => write!(f, "system randomness unavailable"),
            Self::InvalidMnemonic(_) => write!(f, "invalid English BIP-39 mnemonic"),
            Self::WrongWordCount => write!(f, "identity requires exactly 12 words"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Generate an English 12-word BIP-39 mnemonic using OS randomness.
/// The caller must protect and back up the returned phrase. Zeroizing this
/// buffer does not erase terminal, clipboard, swap, or other copies.
pub fn generate_mnemonic() -> Result<Zeroizing<String>, IdentityError> {
    let mut entropy = Zeroizing::new([0u8; 16]);
    getrandom::getrandom(entropy.as_mut()).map_err(IdentityError::Randomness)?;
    // A 16-byte input is always valid BIP-39 entropy.
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
        .map_err(IdentityError::InvalidMnemonic)?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// A deterministic Ed25519 identity derived from a 12-word mnemonic and its
/// optional BIP-39 passphrase. Losing either changes or destroys recoverability.
/// This key must not be treated as an Akashi attestation key.
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    pub fn recover(phrase: &str, passphrase: &str) -> Result<Self, IdentityError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(IdentityError::InvalidMnemonic)?;
        if mnemonic.word_count() != 12 {
            return Err(IdentityError::WrongWordCount);
        }
        let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
        let hkdf = Hkdf::<Sha256>::new(Some(IDENTITY_SALT), seed.as_ref());
        let mut key = Zeroizing::new([0u8; 32]);
        // A 32-byte HKDF-SHA256 output is always within the expansion limit.
        hkdf.expand(IDENTITY_INFO, key.as_mut()).expect("valid HKDF output length");
        Ok(Self { signing_key: SigningKey::from_bytes(&key) })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign arbitrary bytes. A signature proves key possession, not capability,
    /// human authorship, cleanroom conditions, or artifact validity.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn generated_phrase_is_valid_twelve_word_mnemonic() {
        let phrase = generate_mnemonic().unwrap();
        let mnemonic = Mnemonic::parse_in(Language::English, phrase.as_str()).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
        assert!(Identity::recover(&phrase, "").is_ok());
    }

    #[test]
    fn recovery_is_deterministic_and_passphrase_sensitive() {
        let first = Identity::recover(PHRASE, "TREZOR").unwrap();
        let second = Identity::recover(PHRASE, "TREZOR").unwrap();
        let other = Identity::recover(PHRASE, "").unwrap();
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(first.sign(b"test"), second.sign(b"test"));
        assert_ne!(first.public_key(), other.public_key());
    }

    #[test]
    fn signatures_verify_and_reject_modified_messages() {
        let identity = Identity::recover(PHRASE, "").unwrap();
        let key = VerifyingKey::from_bytes(&identity.public_key()).unwrap();
        let signature = Signature::from_bytes(&identity.sign(b"artifact"));
        assert!(key.verify_strict(b"artifact", &signature).is_ok());
        assert!(key.verify_strict(b"changed", &signature).is_err());
    }

    #[test]
    fn rejects_bad_checksum_and_non_twelve_word_mnemonics() {
        assert!(matches!(Identity::recover("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", ""), Err(IdentityError::InvalidMnemonic(_))));
        let long = Mnemonic::from_entropy(&[0u8; 32]).unwrap().to_string();
        assert!(matches!(Identity::recover(&long, ""), Err(IdentityError::WrongWordCount)));
    }
}
