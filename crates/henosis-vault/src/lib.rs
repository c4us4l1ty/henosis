#![deny(unsafe_code)]
//! Local-first cryptographic identity, domain-separated Ed25519 signatures,
//! password-encrypted envelopes, and an encrypted credential keyring.
//!
//! This is **not** a hardware security module or an audited production vault.
//! There is no `mlock`, process isolation, or trusted display. Avoid using real
//! funds, production credentials you cannot rotate, or a mnemonic used elsewhere.
//! Mnemonics, passphrases, and decrypted secrets are exposed to the caller and OS.
//! Signatures prove possession of a key when a payload was signed; they never
//! prove truth, unassisted human authorship, timestamp accuracy, or cleanroom isolation.

pub mod envelope;
pub mod hex;
pub mod keyring;
pub mod storage;

use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

// These constants define identity derivation v1. Changing them changes every
// recovered identity. This is Henosis-specific, not a BIP-32/SLIP-10 wallet.
const IDENTITY_SALT: &[u8] = b"henosis.identity.v1";
const IDENTITY_INFO: &[u8] = b"ed25519.signing-key";

// Purpose-separated subkey derivation (v1), keeping encryption/session keys
// cryptographically independent from the root Ed25519 identity key.
const SUBKEY_SALT: &[u8] = b"henosis.subkey.v1";
const FINGERPRINT_PREFIX: &[u8] = b"henosis.fingerprint.v1\0";
const DOMAIN_SIG_PREFIX: &[u8] = b"henosis.domain-sig.v1\0";
const MAX_DOMAIN_LEN: usize = 128;

/// Standard domain tags used across Henosis subsystems.
pub const DOMAIN_WORLDLINE_COMMIT: &[u8] = b"henosis.worldline.commit.v1";
pub const DOMAIN_CAPABILITY_BUNDLE: &[u8] = b"henosis.akashi.bundle.v1";
pub const DOMAIN_CRUX_CHECKPOINT: &[u8] = b"henosis.crux.checkpoint.v1";
pub const DOMAIN_BLACKOUT_RECEIPT: &[u8] = b"henosis.proxy.blackout.v1";

#[derive(Debug)]
pub enum IdentityError {
    Randomness(getrandom::Error),
    InvalidMnemonic(bip39::Error),
    WrongWordCount,
    InvalidPurpose,
    /// HKDF output or mnemonic-derived seed is not a valid Ed25519 scalar.
    InvalidKey,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Randomness(_) => write!(f, "system randomness unavailable"),
            Self::InvalidMnemonic(_) => write!(f, "invalid English BIP-39 mnemonic"),
            Self::WrongWordCount => write!(f, "identity requires exactly 12 words"),
            Self::InvalidPurpose => write!(f, "purpose label must be 1..=128 ASCII bytes without NUL"),
    Self::InvalidKey => write!(f, "derived key material is not a valid Ed25519 scalar"),
        }
    }
}

impl std::error::Error for IdentityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    InvalidDomain,
    InvalidPublicKey,
    InvalidEncoding,
    VerificationFailed,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDomain => "signature domain must be 1..=128 printable ASCII bytes",
            Self::InvalidPublicKey => "invalid Ed25519 public key",
            Self::InvalidEncoding => "invalid lowercase hexadecimal key or signature",
            Self::VerificationFailed => "Ed25519 signature verification failed",
        })
    }
}

impl std::error::Error for SignatureError {}

fn domain_message(domain: &[u8], payload: &[u8]) -> Result<[u8; 32], SignatureError> {
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_LEN
        || !domain.iter().all(|b| (0x21..=0x7e).contains(b))
    {
        return Err(SignatureError::InvalidDomain);
    }
    let payload_digest = Sha256::digest(payload);
    let len = u32::try_from(domain.len()).map_err(|_| SignatureError::InvalidDomain)?;
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SIG_PREFIX);
    hasher.update(len.to_be_bytes());
    hasher.update(domain);
    hasher.update(payload_digest);
    Ok(hasher.finalize().into())
}

/// Compute a short human-inspectable fingerprint (16 lowercase hex chars) for an
/// Ed25519 public key. Always verify the full 32-byte public key cryptographically;
/// fingerprints are for display disambiguation only.
pub fn public_key_fingerprint(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_PREFIX);
    hasher.update(public_key);
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

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

/// Derive a deterministic 32-byte symmetric subkey for an explicit purpose label
/// from a 12-word mnemonic and optional passphrase. Uses a separate HKDF salt
/// from `Identity::recover` so subkeys remain independent of the signing key.
pub fn derive_purpose_key(
    phrase: &str,
    passphrase: &str,
    purpose: &[u8],
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    if purpose.is_empty()
        || purpose.len() > MAX_DOMAIN_LEN
        || !purpose.iter().all(|b| (0x21..=0x7e).contains(b))
    {
        return Err(IdentityError::InvalidPurpose);
    }
    let mnemonic =
        Mnemonic::parse_in(Language::English, phrase).map_err(IdentityError::InvalidMnemonic)?;
    if mnemonic.word_count() != 12 {
        return Err(IdentityError::WrongWordCount);
    }
    let seed = mnemonic.to_seed(passphrase);
    let hkdf = Hkdf::<Sha256>::new(Some(SUBKEY_SALT), seed.expose_secret());
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(purpose, out.as_mut())
        .expect("valid HKDF output length");
    Ok(out)
}

/// A deterministic Ed25519 identity derived from a 12-word mnemonic and its
/// optional BIP-39 passphrase. Losing either changes or destroys recoverability.
/// A signature proves possession of this key, not hardware cleanroom attestation.
pub struct Identity {
    signing_key: SigningKey,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn recover(phrase: &str, passphrase: &str) -> Result<Self, IdentityError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(IdentityError::InvalidMnemonic)?;
        if mnemonic.word_count() != 12 {
            return Err(IdentityError::WrongWordCount);
        }
        let seed = mnemonic.to_seed(passphrase);
        let hkdf = Hkdf::<Sha256>::new(Some(IDENTITY_SALT), &seed);
        let mut key = Zeroizing::new([0u8; 32]);
        // A 32-byte HKDF-SHA256 output is always within the expansion limit.
        hkdf.expand(IDENTITY_INFO, key.as_mut())
            .expect("valid HKDF output length");
        let signing_key = SigningKey::from_bytes(&*key)
            .expect("derived key material is not a valid Ed25519 scalar");
        Ok(Self { signing_key })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key())
    }

    pub fn fingerprint(&self) -> String {
        public_key_fingerprint(&self.public_key())
    }

    /// Sign arbitrary bytes. A signature proves key possession, not capability,
    /// human authorship, cleanroom conditions, or artifact validity.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Sign `payload` bound to a non-empty ASCII `domain` label so signatures
    /// cannot be replayed across different Henosis record formats.
    pub fn sign_domain(&self, domain: &[u8], payload: &[u8]) -> Result<[u8; 64], SignatureError> {
        let digest = domain_message(domain, payload)?;
        Ok(self.signing_key.sign(&digest).to_bytes())
    }

    /// Convenience wrapper returning a lowercase hex signature.
    pub fn sign_domain_hex(&self, domain: &[u8], payload: &[u8]) -> Result<String, SignatureError> {
        Ok(hex::encode(&self.sign_domain(domain, payload)?))
    }
}

/// Strictly verify an un-prefixed Ed25519 signature against `public_key`.
pub fn verify_raw(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), SignatureError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| SignatureError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature);
    key.verify_strict(message, &sig)
        .map_err(|_| SignatureError::VerificationFailed)
}

/// Strictly verify a domain-separated Ed25519 signature created by `Identity::sign_domain`.
pub fn verify_domain(
    public_key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), SignatureError> {
    let digest = domain_message(domain, payload)?;
    verify_raw(public_key, &digest, signature)
}

/// Strictly verify hex-encoded public key and signature for a domain-separated message.
pub fn verify_domain_hex(
    public_key_hex: &str,
    domain: &[u8],
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), SignatureError> {
    let pk = hex::decode_array::<32>(public_key_hex).map_err(|_| SignatureError::InvalidEncoding)?;
    let sig =
        hex::decode_array::<64>(signature_hex).map_err(|_| SignatureError::InvalidEncoding)?;
    verify_domain(&pk, domain, payload, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
    fn identity_v1_recovery_vector_is_stable() {
        // Independently calculated from the public BIP-39 TREZOR test vector
        // using PBKDF2-HMAC-SHA512, HKDF-SHA256, and Ed25519.
        let identity = Identity::recover(PHRASE, "TREZOR").unwrap();
        assert_eq!(
            identity.public_key(),
            [
                0x69, 0x61, 0xd8, 0x78, 0xb0, 0x3a, 0x53, 0xf1, 0xf0, 0xc9, 0x12, 0xfb, 0x4e,
                0x04, 0x30, 0xe8, 0xb1, 0x87, 0x40, 0xff, 0xdd, 0xbd, 0x49, 0x44, 0xde, 0x4a,
                0xee, 0x85, 0x28, 0xda, 0xd9, 0x58,
            ]
        );
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
    fn domain_separated_signatures_prevent_cross_protocol_replay() {
        let identity = Identity::recover(PHRASE, "").unwrap();
        let pk_hex = identity.public_key_hex();
        let sig_hex = identity
            .sign_domain_hex(DOMAIN_WORLDLINE_COMMIT, b"payload-123")
            .unwrap();
        assert!(verify_domain_hex(&pk_hex, DOMAIN_WORLDLINE_COMMIT, b"payload-123", &sig_hex).is_ok());
        assert_eq!(
            verify_domain_hex(&pk_hex, DOMAIN_CAPABILITY_BUNDLE, b"payload-123", &sig_hex),
            Err(SignatureError::VerificationFailed)
        );
        assert_eq!(
            verify_domain_hex(&pk_hex, DOMAIN_WORLDLINE_COMMIT, b"payload-124", &sig_hex),
            Err(SignatureError::VerificationFailed)
        );
        assert_eq!(
            identity.sign_domain(b"", b"x"),
            Err(SignatureError::InvalidDomain)
        );
        assert_eq!(
            identity.sign_domain(b"bad domain", b"x"),
            Err(SignatureError::InvalidDomain)
        );
    }

    #[test]
    fn purpose_subkeys_are_distinct_and_independent_of_identity() {
        let identity = Identity::recover(PHRASE, "").unwrap();
        let k1 = derive_purpose_key(PHRASE, "", b"sync.encrypt.v1").unwrap();
        let k2 = derive_purpose_key(PHRASE, "", b"vault.local.v1").unwrap();
        let k1_again = derive_purpose_key(PHRASE, "", b"sync.encrypt.v1").unwrap();
        assert_eq!(*k1, *k1_again);
        assert_ne!(*k1, *k2);
        assert_ne!(*k1, identity.public_key());
        assert!(derive_purpose_key(PHRASE, "", b"").is_err());
    }

    #[test]
    fn debug_redacts_private_material() {
        let identity = Identity::recover(PHRASE, "").unwrap();
        let rendered = format!("{identity:?}");
        assert!(rendered.contains(&identity.fingerprint()));
        assert_eq!(identity.fingerprint().len(), 16);
    }

    #[test]
    fn rejects_bad_checksum_and_non_twelve_word_mnemonics() {
        assert!(matches!(
            Identity::recover(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
                ""
            ),
            Err(IdentityError::InvalidMnemonic(_))
        ));
        let long = Mnemonic::from_entropy(&[0u8; 32]).unwrap().to_string();
        assert!(matches!(
            Identity::recover(&long, ""),
            Err(IdentityError::WrongWordCount)
        ));
    }
}
