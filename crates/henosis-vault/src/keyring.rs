//! Password-encrypted local identity and provider credential keyring.
//!
//! Stores a 12-word recovery mnemonic and named provider credentials inside a
//! versioned [`crate::storage`] envelope. Secret strings are cleared on drop via
//! `zeroize`, redacted in `Debug` output, and rejected if they contain HTTP
//! header-injection characters (`\r`, `\n`, `\0`).
//!
//! Security limits: no `mlock`, hardware enclave, rollback detection, or
//! same-user malware isolation. Only use rotatable development credentials until
//! an independent security audit is complete.

use crate::storage::{self, StorageError};
use crate::{generate_mnemonic, public_key_fingerprint, Identity, IdentityError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const KEYRING_FORMAT_VERSION: u32 = 1;
const MAX_CREDENTIALS: usize = 64;
const MAX_NAME_LEN: usize = 64;
const MAX_SECRET_LEN: usize = 4096;
const MAX_URL_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    Bearer,
    XApiKey,
}

impl AuthScheme {
    pub fn parse(value: &str) -> Result<Self, KeyringError> {
        match value {
            "bearer" => Ok(Self::Bearer),
            "x-api-key" | "x_api_key" => Ok(Self::XApiKey),
            _ => Err(KeyringError::Validation(
                "auth scheme must be 'bearer' or 'x-api-key'".into(),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::XApiKey => "x-api-key",
        }
    }
}

/// Non-secret metadata for an encrypted provider entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub name: String,
    pub auth_scheme: AuthScheme,
    pub base_url: Option<String>,
    pub secret_len: usize,
}

/// Non-secret summary of a vault's default identity (derived with the passphrase
/// provided at initialization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSummary {
    pub public_key_hex: String,
    pub fingerprint: String,
    pub credential_count: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredential {
    secret: String,
    auth_scheme: AuthScheme,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base_url: Option<String>,
}

impl Drop for StoredCredential {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringDocument {
    version: u32,
    mnemonic: String,
    public_key_hex: String,
    fingerprint: String,
    credentials: BTreeMap<String, StoredCredential>,
}

impl Drop for KeyringDocument {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
    }
}

#[derive(Debug)]
pub enum KeyringError {
    Storage(StorageError),
    Identity(IdentityError),
    Validation(String),
    Corrupt(String),
    NotFound(String),
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "{err}"),
            Self::Identity(err) => write!(f, "{err}"),
            Self::Validation(msg) => write!(f, "invalid keyring input: {msg}"),
            Self::Corrupt(msg) => write!(f, "corrupt keyring payload: {msg}"),
            Self::NotFound(name) => write!(f, "no credential named '{name}'"),
        }
    }
}

impl std::error::Error for KeyringError {}

impl From<StorageError> for KeyringError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

impl From<IdentityError> for KeyringError {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}

fn validate_provider_name(name: &str) -> Result<(), KeyringError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.bytes().enumerate().all(|(idx, b)| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || (idx > 0 && (b == b'-' || b == b'_'))
        });
    if ok {
        Ok(())
    } else {
        Err(KeyringError::Validation(
            "provider name must be 1..=64 lowercase ASCII alphanumeric, '-' or '_' characters"
                .into(),
        ))
    }
}

fn validate_secret(secret: &str) -> Result<(), KeyringError> {
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(KeyringError::Validation(
            "secret must be nonempty and at most 4096 bytes".into(),
        ));
    }
    if secret
        .bytes()
        .any(|b| b == 0 || b == b'\r' || b == b'\n' || b.is_ascii_control())
    {
        return Err(KeyringError::Validation(
            "secret must not contain control characters".into(),
        ));
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<(), KeyringError> {
    if url.is_empty()
        || url.len() > MAX_URL_LEN
        || !(url.starts_with("http://") || url.starts_with("https://"))
        || url.bytes().any(|b| b.is_ascii_control() || b == b' ')
    {
        return Err(KeyringError::Validation(
            "base URL must start with http:// or https:// and contain no spaces or control bytes"
                .into(),
        ));
    }
    Ok(())
}

fn validate_document(doc: &KeyringDocument) -> Result<(), KeyringError> {
    if doc.version != KEYRING_FORMAT_VERSION {
        return Err(KeyringError::Corrupt(format!(
            "unsupported keyring version {}",
            doc.version
        )));
    }
    // Confirm the stored mnemonic parses as a valid 12-word phrase.
    let _ = Identity::recover(&doc.mnemonic, "")?;
    let pk = crate::hex::decode_array::<32>(&doc.public_key_hex)
        .map_err(|_| KeyringError::Corrupt("invalid stored public key hex".into()))?;
    if public_key_fingerprint(&pk) != doc.fingerprint {
        return Err(KeyringError::Corrupt(
            "stored fingerprint does not match stored public key".into(),
        ));
    }
    if doc.credentials.len() > MAX_CREDENTIALS {
        return Err(KeyringError::Corrupt("too many credentials".into()));
    }
    for (name, cred) in &doc.credentials {
        validate_provider_name(name)?;
        validate_secret(&cred.secret)?;
        if let Some(url) = &cred.base_url {
            validate_url(url)?;
        }
    }
    Ok(())
}

fn encode_document(doc: &KeyringDocument) -> Result<Zeroizing<Vec<u8>>, KeyringError> {
    serde_json::to_vec(doc)
        .map(Zeroizing::new)
        .map_err(|err| KeyringError::Corrupt(err.to_string()))
}

/// An unlocked in-memory vault keyring with compare-and-swap persistence.
pub struct UnlockedVault {
    doc: KeyringDocument,
    ciphertext_sha256: [u8; 32],
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("fingerprint", &self.doc.fingerprint)
            .field("credentials", &self.doc.credentials.len())
            .finish_non_exhaustive()
    }
}

impl UnlockedVault {
    /// Generate a new 12-word mnemonic, encrypt it to `path` (create-only), and
    /// return the mnemonic once for user backup along with the public summary.
    pub fn create_new(
        path: &Path,
        password: &[u8],
        passphrase: &str,
    ) -> Result<(Zeroizing<String>, VaultSummary), KeyringError> {
        let mnemonic = generate_mnemonic()?;
        let summary = Self::create_from_mnemonic(path, password, &mnemonic, passphrase)?;
        Ok((mnemonic, summary))
    }

    /// Persist an existing 12-word mnemonic into a new encrypted vault file.
    pub fn create_from_mnemonic(
        path: &Path,
        password: &[u8],
        phrase: &str,
        passphrase: &str,
    ) -> Result<VaultSummary, KeyringError> {
        let identity = Identity::recover(phrase, passphrase)?;
        // Normalize spacing by re-parsing.
        let normalized: Zeroizing<String> = Zeroizing::new(
            phrase
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        );
        let doc = KeyringDocument {
            version: KEYRING_FORMAT_VERSION,
            mnemonic: normalized.as_str().to_owned(),
            public_key_hex: identity.public_key_hex(),
            fingerprint: identity.fingerprint(),
            credentials: BTreeMap::new(),
        };
        validate_document(&doc)?;
        let encoded = encode_document(&doc)?;
        let _ = storage::create_with_digest(path, password, &encoded)?;
        Ok(VaultSummary {
            public_key_hex: doc.public_key_hex.clone(),
            fingerprint: doc.fingerprint.clone(),
            credential_count: 0,
        })
    }

    /// Decrypt and validate an existing vault file.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self, KeyringError> {
        let opened = storage::open_with_digest(path, password)?;
        let doc: KeyringDocument = serde_json::from_slice(&opened.plaintext)
            .map_err(|err| KeyringError::Corrupt(err.to_string()))?;
        validate_document(&doc)?;
        Ok(Self {
            doc,
            ciphertext_sha256: opened.ciphertext_sha256,
        })
    }

    pub fn summary(&self) -> VaultSummary {
        VaultSummary {
            public_key_hex: self.doc.public_key_hex.clone(),
            fingerprint: self.doc.fingerprint.clone(),
            credential_count: self.doc.credentials.len(),
        }
    }

    /// Derive the Ed25519 signing identity using `passphrase`.
    pub fn identity(&self, passphrase: &str) -> Result<Identity, KeyringError> {
        Ok(Identity::recover(&self.doc.mnemonic, passphrase)?)
    }

    /// Derive a purpose-separated 32-byte symmetric key from the stored seed.
    pub fn purpose_key(
        &self,
        passphrase: &str,
        purpose: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KeyringError> {
        Ok(crate::derive_purpose_key(&self.doc.mnemonic, passphrase, purpose)?)
    }

    /// Insert or replace a named provider credential in memory. Call [`Self::save`]
    /// to persist changes atomically.
    pub fn set_credential(
        &mut self,
        name: &str,
        secret: &str,
        auth_scheme: AuthScheme,
        base_url: Option<String>,
    ) -> Result<CredentialSummary, KeyringError> {
        validate_provider_name(name)?;
        validate_secret(secret)?;
        if let Some(url) = &base_url {
            validate_url(url)?;
        }
        if !self.doc.credentials.contains_key(name) && self.doc.credentials.len() >= MAX_CREDENTIALS
        {
            return Err(KeyringError::Validation(
                "keyring already holds maximum 64 credentials".into(),
            ));
        }
        let summary = CredentialSummary {
            name: name.to_owned(),
            auth_scheme,
            base_url: base_url.clone(),
            secret_len: secret.len(),
        };
        self.doc.credentials.insert(
            name.to_owned(),
            StoredCredential {
                secret: secret.to_owned(),
                auth_scheme,
                base_url,
            },
        );
        Ok(summary)
    }

    pub fn remove_credential(&mut self, name: &str) -> Result<(), KeyringError> {
        self.doc
            .credentials
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| KeyringError::NotFound(name.to_owned()))
    }

    pub fn list_credentials(&self) -> Vec<CredentialSummary> {
        self.doc
            .credentials
            .iter()
            .map(|(name, cred)| CredentialSummary {
                name: name.clone(),
                auth_scheme: cred.auth_scheme,
                base_url: cred.base_url.clone(),
                secret_len: cred.secret.len(),
            })
            .collect()
    }

    /// Retrieve a decrypted provider credential for in-process proxy injection.
    /// Never pass the returned secret into child process environments or logs.
    pub fn resolve_credential(
        &self,
        name: &str,
    ) -> Result<(Zeroizing<String>, CredentialSummary), KeyringError> {
        let cred = self
            .doc
            .credentials
            .get(name)
            .ok_or_else(|| KeyringError::NotFound(name.to_owned()))?;
        Ok((
            Zeroizing::new(cred.secret.clone()),
            CredentialSummary {
                name: name.to_owned(),
                auth_scheme: cred.auth_scheme,
                base_url: cred.base_url.clone(),
                secret_len: cred.secret.len(),
            },
        ))
    }

    /// Return zeroized copies of all stored secret strings (including the mnemonic)
    /// for outbound DLP registration in `henosis-proxy`.
    pub fn protected_literals(&self) -> Vec<Zeroizing<String>> {
        let mut out = Vec::with_capacity(self.doc.credentials.len() + 1);
        out.push(Zeroizing::new(self.doc.mnemonic.clone()));
        for cred in self.doc.credentials.values() {
            out.push(Zeroizing::new(cred.secret.clone()));
        }
        out
    }

    /// Persist modifications only if the on-disk file has not changed since open
    /// or the previous save.
    pub fn save(&mut self, path: &Path, password: &[u8]) -> Result<(), KeyringError> {
        validate_document(&self.doc)?;
        let encoded = encode_document(&self.doc)?;
        let next_digest =
            storage::replace_if_unchanged(path, &self.ciphertext_sha256, password, &encoded)?;
        self.ciphertext_sha256 = next_digest;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_lifecycle_stores_credentials_without_leaking_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sovereign.hnv");
        let pw = b"correct-horse-battery-staple-test";
        let (mnemonic, summary) = UnlockedVault::create_new(&path, pw, "").unwrap();
        assert_eq!(summary.credential_count, 0);

        let mut vault = UnlockedVault::open(&path, pw).unwrap();
        let id = vault.identity("").unwrap();
        assert_eq!(id.public_key_hex(), summary.public_key_hex);

        vault
            .set_credential(
                "openrouter",
                "sk-or-v1-test-dummy-credential-99999",
                AuthScheme::Bearer,
                Some("http://127.0.0.1:8080".into()),
            )
            .unwrap();
        vault
            .set_credential("anthropic", "sk-ant-test-dummy-77777", AuthScheme::XApiKey, None)
            .unwrap();
        vault.save(&path, pw).unwrap();

        let disk_bytes = std::fs::read(&path).unwrap();
        let lossy = String::from_utf8_lossy(&disk_bytes);
        assert!(!lossy.contains("sk-or-v1-test-dummy"));
        assert!(!lossy.contains(mnemonic.as_str()));
        assert!(!format!("{vault:?}").contains("sk-or-v1-test-dummy"));

        let mut reopened = UnlockedVault::open(&path, pw).unwrap();
        assert_eq!(reopened.list_credentials().len(), 2);
        let (secret, meta) = reopened.resolve_credential("openrouter").unwrap();
        assert_eq!(secret.as_str(), "sk-or-v1-test-dummy-credential-99999");
        assert_eq!(meta.auth_scheme, AuthScheme::Bearer);
        assert_eq!(reopened.protected_literals().len(), 3);

        reopened.remove_credential("anthropic").unwrap();
        reopened.save(&path, pw).unwrap();

        // Stale handle cannot silently overwrite the newer save.
        vault
            .set_credential("openai", "sk-proj-stale", AuthScheme::Bearer, None)
            .unwrap();
        assert!(matches!(
            vault.save(&path, pw),
            Err(KeyringError::Storage(StorageError::Conflict))
        ));
    }

    #[test]
    fn rejects_header_injection_and_malformed_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.hnv");
        let pw = b"test-password";
        let _ = UnlockedVault::create_new(&path, pw, "").unwrap();
        let mut vault = UnlockedVault::open(&path, pw).unwrap();
        assert!(vault
            .set_credential("UPPER", "valid", AuthScheme::Bearer, None)
            .is_err());
        assert!(vault
            .set_credential("-leading", "valid", AuthScheme::Bearer, None)
            .is_err());
        assert!(vault
            .set_credential("openai", "bad\r\nX-Injected: 1", AuthScheme::Bearer, None)
            .is_err());
        assert!(vault
            .set_credential("openai", "valid", AuthScheme::Bearer, Some("ftp://bad".into()))
            .is_err());
    }
}
