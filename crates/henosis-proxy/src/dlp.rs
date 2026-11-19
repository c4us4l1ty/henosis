//! Outbound prompt Data Loss Prevention (DLP) and secret scanner.
//!
//! Performs deterministic local checks on outbound proxy payloads before any
//! upstream request is sent. Matched secret values are never included in
//! violation messages or telemetry logs.
//!
//! Limitation: heuristic and literal scanning cannot catch encoded, split,
//! paraphrased, or steganographic exfiltration, nor direct network access that
//! bypasses the proxy.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

pub const DEFAULT_MAX_BODY_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpCategory {
    PayloadTooLarge,
    RegisteredVaultSecret,
    PrivateKeyMaterial,
    CredentialPrefix,
    SensitiveHostPath,
    HighEntropyToken,
}

impl DlpCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PayloadTooLarge => "payload_too_large",
            Self::RegisteredVaultSecret => "registered_vault_secret",
            Self::PrivateKeyMaterial => "private_key_material",
            Self::CredentialPrefix => "credential_prefix",
            Self::SensitiveHostPath => "sensitive_host_path",
            Self::HighEntropyToken => "high_entropy_token",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpViolation {
    pub category: DlpCategory,
    pub reason: String,
}

impl fmt::Display for DlpViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "outbound DLP blocked ({}): {}", self.category.as_str(), self.reason)
    }
}

impl std::error::Error for DlpViolation {}

const PRIVATE_KEY_MARKERS: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
];

const CREDENTIAL_PREFIXES: &[(&str, &str)] = &[
    ("sk-ant-", "Anthropic API key prefix"),
    ("sk-proj-", "OpenAI project key prefix"),
    ("sk-or-v1-", "OpenRouter API key prefix"),
    ("ghp_", "GitHub personal access token prefix"),
    ("github_pat_", "GitHub fine-grained token prefix"),
    ("glpat-", "GitLab access token prefix"),
    ("xoxb-", "Slack bot token prefix"),
    ("AKIA", "AWS access key prefix"),
    ("henosis-cap-", "Henosis capability token reflection"),
];

const SENSITIVE_PATHS: &[&str] = &[
    "/.ssh/id_",
    "\\.ssh\\id_",
    "/.gnupg/",
    "/.aws/credentials",
    "\\.aws\\credentials",
    "/etc/shadow",
    ".git-credentials",
    "/.netrc",
];

/// Outbound scanner configuration with zeroized registered vault secrets.
pub struct DlpScanner {
    max_body_bytes: usize,
    entropy_min_len: usize,
    entropy_bits_threshold: f64,
    protected_literals: Vec<Zeroizing<String>>,
}

impl fmt::Debug for DlpScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DlpScanner")
            .field("max_body_bytes", &self.max_body_bytes)
            .field("protected_literal_count", &self.protected_literals.len())
            .finish()
    }
}

impl Default for DlpScanner {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            entropy_min_len: 48,
            entropy_bits_threshold: 4.65,
            protected_literals: Vec::new(),
        }
    }
}

impl DlpScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Register an exact secret string (e.g. a decrypted vault API key or
    /// recovery phrase) to block if it ever appears in an outbound payload.
    /// Short strings under 8 bytes are ignored to avoid spurious matches.
    pub fn register_secret(&mut self, secret: Zeroizing<String>) {
        if secret.len() >= 8 {
            self.protected_literals.push(secret);
        }
    }

    pub fn register_secrets(&mut self, secrets: Vec<Zeroizing<String>>) {
        for secret in secrets {
            self.register_secret(secret);
        }
    }

    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Scan an outbound payload and return the first violation without exposing
    /// matched secret material.
    pub fn scan(&self, body: &[u8]) -> Result<(), DlpViolation> {
        if body.len() > self.max_body_bytes {
            return Err(DlpViolation {
                category: DlpCategory::PayloadTooLarge,
                reason: format!(
                    "request body ({} bytes) exceeds limit ({} bytes)",
                    body.len(),
                    self.max_body_bytes
                ),
            });
        }
        // Check exact registered secrets directly over raw bytes first.
        for secret in &self.protected_literals {
            let needle = secret.as_bytes();
            if needle.len() <= body.len() && body.windows(needle.len()).any(|w| w == needle) {
                return Err(DlpViolation {
                    category: DlpCategory::RegisteredVaultSecret,
                    reason: "payload contained a registered protected vault secret".into(),
                });
            }
        }

        let text = String::from_utf8_lossy(body);
        for marker in PRIVATE_KEY_MARKERS {
            if text.contains(marker) {
                return Err(DlpViolation {
                    category: DlpCategory::PrivateKeyMaterial,
                    reason: "payload contained a private key block header".into(),
                });
            }
        }
        for &(prefix, label) in CREDENTIAL_PREFIXES {
            if contains_credential_prefix(&text, prefix) {
                return Err(DlpViolation {
                    category: DlpCategory::CredentialPrefix,
                    reason: format!("payload matched {label}"),
                });
            }
        }
        for path in SENSITIVE_PATHS {
            if text.contains(path) {
                return Err(DlpViolation {
                    category: DlpCategory::SensitiveHostPath,
                    reason: "payload referenced a restricted credential path".into(),
                });
            }
        }
        if has_high_entropy_token(&text, self.entropy_min_len, self.entropy_bits_threshold) {
            return Err(DlpViolation {
                category: DlpCategory::HighEntropyToken,
                reason: "payload contained a high-entropy token resembling key material".into(),
            });
        }
        Ok(())
    }
}

fn contains_credential_prefix(text: &str, prefix: &str) -> bool {
    let mut rest = text;
    while let Some(pos) = rest.find(prefix) {
        let after = &rest[pos + prefix.len()..];
        let tail_len = after
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            .count();
        if tail_len >= 12 {
            return true;
        }
        rest = after;
    }
    false
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = f64::from(count) / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn has_high_entropy_token(text: &str, min_len: usize, threshold: f64) -> bool {
    let bytes = text.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if !is_token_byte(bytes[idx]) {
            idx += 1;
            continue;
        }
        let start = idx;
        while idx < bytes.len() && is_token_byte(bytes[idx]) {
            idx += 1;
        }
        let token = &bytes[start..idx];
        if token.len() < min_len {
            continue;
        }
        // Pure lowercase hex digests (e.g. SHA-256 hashes of research artifacts)
        // have max entropy <= 4.0 bits/byte and naturally stay under threshold,
        // while mixed-case base64 secret blobs exceed 4.65 bits/byte.
        let has_upper = token.iter().any(|b| b.is_ascii_uppercase());
        let has_lower = token.iter().any(|b| b.is_ascii_lowercase());
        let has_digit = token.iter().any(|b| b.is_ascii_digit());
        if has_upper && has_lower && has_digit && shannon_entropy(token) >= threshold {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_scientific_prompts_and_sha256_digests() {
        let scanner = DlpScanner::new();
        let prompt = br#"{"model":"qwen","messages":[{"role":"user","content":"Derive the CFL stability bound for explicit Euler on dy/dt = -lambda*y. Artifact sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}]}"#;
        assert!(scanner.scan(prompt).is_ok());
    }

    #[test]
    fn blocks_registered_secrets_private_keys_prefixes_paths_and_entropy() {
        let mut scanner = DlpScanner::new();
        scanner.register_secret(Zeroizing::new("custom-vault-secret-token-xyz".into()));

        let r1 = scanner
            .scan(br#"{"prompt":"leak custom-vault-secret-token-xyz"}"#)
            .unwrap_err();
        assert_eq!(r1.category, DlpCategory::RegisteredVaultSecret);
        assert!(!r1.to_string().contains("custom-vault-secret-token-xyz"));

        let r2 = scanner
            .scan(b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
            .unwrap_err();
        assert_eq!(r2.category, DlpCategory::PrivateKeyMaterial);

        let r3 = scanner
            .scan(b"here is sk-ant-api03-1234567890abcdef")
            .unwrap_err();
        assert_eq!(r3.category, DlpCategory::CredentialPrefix);

        let r4 = scanner
            .scan(b"cat /home/alice/.ssh/id_ed25519")
            .unwrap_err();
        assert_eq!(r4.category, DlpCategory::SensitiveHostPath);

        let r5 = scanner
            .scan(b"blob=aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3+/A4B5C6D7E8F9G0H1")
            .unwrap_err();
        assert_eq!(r5.category, DlpCategory::HighEntropyToken);
    }
}
