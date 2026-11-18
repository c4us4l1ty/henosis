//! Detached Ed25519 checkpoints for crux journals.
//!
//! Signs a validated journal's exact byte length, event count, and SHA-256
//! digest without altering the JSON-lines format. Later verification can distinguish:
//! - [`CheckpointStatus::ExactMatch`]: byte-for-byte identical to the signed snapshot.
//! - [`CheckpointStatus::AppendOnlyExtension`]: the signed prefix bytes are intact
//!   and only valid events were appended after the checkpoint.
//! - [`CheckpointStatus::HistoryAltered`]: truncation, rollback, or modification
//!   within the signed prefix.
//!
//! A valid signature proves possession of the signing key when the checkpoint
//! was created, not truth of journal entries or resistance against an attacker
//! who replaces both journal and checkpoint files.

use crate::{open_read, snapshot};
use henosis_vault::{
    hex, public_key_fingerprint, verify_domain_hex, Identity, DOMAIN_CRUX_CHECKPOINT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::path::Path;

const CHECKPOINT_VERSION: u32 = 1;
const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024;
const MAX_NOTE_LEN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub version: u32,
    pub event_count: usize,
    pub byte_len: u64,
    pub journal_sha256: String,
    pub note: String,
    pub public_key_hex: String,
    pub fingerprint: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCheckpoint<'a> {
    version: u32,
    event_count: usize,
    byte_len: u64,
    journal_sha256: &'a str,
    note: &'a str,
    public_key_hex: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointStatus {
    ExactMatch,
    AppendOnlyExtension { appended_events: usize },
    HistoryAltered { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointReport {
    pub checkpoint: SignedCheckpoint,
    pub status: CheckpointStatus,
    pub current_events: usize,
    pub current_sha256: String,
}

fn canonical_payload(
    version: u32,
    event_count: usize,
    byte_len: u64,
    journal_sha256: &str,
    note: &str,
    public_key_hex: &str,
) -> io::Result<Vec<u8>> {
    serde_json::to_vec(&CanonicalCheckpoint {
        version,
        event_count,
        byte_len,
        journal_sha256,
        note,
        public_key_hex,
    })
    .map_err(io::Error::other)
}

/// Sign a validated snapshot of `journal_path` and publish the detached
/// checkpoint to `checkpoint_path` without overwriting an existing file.
pub fn create_checkpoint(
    journal_path: &Path,
    checkpoint_path: &Path,
    identity: &Identity,
    note: &str,
) -> io::Result<SignedCheckpoint> {
    if note.len() > MAX_NOTE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "checkpoint note exceeds 512 bytes",
        ));
    }
    let file = open_read(journal_path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal is not a regular file",
        ));
    }
    fs2::FileExt::lock_shared(&file)?;
    let (events, bytes) = snapshot(&file)?;
    drop(file);

    let journal_sha256 = hex::encode(&Sha256::digest(&bytes));
    let public_key_hex = identity.public_key_hex();
    let fingerprint = identity.fingerprint();
    let byte_len = bytes.len() as u64;
    let payload = canonical_payload(
        CHECKPOINT_VERSION,
        events.len(),
        byte_len,
        &journal_sha256,
        note,
        &public_key_hex,
    )?;
    let signature_hex = identity
        .sign_domain_hex(DOMAIN_CRUX_CHECKPOINT, &payload)
        .map_err(io::Error::other)?;
    let checkpoint = SignedCheckpoint {
        version: CHECKPOINT_VERSION,
        event_count: events.len(),
        byte_len,
        journal_sha256,
        note: note.to_owned(),
        public_key_hex,
        fingerprint,
        signature_hex,
    };
    let mut encoded = serde_json::to_vec_pretty(&checkpoint).map_err(io::Error::other)?;
    encoded.push(b'\n');

    let parent = checkpoint_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(&encoded)?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(checkpoint_path)
        .map_err(|err| err.error)?;
    Ok(checkpoint)
}

fn read_checkpoint(path: &Path) -> io::Result<SignedCheckpoint> {
    let file = open_read(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "checkpoint is not a regular file",
        ));
    }
    let mut buf = Vec::new();
    file.take(MAX_CHECKPOINT_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint exceeds size limit",
        ));
    }
    let cp: SignedCheckpoint = serde_json::from_slice(&buf)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if cp.version != CHECKPOINT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported checkpoint version",
        ));
    }
    let pk = hex::decode_array::<32>(&cp.public_key_hex)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if public_key_fingerprint(&pk) != cp.fingerprint {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint fingerprint does not match public key",
        ));
    }
    let _ = hex::decode_array::<32>(&cp.journal_sha256)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let payload = canonical_payload(
        cp.version,
        cp.event_count,
        cp.byte_len,
        &cp.journal_sha256,
        &cp.note,
        &cp.public_key_hex,
    )?;
    verify_domain_hex(
        &cp.public_key_hex,
        DOMAIN_CRUX_CHECKPOINT,
        &payload,
        &cp.signature_hex,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(cp)
}

/// Verify a detached checkpoint's Ed25519 signature (and optional expected
/// public key) and compare it against the current validated journal.
pub fn verify_checkpoint(
    journal_path: &Path,
    checkpoint_path: &Path,
    expected_public_key_hex: Option<&str>,
) -> io::Result<CheckpointReport> {
    let checkpoint = read_checkpoint(checkpoint_path)?;
    if let Some(expected) = expected_public_key_hex {
        if checkpoint.public_key_hex != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "checkpoint signer does not match expected public key",
            ));
        }
    }
    let file = open_read(journal_path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal is not a regular file",
        ));
    }
    fs2::FileExt::lock_shared(&file)?;
    let (events, bytes) = snapshot(&file)?;
    drop(file);

    let current_sha256 = hex::encode(&Sha256::digest(&bytes));
    let current_len = bytes.len() as u64;
    let status = if current_len == checkpoint.byte_len
        && current_sha256 == checkpoint.journal_sha256
        && events.len() == checkpoint.event_count
    {
        CheckpointStatus::ExactMatch
    } else if current_len < checkpoint.byte_len {
        CheckpointStatus::HistoryAltered {
            reason: format!(
                "journal shrank from {} bytes to {} bytes (truncated or rolled back)",
                checkpoint.byte_len, current_len
            ),
        }
    } else {
        let prefix_len = usize::try_from(checkpoint.byte_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "checkpoint byte_len overflow"))?;
        let prefix_sha256 = hex::encode(&Sha256::digest(&bytes[..prefix_len]));
        if prefix_sha256 == checkpoint.journal_sha256 && events.len() > checkpoint.event_count {
            CheckpointStatus::AppendOnlyExtension {
                appended_events: events.len() - checkpoint.event_count,
            }
        } else {
            CheckpointStatus::HistoryAltered {
                reason: "signed prefix bytes were modified after checkpointing".into(),
            }
        }
    };
    Ok(CheckpointReport {
        checkpoint,
        status,
        current_events: events.len(),
        current_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{append, Event};

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn checkpoint_detects_exact_match_append_extension_rollback_and_forgery() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("crux.jsonl");
        let sig = dir.path().join("crux.sig.json");
        let id = Identity::recover(PHRASE, "").unwrap();
        let other = Identity::recover(PHRASE, "other").unwrap();

        append(
            &journal,
            Event::Proposed {
                goal: "Reproduce Euler solver".into(),
                hypothesis: "dt=0.05 is stable".into(),
                test: "Run baseline".into(),
            },
        )
        .unwrap();
        create_checkpoint(&journal, &sig, &id, "day-1").unwrap();
        // Create-only: refuses to overwrite.
        assert_eq!(
            create_checkpoint(&journal, &sig, &id, "day-2")
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );

        let exact = verify_checkpoint(&journal, &sig, Some(&id.public_key_hex())).unwrap();
        assert_eq!(exact.status, CheckpointStatus::ExactMatch);
        assert_eq!(
            verify_checkpoint(&journal, &sig, Some(&other.public_key_hex()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        // Append-only extension preserves signed prefix.
        append(
            &journal,
            Event::Observed {
                proposal: 1,
                outcome: "Matched analytical curve".into(),
            },
        )
        .unwrap();
        let ext = verify_checkpoint(&journal, &sig, None).unwrap();
        assert_eq!(
            ext.status,
            CheckpointStatus::AppendOnlyExtension { appended_events: 1 }
        );

        // Rewriting a character inside event 1 breaks the prefix hash while keeping JSON valid.
        let rewritten = std::fs::read_to_string(&journal)
            .unwrap()
            .replace("dt=0.05", "dt=0.01");
        std::fs::write(&journal, rewritten).unwrap();
        let altered = verify_checkpoint(&journal, &sig, None).unwrap();
        assert!(matches!(altered.status, CheckpointStatus::HistoryAltered { .. }));

        // Rollback to empty journal is detected as truncation.
        std::fs::write(&journal, b"").unwrap();
        let rolled = verify_checkpoint(&journal, &sig, None).unwrap();
        assert!(matches!(rolled.status, CheckpointStatus::HistoryAltered { .. }));

        // Tampering with the checkpoint itself fails signature verification.
        let bad_cp = std::fs::read_to_string(&sig)
            .unwrap()
            .replace("day-1", "day-9");
        std::fs::write(&sig, bad_cp).unwrap();
        assert_eq!(
            verify_checkpoint(&journal, &sig, None).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
