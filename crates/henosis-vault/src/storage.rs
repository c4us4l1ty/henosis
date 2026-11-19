//! Persistence for encrypted envelopes in a trusted directory.
//!
//! `create` writes to a same-directory temporary file, syncs it, and publishes
//! without replacing an existing destination. `replace_if_unchanged` updates an
//! existing envelope only when its on-disk SHA-256 still matches a caller-supplied
//! snapshot digest under a cooperating advisory sidecar lock.
//!
//! No plaintext is written. This does not protect against an attacker who can
//! modify the directory, backups, or roll the file back to an earlier ciphertext;
//! directory fsync is absent. Unix files use owner-only permissions; Windows
//! permissions depend on directory ACLs. Callers must secure the directory.

use crate::envelope::{self, EnvelopeError, HEADER_LEN, MAX_PLAINTEXT_LEN, TAG_LEN};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAX_ENVELOPE_LEN: usize = HEADER_LEN + MAX_PLAINTEXT_LEN + TAG_LEN;

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Envelope(EnvelopeError),
    /// The on-disk envelope changed since it was opened; caller must reload.
    Conflict,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "vault file error: {error}"),
            Self::Envelope(error) => write!(f, "vault envelope error: {error}"),
            Self::Conflict => f.write_str("vault file changed concurrently; reload before saving"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Envelope(error) => Some(error),
            Self::Conflict => None,
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<EnvelopeError> for StorageError {
    fn from(value: EnvelopeError) -> Self {
        Self::Envelope(value)
    }
}

/// A decrypted envelope together with the SHA-256 of its ciphertext bytes,
/// allowing compare-and-swap updates via [`replace_if_unchanged`].
pub struct OpenedEnvelope {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub ciphertext_sha256: [u8; 32],
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn lock_path(path: &Path) -> io::Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "vault path lacks file name"))?;
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(".hnvlock");
    Ok(parent_dir(path).join(name))
}

fn acquire_update_lock(path: &Path) -> io::Result<File> {
    let sidecar = lock_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(sidecar)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "lock path is not a regular file",
        ));
    }
    fs2::FileExt::lock_exclusive(&file)?;
    Ok(file)
}

/// Create a new encrypted file and return the SHA-256 of the stored ciphertext.
/// Never overwrites an existing destination.
pub fn create_with_digest(
    path: &Path,
    password: &[u8],
    plaintext: &[u8],
) -> Result<[u8; 32], StorageError> {
    let ciphertext = envelope::seal(password, plaintext)?;
    let digest: [u8; 32] = Sha256::digest(&ciphertext).into();
    let mut temporary = tempfile::NamedTempFile::new_in(parent_dir(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(&ciphertext)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| StorageError::Io(error.error))?;
    Ok(digest)
}

/// Create a new encrypted file without overwriting an existing path.
/// The parent directory must already exist and be controlled by the user.
pub fn create(path: &Path, password: &[u8], plaintext: &[u8]) -> Result<(), StorageError> {
    let _ = create_with_digest(path, password, plaintext)?;
    Ok(())
}

// Opening a FIFO for reading ordinarily blocks before we can inspect its type.
// O_NONBLOCK allows fstat to reject FIFOs even when no writer is present.
#[cfg(unix)]
fn open_for_read(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_for_read(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn read_ciphertext(path: &Path) -> Result<Vec<u8>, StorageError> {
    let file = open_for_read(path)?;
    if !file.metadata()?.is_file() {
        return Err(StorageError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        )));
    }
    let mut data = Vec::new();
    file.take((MAX_ENVELOPE_LEN + 1) as u64)
        .read_to_end(&mut data)?;
    if data.len() > MAX_ENVELOPE_LEN {
        return Err(StorageError::Envelope(EnvelopeError::TooLarge));
    }
    Ok(data)
}

/// Read and decrypt a regular file along with its ciphertext SHA-256 digest.
pub fn open_with_digest(path: &Path, password: &[u8]) -> Result<OpenedEnvelope, StorageError> {
    let data = read_ciphertext(path)?;
    let ciphertext_sha256: [u8; 32] = Sha256::digest(&data).into();
    let plaintext = envelope::open(password, &data)?;
    Ok(OpenedEnvelope {
        plaintext,
        ciphertext_sha256,
    })
}

/// Read and decrypt a regular file, with a bound applied before allocation.
/// A trusted directory is required: the path may follow symbolic links.
pub fn open(path: &Path, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    Ok(open_with_digest(path, password)?.plaintext)
}

/// Atomically replace an existing encrypted file via synced same-directory
/// temporary file, succeeding only if the current file's SHA-256 matches
/// `expected_sha256` and decrypts under `password`. Returns the new SHA-256.
pub fn replace_if_unchanged(
    path: &Path,
    expected_sha256: &[u8; 32],
    password: &[u8],
    plaintext: &[u8],
) -> Result<[u8; 32], StorageError> {
    let new_ciphertext = envelope::seal(password, plaintext)?;
    let new_digest: [u8; 32] = Sha256::digest(&new_ciphertext).into();
    let _guard = acquire_update_lock(path)?;
    let current = read_ciphertext(path)?;
    let current_digest: [u8; 32] = Sha256::digest(&current).into();
    if current_digest.ct_eq(expected_sha256).unwrap_u8() != 1 {
        return Err(StorageError::Conflict);
    }
    // Verify the caller actually knows the current password before replacing.
    let _ = envelope::open(password, &current)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent_dir(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(&new_ciphertext)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| StorageError::Io(error.error))?;
    Ok(new_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn create_open_and_never_replace_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.hnv");
        create(&path, b"test password", b"private phrase").unwrap();
        let original = fs::read(&path).unwrap();
        assert!(!original
            .windows(b"private phrase".len())
            .any(|w| w == b"private phrase"));
        assert_eq!(&open(&path, b"test password").unwrap()[..], b"private phrase");
        assert!(matches!(
            open(&path, b"bad password"),
            Err(StorageError::Envelope(EnvelopeError::AuthenticationFailed))
        ));
        assert!(matches!(
            create(&path, b"test password", b"replacement"),
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn compare_and_swap_update_rejects_stale_digest_and_wrong_password() {
        use std::sync::{Arc, Barrier};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.hnv");
        let base_digest = create_with_digest(&path, b"secret-pw", b"v1").unwrap();
        let opened = open_with_digest(&path, b"secret-pw").unwrap();
        assert_eq!(opened.ciphertext_sha256, base_digest);
        assert!(matches!(
            replace_if_unchanged(&path, &base_digest, b"wrong-pw", b"v2"),
            Err(StorageError::Envelope(EnvelopeError::AuthenticationFailed))
        ));
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [b"v2-a".as_slice(), b"v2-b".as_slice()]
            .into_iter()
            .map(|payload| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    replace_if_unchanged(&path, &base_digest, b"secret-pw", payload)
                })
            })
            .collect();
        let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|r| matches!(r, Err(StorageError::Conflict)))
                .count(),
            1
        );
        let after = open(&path, b"secret-pw").unwrap();
        assert!(&after[..] == b"v2-a" || &after[..] == b"v2-b");
    }

    #[test]
    fn oversized_and_non_regular_files_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            open(directory.path(), b"password"),
            Err(StorageError::Io(_))
        ));
        let path = directory.path().join("large");
        fs::write(&path, vec![0u8; MAX_ENVELOPE_LEN + 1]).unwrap();
        assert!(matches!(
            open(&path, b"password"),
            Err(StorageError::Envelope(EnvelopeError::TooLarge))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn opening_a_fifo_without_a_writer_is_rejected() {
        use std::process::Command;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fifo");
        assert!(Command::new("mkfifo").arg(&path).status().unwrap().success());
        assert!(matches!(
            open(&path, b"password"),
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn competing_creations_do_not_overwrite() {
        use std::sync::{Arc, Barrier};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault");
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|message| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    create(&path, b"test password", message)
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
                ))
                .count(),
            1
        );
        let value = open(&path, b"test password").unwrap();
        assert!(&value[..] == b"first" || &value[..] == b"second");
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_file_permissions_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault");
        create(&path, b"test password", b"private").unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o077,
            0
        );
    }
}
