//! Create-only persistence for encrypted envelopes in a trusted directory.
//!
//! Writes go to a same-directory temporary file, are synced, then published
//! without replacing an existing destination. No plaintext is written. This does
//! not protect against an attacker who can modify the directory, backups, or
//! replace the file later; rollback detection and directory fsync are absent.
//! Platform filesystems may not support no-clobber publication. Temporary encrypted
//! files can remain after a crash. Unix temporary files use restrictive permissions;
//! Windows permissions depend on directory ACLs. Callers must secure the directory.

use crate::envelope::{self, EnvelopeError, HEADER_LEN, MAX_PLAINTEXT_LEN, TAG_LEN};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

const MAX_ENVELOPE_LEN: usize = HEADER_LEN + MAX_PLAINTEXT_LEN + TAG_LEN;

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Envelope(EnvelopeError),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "vault file error: {error}"),
            Self::Envelope(error) => write!(f, "vault envelope error: {error}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Io(error) => Some(error), Self::Envelope(error) => Some(error) }
    }
}

impl From<io::Error> for StorageError {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}

impl From<EnvelopeError> for StorageError {
    fn from(value: EnvelopeError) -> Self { Self::Envelope(value) }
}

/// Create a new encrypted file without overwriting an existing path.
/// The parent directory must already exist and be controlled by the user.
/// This is deliberately not an update or password-change operation.
pub fn create(path: &Path, password: &[u8], plaintext: &[u8]) -> Result<(), StorageError> {
    let ciphertext = envelope::seal(password, plaintext)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&ciphertext)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path).map_err(|error| StorageError::Io(error.error))?;
    Ok(())
}

// Opening a FIFO for reading ordinarily blocks before we can inspect its type.
// O_NONBLOCK allows fstat to reject FIFOs even when no writer is present.
#[cfg(unix)]
fn open_for_read(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)
}

#[cfg(not(unix))]
fn open_for_read(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Read and decrypt a regular file, with a bound applied before allocation.
/// A trusted directory is required: the path may follow symbolic links.
pub fn open(path: &Path, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let file = open_for_read(path)?;
    if !file.metadata()?.is_file() {
        return Err(StorageError::Io(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file")));
    }
    let mut data = Vec::new();
    file.take((MAX_ENVELOPE_LEN + 1) as u64).read_to_end(&mut data)?;
    if data.len() > MAX_ENVELOPE_LEN { return Err(StorageError::Envelope(EnvelopeError::TooLarge)); }
    Ok(envelope::open(password, &data)?)
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
        assert!(!original.windows(b"private phrase".len()).any(|w| w == b"private phrase"));
        assert_eq!(&open(&path, b"test password").unwrap()[..], b"private phrase");
        assert!(matches!(open(&path, b"bad password"), Err(StorageError::Envelope(EnvelopeError::AuthenticationFailed))));
        assert!(matches!(create(&path, b"test password", b"replacement"), Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists));
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn oversized_and_non_regular_files_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(open(directory.path(), b"password"), Err(StorageError::Io(_))));
        let path = directory.path().join("large");
        fs::write(&path, vec![0u8; MAX_ENVELOPE_LEN + 1]).unwrap();
        assert!(matches!(open(&path, b"password"), Err(StorageError::Envelope(EnvelopeError::TooLarge))));
    }

    #[cfg(unix)]
    #[test]
    fn opening_a_fifo_without_a_writer_is_rejected() {
        use std::process::Command;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fifo");
        assert!(Command::new("mkfifo").arg(&path).status().unwrap().success());
        assert!(matches!(open(&path, b"password"), Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput));
    }

    #[test]
    fn competing_creations_do_not_overwrite() {
        use std::sync::{Arc, Barrier};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault");
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [b"first".as_slice(), b"second".as_slice()].into_iter().map(|message| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                create(&path, b"test password", message)
            })
        }).collect();
        let results: Vec<_> = threads.into_iter().map(|thread| thread.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| matches!(result, Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists)).count(), 1);
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
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
    }
}
