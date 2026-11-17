#![deny(unsafe_code)]
//! Evidence from trusted commands. This is not isolation or proof of authorship.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 16 * 1024;
const ARTIFACT_LIMIT: u64 = 64 * 1024 * 1024;
const RUN_LIMIT: Duration = Duration::from_secs(30);
const DRAIN_LIMIT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub project: String,
    pub program: String,
    pub arguments: Vec<String>,
    pub artifact: String,
    pub expected_exit: i32,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub output_incomplete: bool,
    pub artifact_sha256: Option<String>,
    pub artifact_error: Option<String>,
}

#[derive(Default)]
struct Capture { bytes: Vec<u8>, truncated: bool, failed: bool }

fn drain<R: Read + Send + 'static>(mut reader: R, state: Arc<Mutex<Capture>>, done: mpsc::Sender<()>) {
    std::thread::spawn(move || {
        let mut buffer = [0; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let mut capture = state.lock().unwrap_or_else(|e| e.into_inner());
                    let keep = n.min(OUTPUT_LIMIT.saturating_sub(capture.bytes.len()));
                    capture.bytes.extend_from_slice(&buffer[..keep]);
                    capture.truncated |= keep < n;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => { state.lock().unwrap_or_else(|e| e.into_inner()).failed = true; break; }
            }
        }
        let _ = done.send(());
    });
}

fn artifact_hash(path: &Path) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "artifact is not a regular file")); }
    let mut reader = file.take(ARTIFACT_LIMIT + 1);
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 { break; }
        count += n as u64;
        if count > ARTIFACT_LIMIT { return Err(io::Error::new(io::ErrorKind::InvalidData, "artifact exceeds 64 MiB")); }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Run a trusted executable with an empty environment. Output is drained while
/// the process runs but retained only up to 16 KiB per stream. The 30-second
/// timeout kills the direct child only. Descendants are not contained.
/// An artifact hash is an observation of bytes read after exit, not attestation.
pub fn run(project: &str, artifact: &str, expected_exit: i32, program: &str, arguments: &[String]) -> io::Result<Evidence> {
    run_inner(project, artifact, expected_exit, program, arguments, (RUN_LIMIT, DRAIN_LIMIT))
}

fn run_inner(project: &str, artifact: &str, expected_exit: i32, program: &str, arguments: &[String], limits: (Duration, Duration)) -> io::Result<Evidence> {
    let directory = Path::new(project);
    let executable = Path::new(program);
    let artifact_path = Path::new(artifact);
    if !directory.is_absolute() || !directory.is_dir() || !executable.is_absolute()
        || artifact_path.as_os_str().is_empty() || !artifact_path.components().all(|c| matches!(c, Component::Normal(_) | Component::CurDir)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "project and program must be absolute; artifact must be a relative path without parent traversal"));
    }
    let mut child = Command::new(executable).args(arguments).current_dir(directory).env_clear()
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let stdout = Arc::new(Mutex::new(Capture::default()));
    let stderr = Arc::new(Mutex::new(Capture::default()));
    let (send, recv) = mpsc::channel();
    drain(child.stdout.take().expect("piped stdout"), Arc::clone(&stdout), send.clone());
    drain(child.stderr.take().expect("piped stderr"), Arc::clone(&stderr), send);
    let deadline = Instant::now() + limits.0;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() >= deadline => {
                if let Err(error) = child.kill() {
                    if let Some(status) = child.try_wait()? { break (status, false); }
                    return Err(error);
                }
                break (child.wait()?, true);
            },
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => { let _ = child.kill(); let _ = child.wait(); return Err(error); }
        }
    };
    // A descendant can keep inherited pipes open after the direct child exits.
    // Do not wait forever; detached readers may persist until those pipes close.
    let deadline = Instant::now() + limits.1;
    let mut finished = 0;
    while finished < 2 {
        match recv.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(()) => finished += 1,
            Err(_) => break,
        }
    }
    let stdout = stdout.lock().unwrap_or_else(|e| e.into_inner());
    let stderr = stderr.lock().unwrap_or_else(|e| e.into_inner());
    let hash = artifact_hash(&directory.join(artifact_path));
    let (artifact_sha256, artifact_error) = match hash { Ok(hash) => (Some(hash), None), Err(error) => (None, Some(error.to_string())) };
    Ok(Evidence {
        project: project.into(), program: program.into(), arguments: arguments.to_vec(), artifact: artifact.into(), expected_exit,
        exit_code: status.code(), timed_out,
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(), stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
        stdout_truncated: stdout.truncated, stderr_truncated: stderr.truncated,
        output_incomplete: finished != 2 || stdout.failed || stderr.failed,
        artifact_sha256, artifact_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn records_exit_output_and_artifact_hash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("artifact"), b"abc").unwrap();
        let result = run(dir.path().to_str().unwrap(), "artifact", 3, "/bin/sh", &["-c".into(), "printf hello; printf error >&2; exit 3".into()]).unwrap();
        assert_eq!(result.exit_code, Some(3));
        assert_eq!(result.stdout, "hello");
        assert_eq!(result.stderr, "error");
        assert_eq!(result.artifact_sha256.as_deref(), Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        assert!(!result.output_incomplete);
    }
    #[cfg(unix)]
    #[test]
    fn output_is_capped_but_process_can_finish_and_missing_artifact_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(dir.path().to_str().unwrap(), "missing", 0, "/bin/sh", &["-c".into(), "while :; do printf 1234567890; done | /usr/bin/head -c 40000".into()]).unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout.len(), OUTPUT_LIMIT);
        assert!(result.stdout_truncated);
        assert!(result.artifact_sha256.is_none());
        assert!(result.artifact_error.is_some());
    }
    #[cfg(unix)]
    #[test]
    fn timeout_reaps_direct_child_and_records_missing_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let result = run_inner(dir.path().to_str().unwrap(), "missing", 0, "/bin/sleep", &["10".into()], (Duration::from_millis(100), Duration::from_secs(1))).unwrap();
        assert!(result.timed_out);
        assert_ne!(result.exit_code, Some(0));
        assert!(result.artifact_error.is_some());
    }
    #[cfg(unix)]
    #[test]
    fn inherited_pipes_do_not_block_the_runner_indefinitely() {
        let dir = tempfile::tempdir().unwrap();
        let result = run_inner(dir.path().to_str().unwrap(), "missing", 0, "/bin/sh", &["-c".into(), "/bin/sleep 2 &".into()], (Duration::from_secs(5), Duration::from_millis(100))).unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert!(result.output_incomplete);
    }
    #[test]
    fn rejects_unsafe_paths_before_execution() {
        let dir = tempfile::tempdir().unwrap();
        assert!(run(dir.path().to_str().unwrap(), "../outside", 0, "/program", &[]).is_err());
        assert!(run(dir.path().to_str().unwrap(), "artifact", 0, "relative", &[]).is_err());
    }
}
