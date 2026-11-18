#![deny(unsafe_code)]
//! Evidence from trusted commands. This is not isolation or proof of authorship.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 16 * 1024;
const ARTIFACT_LIMIT: u64 = 64 * 1024 * 1024;
const RUN_LIMIT: Duration = Duration::from_secs(30);
const DRAIN_LIMIT: Duration = Duration::from_secs(1);

/// User-supplied command details, recorded before a run is attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub project: String,
    pub program: String,
    pub arguments: Vec<String>,
    pub artifact: String,
    pub expected_exit: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_keys: Vec<String>,
}

impl Request {
    pub fn matches(&self, evidence: &Evidence) -> bool {
        self.project == evidence.project && self.program == evidence.program
            && self.arguments == evidence.arguments && self.artifact == evidence.artifact
            && self.expected_exit == evidence.expected_exit && self.env_keys == evidence.env_keys
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub project: String,
    pub program: String,
    pub arguments: Vec<String>,
    pub artifact: String,
    pub expected_exit: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_keys: Vec<String>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// None on older records; normal completion does not attempt tree cleanup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_cleanup: Option<TimeoutCleanup>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    #[serde(default)]
    pub stdout_lossy: Option<bool>,
    #[serde(default)]
    pub stderr_lossy: Option<bool>,
    pub output_incomplete: bool,
    pub artifact_sha256: Option<String>,
    pub artifact_error: Option<String>,
    /// None for evidence recorded before pre-run observations were introduced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_before: Option<ArtifactBefore>,
}

/// What was attempted on timeout. Successful signaling is not proof that all
/// descendants stopped. A direct-child termination failure is a runner error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum TimeoutCleanup {
    NotNeeded,
    UnixProcessGroup { signal_error: Option<String> },
    DirectChild,
}

/// An observation made immediately before starting the child, not an attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactBefore {
    NotFound,
    Hashed { sha256: String },
    Unavailable { error: String },
}

/// Comparison of observed bytes; it does not establish who changed the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactChange { Appeared, Changed, Unchanged, Unavailable }

fn valid_sha256(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Evidence {
    pub fn artifact_change(&self) -> ArtifactChange {
        if !self.artifact_sha256.as_deref().is_some_and(valid_sha256) { return ArtifactChange::Unavailable; }
        if let Some(ArtifactBefore::Hashed { sha256 }) = &self.artifact_before {
            if !valid_sha256(sha256) { return ArtifactChange::Unavailable; }
        }
        match (&self.artifact_before, &self.artifact_sha256, &self.artifact_error) {
            (Some(ArtifactBefore::NotFound), Some(_), None) => ArtifactChange::Appeared,
            (Some(ArtifactBefore::Hashed { sha256 }), Some(after), None) if sha256 == after => ArtifactChange::Unchanged,
            (Some(ArtifactBefore::Hashed { .. }), Some(_), None) => ArtifactChange::Changed,
            _ => ArtifactChange::Unavailable,
        }
    }
}

#[derive(Default)]
struct Capture { bytes: Vec<u8>, truncated: bool, failed: bool }

fn drain<R: Read + Send + 'static>(mut reader: R, state: Arc<Mutex<Capture>>, done: mpsc::Sender<()>) -> io::Result<()> {
    std::thread::Builder::new().spawn(move || {
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
    })?;
    Ok(())
}

// If setting up either reader fails, terminate and reap the direct child when
// possible. Killing descendants is outside this runner's security boundary.
fn start_readers<F>(child: &mut Child, stdout: Arc<Mutex<Capture>>, stderr: Arc<Mutex<Capture>>, send: mpsc::Sender<()>, mut start: F) -> io::Result<()>
where F: FnMut(Box<dyn Read + Send>, Arc<Mutex<Capture>>, mpsc::Sender<()>) -> io::Result<()> {
    let result = (|| {
        let out = child.stdout.take().ok_or_else(|| io::Error::other("missing stdout pipe"))?;
        let err = child.stderr.take().ok_or_else(|| io::Error::other("missing stderr pipe"))?;
        start(Box::new(out), stdout, send.clone())?;
        start(Box::new(err), stderr, send)?;
        Ok(())
    })();
    if result.is_err() {
        if child.kill().is_ok() { let _ = child.wait(); }
        else { let _ = child.try_wait(); }
    }
    result
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
    let metadata = file.metadata()?;
    if !metadata.is_file() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "artifact is not a regular file")); }
    if metadata.len() > ARTIFACT_LIMIT { return Err(io::Error::new(io::ErrorKind::InvalidData, "artifact exceeds 64 MiB")); }
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

fn checked_artifact_path(project: &str, artifact: &str) -> io::Result<PathBuf> {
    let directory = Path::new(project);
    let artifact_path = Path::new(artifact);
    if !directory.is_absolute() || !directory.is_dir() || artifact_path.as_os_str().is_empty()
        || !artifact_path.components().all(|c| matches!(c, Component::Normal(_) | Component::CurDir)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "project must be an absolute directory; artifact must be a relative path without parent traversal"));
    }
    Ok(directory.join(artifact_path))
}

/// A comparison of the recorded digest to the file bytes read now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactComparison {
    pub recorded: String,
    pub current: String,
    pub matches: bool,
}

/// Re-hash the recorded artifact without executing the command or changing the
/// journal. A match is not an attestation or proof of capability. The project
/// and its directory must be trusted; symlinks are followed and concurrent
/// modification is not prevented. File contents are limited to 64 MiB.
pub fn compare_artifact(evidence: &Evidence) -> io::Result<ArtifactComparison> {
    let recorded = evidence.artifact_sha256.as_deref().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no recorded artifact hash"))?;
    if !valid_sha256(recorded) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid recorded SHA-256 hash"));
    }
    let path = checked_artifact_path(&evidence.project, &evidence.artifact)?;
    let current = artifact_hash(&path)?;
    Ok(ArtifactComparison { recorded: recorded.to_owned(), matches: recorded == current, current })
}

/// Validate explicit environment names before resolving or passing values.
/// Names are upper-case ASCII identifiers to avoid platform case ambiguities.
/// Validation cannot determine whether a value is secret.
pub fn validate_env_keys(keys: &[String]) -> io::Result<()> {
    let mut seen = std::collections::HashSet::new();
    if keys.len() > 32 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "at most 32 environment names are allowed")); }
    for key in keys {
        let valid = !key.is_empty() && key.len() <= 128 && key.bytes().enumerate().all(|(i, c)| {
            c.is_ascii_uppercase() || c == b'_' || (i > 0 && c.is_ascii_digit())
        });
        if !valid || !seen.insert(key) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "environment names must be unique uppercase ASCII identifiers"));
        }
    }
    Ok(())
}

/// Resolve explicitly selected names from the parent. Missing names are errors.
/// Values are not put into evidence, but the child can print or transmit them.
pub fn resolve_parent_environment(keys: &[String]) -> io::Result<Vec<(String, OsString)>> {
    validate_env_keys(keys)?;
    keys.iter().map(|key| std::env::var_os(key).map(|value| (key.clone(), value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("environment variable {key} is not set")))).collect()
}

/// Run a trusted program with only explicitly supplied environment entries.
/// Their names, but not values, are recorded. Never pass secrets: the program
/// and descendants can access or print them, and output is stored in plaintext.
pub fn run_with_env(project: &str, artifact: &str, expected_exit: i32, program: &str, arguments: &[String], environment: &[(String, OsString)]) -> io::Result<Evidence> {
    let keys: Vec<String> = environment.iter().map(|(key, _)| key.clone()).collect();
    validate_env_keys(&keys)?;
    run_inner(project, artifact, expected_exit, program, arguments, environment, (RUN_LIMIT, DRAIN_LIMIT))
}

/// Run a trusted executable with an empty environment. Output is drained while
/// the process runs but retained only up to 16 KiB per stream. The 30-second
/// timeout best-effort signals the Unix process group and kills the direct child;
/// elsewhere it kills only the direct child. Descendants are not contained.
/// An artifact hash is an observation of bytes read after exit, not attestation.
pub fn run(project: &str, artifact: &str, expected_exit: i32, program: &str, arguments: &[String]) -> io::Result<Evidence> {
    run_with_env(project, artifact, expected_exit, program, arguments, &[])
}

// The leader has not been reaped since the last try_wait returned None. Signal
// before waiting, so its PID cannot be recycled into an unrelated group. Never
// use group ID 1: kill(-1, ...) has system-wide semantics on Unix.
#[cfg(unix)]
fn signal_group(child: &Child) -> io::Result<()> {
    use rustix::process::{kill_process_group, Pid, Signal};
    let raw = i32::try_from(child.id()).map_err(|_| io::Error::other("child PID out of range"))?;
    if raw <= 1 { return Err(io::Error::other("invalid child process group ID")); }
    let pid = Pid::from_raw(raw).ok_or_else(|| io::Error::other("invalid child process group ID"))?;
    kill_process_group(pid, Signal::KILL).map_err(io::Error::from)
}

// Always also kill the direct child: it may have escaped the original group.
// If kill races with exit, reap it; otherwise report failure without waiting on
// a potentially still-running child. Include the group error in that failure.
fn timeout_child<F>(child: &mut Child, cleanup: F) -> io::Result<(std::process::ExitStatus, TimeoutCleanup)>
where F: FnOnce(&Child) -> TimeoutCleanup {
    let outcome = cleanup(child);
    if let Err(error) = child.kill() {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, outcome)),
            Ok(None) => return Err(io::Error::other(format!("direct child termination failed: {error}; timeout cleanup: {outcome:?}"))),
            Err(wait_error) => return Err(io::Error::other(format!("direct child termination failed: {error}; status check failed: {wait_error}; timeout cleanup: {outcome:?}"))),
        }
    }
    let status = child.wait().map_err(|error| io::Error::other(format!("direct child wait failed: {error}; timeout cleanup: {outcome:?}")))?;
    Ok((status, outcome))
}

fn run_inner(project: &str, artifact: &str, expected_exit: i32, program: &str, arguments: &[String], environment: &[(String, OsString)], limits: (Duration, Duration)) -> io::Result<Evidence> {
    let directory = Path::new(project);
    let executable = Path::new(program);
    if !executable.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "program must be an absolute path"));
    }
    let artifact_path = checked_artifact_path(project, artifact)?;
    let artifact_before = match artifact_hash(&artifact_path) {
        Ok(sha256) => ArtifactBefore::Hashed { sha256 },
        Err(error) if error.kind() == io::ErrorKind::NotFound => ArtifactBefore::NotFound,
        Err(error) => ArtifactBefore::Unavailable { error: error.to_string() },
    };
    let mut command = Command::new(executable);
    command.args(arguments).current_dir(directory).env_clear()
        .envs(environment.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let stdout = Arc::new(Mutex::new(Capture::default()));
    let stderr = Arc::new(Mutex::new(Capture::default()));
    let (send, recv) = mpsc::channel();
    start_readers(&mut child, Arc::clone(&stdout), Arc::clone(&stderr), send, drain)?;
    let deadline = Instant::now() + limits.0;
    let (status, timed_out, timeout_cleanup) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false, TimeoutCleanup::NotNeeded),
            Ok(None) if Instant::now() >= deadline => {
                let (status, cleanup) = timeout_child(&mut child, |child| {
                    #[cfg(unix)]
                    { TimeoutCleanup::UnixProcessGroup { signal_error: signal_group(child).err().map(|error| error.to_string()) } }
                    #[cfg(not(unix))]
                    { let _ = child; TimeoutCleanup::DirectChild }
                })?;
                break (status, true, cleanup);
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
    // Snapshot output and release both locks before file I/O; descendants may
    // still be writing to their pipes and readers must remain able to drain.
    let (stdout_text, stdout_truncated, stdout_failed, stdout_lossy) = {
        let capture = stdout.lock().unwrap_or_else(|e| e.into_inner());
        (String::from_utf8_lossy(&capture.bytes).into_owned(), capture.truncated, capture.failed, std::str::from_utf8(&capture.bytes).is_err())
    };
    let (stderr_text, stderr_truncated, stderr_failed, stderr_lossy) = {
        let capture = stderr.lock().unwrap_or_else(|e| e.into_inner());
        (String::from_utf8_lossy(&capture.bytes).into_owned(), capture.truncated, capture.failed, std::str::from_utf8(&capture.bytes).is_err())
    };
    let hash = artifact_hash(&artifact_path);
    let (artifact_sha256, artifact_error) = match hash { Ok(hash) => (Some(hash), None), Err(error) => (None, Some(error.to_string())) };
    Ok(Evidence {
        project: project.into(), program: program.into(), arguments: arguments.to_vec(), artifact: artifact.into(), expected_exit,
        env_keys: environment.iter().map(|(key, _)| key.clone()).collect(),
        exit_code: status.code(), timed_out, timeout_cleanup: Some(timeout_cleanup),
        stdout: stdout_text, stderr: stderr_text,
        stdout_truncated, stderr_truncated,
        stdout_lossy: Some(stdout_lossy), stderr_lossy: Some(stderr_lossy),
        output_incomplete: finished != 2 || stdout_failed || stderr_failed,
        artifact_sha256, artifact_error, artifact_before: Some(artifact_before),
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
    fn artifact_observations_compare_before_and_after_without_claiming_authorship() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().to_str().unwrap();
        let command = |script: &str| run(project, "artifact", 0, "/bin/sh", &["-c".into(), script.into()]).unwrap();
        let appeared = command("printf first > artifact");
        assert_eq!(appeared.artifact_before, Some(ArtifactBefore::NotFound));
        assert_eq!(appeared.artifact_change(), ArtifactChange::Appeared);
        let unchanged = command("exit 0");
        assert!(matches!(unchanged.artifact_before, Some(ArtifactBefore::Hashed { .. })));
        assert_eq!(unchanged.artifact_change(), ArtifactChange::Unchanged);
        let changed = command("printf second > artifact");
        assert_eq!(changed.artifact_change(), ArtifactChange::Changed);
        let removed = command("/bin/rm artifact");
        assert_eq!(removed.artifact_change(), ArtifactChange::Unavailable);
        let missing = command("exit 0");
        assert_eq!(missing.artifact_before, Some(ArtifactBefore::NotFound));
        assert_eq!(missing.artifact_change(), ArtifactChange::Unavailable);
        std::fs::File::create(dir.path().join("artifact")).unwrap().set_len(ARTIFACT_LIMIT + 1).unwrap();
        let large_before = command("printf small > artifact");
        assert!(matches!(large_before.artifact_before, Some(ArtifactBefore::Unavailable { .. })));
        assert_eq!(large_before.artifact_change(), ArtifactChange::Unavailable);
        std::fs::File::create(dir.path().join("artifact")).unwrap().set_len(ARTIFACT_LIMIT + 1).unwrap();
        let large_after = command("exit 0");
        assert!(large_after.artifact_error.is_some());
        assert_eq!(large_after.artifact_change(), ArtifactChange::Unavailable);
    }
    #[cfg(unix)]
    #[test]
    fn symlink_observations_follow_targets_without_proving_file_creation() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        symlink("target", dir.path().join("artifact")).unwrap();
        let project = dir.path().to_str().unwrap();
        let run_script = |script: &str| run(project, "artifact", 0, "/bin/sh", &["-c".into(), script.into()]).unwrap();
        let result = run_script("printf content > artifact");
        assert_eq!(result.artifact_before, Some(ArtifactBefore::NotFound));
        assert_eq!(result.artifact_change(), ArtifactChange::Appeared);
        assert!(std::fs::symlink_metadata(dir.path().join("artifact")).unwrap().file_type().is_symlink());
        std::fs::write(dir.path().join("other"), b"different").unwrap();
        let result = run_script("/bin/ln -sf other artifact");
        assert_eq!(result.artifact_change(), ArtifactChange::Changed);
    }
    #[test]
    fn oversized_artifact_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large");
        std::fs::File::create(&path).unwrap().set_len(ARTIFACT_LIMIT + 1).unwrap();
        assert_eq!(artifact_hash(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
    #[cfg(unix)]
    #[test]
    fn artifact_fifo_without_writer_is_rejected_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        assert!(Command::new("mkfifo").arg(&path).status().unwrap().success());
        assert_eq!(artifact_hash(&path).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
    #[cfg(unix)]
    #[test]
    fn compares_recorded_hash_without_reexecuting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"abc").unwrap();
        let mut evidence = run(dir.path().to_str().unwrap(), "artifact", 0, "/bin/sh", &["-c".into(), "exit 0".into()]).unwrap();
        assert!(compare_artifact(&evidence).unwrap().matches);
        std::fs::write(&path, b"changed").unwrap();
        let changed = compare_artifact(&evidence).unwrap();
        assert!(!changed.matches);
        assert_ne!(changed.recorded, changed.current);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(compare_artifact(&evidence).unwrap_err().kind(), io::ErrorKind::NotFound);
        evidence.artifact_sha256 = None;
        assert_eq!(compare_artifact(&evidence).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        evidence.artifact_sha256 = Some("not-a-hash".into());
        assert_eq!(compare_artifact(&evidence).unwrap_err().kind(), io::ErrorKind::InvalidData);
        evidence.artifact_sha256 = Some("0".repeat(64));
        evidence.artifact = "../outside".into();
        assert_eq!(compare_artifact(&evidence).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
    #[cfg(unix)]
    #[test]
    fn invalid_utf8_is_marked_as_lossy() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(dir.path().to_str().unwrap(), "missing", 0, "/bin/sh", &["-c".into(), "printf '\\377'; printf normal >&2".into()]).unwrap();
        assert_eq!(result.stdout_lossy, Some(true));
        assert_eq!(result.stderr_lossy, Some(false));
        assert_eq!(result.stdout, "\u{fffd}");
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
    fn reader_setup_failure_stops_and_reaps_direct_child() {
        for failing_call in [1, 2] {
            let mut child = Command::new("/bin/sleep").arg("30").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            let (send, _recv) = mpsc::channel();
            let mut calls = 0;
            let result = start_readers(&mut child, Arc::new(Mutex::new(Capture::default())), Arc::new(Mutex::new(Capture::default())), send,
                |reader, state, sender| {
                    calls += 1;
                    if calls == failing_call { Err(io::Error::other("simulated thread creation failure")) }
                    else { drain(reader, state, sender) }
                });
            assert!(result.is_err());
            assert!(child.try_wait().unwrap().is_some());
        }
    }
    #[cfg(unix)]
    #[test]
    fn timeout_reaps_direct_child_and_records_missing_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let result = run_inner(dir.path().to_str().unwrap(), "missing", 0, "/bin/sleep", &["10".into()], &[], (Duration::from_millis(100), Duration::from_secs(1))).unwrap();
        assert!(result.timed_out);
        assert_ne!(result.exit_code, Some(0));
        assert!(result.artifact_error.is_some());
    }
    #[cfg(unix)]
    #[test]
    fn timeout_records_group_failure_but_still_reaps_direct_child() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let (status, cleanup) = timeout_child(&mut child, |_| TimeoutCleanup::UnixProcessGroup { signal_error: Some("simulated failure".into()) }).unwrap();
        assert!(!status.success());
        assert_eq!(cleanup, TimeoutCleanup::UnixProcessGroup { signal_error: Some("simulated failure".into()) });
        assert!(child.try_wait().unwrap().is_some());
    }
    #[cfg(unix)]
    #[test]
    fn timeout_signals_group_including_grandchild() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().to_str().unwrap().to_owned();
        // The descendant signals readiness and waits for release. If cleanup
        // fails it can exit itself, so a test failure cannot leave a long orphan.
        let script = "(printf ready > ready; n=0; while [ ! -f release ] && [ $n -lt 100 ]; do /bin/sleep 0.1; n=$((n+1)); done; if [ -f release ]; then printf survived > survived; fi) & wait";
        let thread = std::thread::spawn(move || run_inner(&project, "missing", 0, "/bin/sh", &["-c".into(), script.into()], &[], (Duration::from_secs(3), Duration::from_secs(2))).unwrap());
        let deadline = Instant::now() + Duration::from_secs(2);
        while !dir.path().join("ready").exists() && Instant::now() < deadline { std::thread::sleep(Duration::from_millis(20)); }
        let ready = dir.path().join("ready").exists();
        let result = thread.join().unwrap();
        std::fs::write(dir.path().join("release"), b"release").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(ready, "grandchild did not become ready before timeout");
        assert!(result.timed_out);
        assert_eq!(result.timeout_cleanup, Some(TimeoutCleanup::UnixProcessGroup { signal_error: None }));
        assert!(!result.output_incomplete, "descendant retained output pipes");
        assert!(!dir.path().join("survived").exists(), "grandchild survived cleanup");
    }
    #[cfg(unix)]
    #[test]
    fn inherited_pipes_do_not_block_the_runner_indefinitely() {
        let dir = tempfile::tempdir().unwrap();
        let result = run_inner(dir.path().to_str().unwrap(), "missing", 0, "/bin/sh", &["-c".into(), "/bin/sleep 2 &".into()], &[], (Duration::from_secs(5), Duration::from_millis(100))).unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.timeout_cleanup, Some(TimeoutCleanup::NotNeeded));
        assert!(result.output_incomplete);
    }
    #[test]
    fn environment_names_are_bounded_unique_and_portable() {
        for keys in [vec!["BAD-NAME".into()], vec!["lower".into()], vec!["1NAME".into()], vec!["A".into(), "A".into()], vec!["A".repeat(129)], (0..33).map(|n| format!("KEY_{n}")).collect()] {
            assert!(validate_env_keys(&keys).is_err());
        }
        assert!(validate_env_keys(&["PATH".into(), "HENOSIS_1".into()]).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn only_explicit_environment_is_passed_and_values_not_in_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let environment = vec![("HENOSIS_EXPLICIT".into(), OsString::from("example-value-not-for-recording"))];
        let args = vec!["-c".into(), "test -n \"$HENOSIS_EXPLICIT\" && test -z \"${HENOSIS_UNSELECTED+x}\"".into()];
        let result = run_with_env(dir.path().to_str().unwrap(), "missing", 0, "/bin/sh", &args, &environment).unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.env_keys, vec!["HENOSIS_EXPLICIT"]);
        assert!(!format!("{result:?}").contains("example-value-not-for-recording"));
        let default = run(dir.path().to_str().unwrap(), "missing", 0, "/bin/sh", &["-c".into(), "test -z \"${HENOSIS_EXPLICIT+x}\"".into()]).unwrap();
        assert_eq!(default.exit_code, Some(0));
        assert!(default.env_keys.is_empty());
    }
    #[test]
    fn rejects_unsafe_paths_before_execution() {
        let dir = tempfile::tempdir().unwrap();
        assert!(run(dir.path().to_str().unwrap(), "../outside", 0, "/program", &[]).is_err());
        assert!(run(dir.path().to_str().unwrap(), "artifact", 0, "relative", &[]).is_err());
    }
}
