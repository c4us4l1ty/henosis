use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn shell(directory: &Path, input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .current_dir(directory).env("HENOSIS_DEMO_FACTOR", "00003").env("HENOSIS_UNSELECTED", "not-selected")
        .env_remove("HENOSIS_TEST_MISSING_FOR_RUNENV").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {}", path.display());
        std::thread::sleep(Duration::from_millis(20));
    }
}

// Release a paused sample even if an assertion fails, so an orphan cannot hang.
struct ReleaseOnDrop(std::path::PathBuf);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) { let _ = std::fs::write(&self.0, b"release"); }
}

#[test]
fn sample_project_evidence_and_interruption_workflow() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("main.rs");
    let binary = dir.path().join(format!("double-number{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(&source, include_str!("../../../examples/double-number/main.rs")).unwrap();
    std::fs::write(dir.path().join("input.txt"), include_str!("../../../examples/double-number/input.txt")).unwrap();
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc).arg("--edition=2021").arg(&source).arg("-o").arg(&binary).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    // Backslashes are shell escapes on the runner side; normalize so the quoted
    // path survives shell_words::split on every platform (mirrors the other
    // shell integration tests).
    let project = format!("\"{}\"", dir.path().to_str().unwrap().replace('\\', "/"));
    let executable = format!("\"{}\"", binary.to_str().unwrap().replace('\\', "/"));
    let commands = format!("propose journal.jsonl goal hypothesis test\nrun journal.jsonl 1 {project} result.txt 0 {executable}\nshow journal.jsonl 1\ncompare journal.jsonl 3\nexit\n");
    let output = shell(dir.path(), &commands);
    assert!(output.status.success());
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("COMMAND RESULT for 1 (not a verified capability)"), "{text}");
    assert!(text.contains("Match: true"), "{text}");
    assert!(text.contains("Timeout cleanup: not attempted (no timeout)"), "{text}");
    assert!(text.contains("Artifact before: not found  Comparison: APPEARED"), "{text}");
    assert!(text.contains("result 3: MATCH"), "{text}");
    assert_eq!(std::fs::read(dir.path().join("result.txt")).unwrap(), b"14\n");
    std::fs::write(dir.path().join("result.txt"), b"changed\n").unwrap();
    let changed = shell(dir.path(), "compare journal.jsonl 3\nexit\n");
    assert!(changed.status.success());
    assert!(String::from_utf8(changed.stdout).unwrap().contains("result 3: DIFFERENT"));
    let _release = ReleaseOnDrop(dir.path().join("release.marker"));
    let mut workspace = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .current_dir(dir.path()).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    workspace.stdin.as_mut().unwrap().write_all(format!("run journal.jsonl 1 {project} result.txt 0 {executable} --pause\n").as_bytes()).unwrap();
    wait_for(&dir.path().join("started.marker"));
    workspace.kill().unwrap();
    workspace.wait().unwrap();
    let pending = shell(dir.path(), "pending journal.jsonl\nexit\n");
    assert!(pending.status.success());
    assert!(String::from_utf8(pending.stdout).unwrap().contains("Attempt 4 for proposal 1: outcome not recorded"));
    let review = shell(dir.path(), "review journal.jsonl 4 \"Inspected; sample may still be running\"\npending journal.jsonl\nshow journal.jsonl 1\nexit\n");
    assert!(review.status.success());
    assert!(review.stderr.is_empty(), "{}", String::from_utf8_lossy(&review.stderr));
    let review_text = String::from_utf8(review.stdout).unwrap();
    assert!(review_text.contains("outcome remains unknown"), "{review_text}");
    assert!(review_text.contains("USER REVIEW for proposal 1, attempt 4 (not a command result)"), "{review_text}");
    std::fs::write(dir.path().join("release.marker"), b"release").unwrap();
    wait_for(&dir.path().join("finished.marker"));
    assert_eq!(std::fs::read(dir.path().join("result.txt")).unwrap(), b"14\n");
    let commands = format!("runenv journal.jsonl 1 {project} result.txt 0 HENOSIS_DEMO_FACTOR {executable} --factor-env\nshow journal.jsonl 1\nexit\n");
    let env_run = shell(dir.path(), &commands);
    assert!(env_run.status.success());
    assert!(env_run.stderr.is_empty(), "{}", String::from_utf8_lossy(&env_run.stderr));
    let output = String::from_utf8(env_run.stdout).unwrap();
    assert!(output.contains("HENOSIS_DEMO_FACTOR"), "{output}");
    assert!(output.contains("Comparison: CHANGED"), "{output}");
    assert!(output.contains("Match: true"), "{output}");
    assert_eq!(std::fs::read(dir.path().join("result.txt")).unwrap(), b"21\n");
    let journal = std::fs::read_to_string(dir.path().join("journal.jsonl")).unwrap();
    assert!(!journal.contains("00003"), "environment value was recorded");
    assert!(!journal.contains("not-selected"), "unselected value was recorded");
    let before = henosis_crux::read(&dir.path().join("journal.jsonl")).unwrap().len();
    let invalid = format!("runenv journal.jsonl 1 {project} result.txt 0 HENOSIS_TEST_MISSING_FOR_RUNENV {executable} --factor-env\nrunenv journal.jsonl 1 {project} result.txt 0 HENOSIS_DEMO_FACTOR,HENOSIS_DEMO_FACTOR {executable} --factor-env\nexit\n");
    let bad = shell(dir.path(), &invalid);
    assert_eq!(String::from_utf8(bad.stderr).unwrap().matches("environment selection failed").count(), 2);
    assert_eq!(henosis_crux::read(&dir.path().join("journal.jsonl")).unwrap().len(), before);
}
