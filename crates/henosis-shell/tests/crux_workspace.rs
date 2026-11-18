use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn workspace_records_assesses_and_ranks_proposals() {
    let directory = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .current_dir(directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn().unwrap();
    let input = concat!(
        "propose crux.jsonl \"Build a prototype\" \"Heat is the bottleneck\" \"Measure heat\"\n",
        "propose crux.jsonl \"Build a prototype\" \"Cost is the bottleneck\" \"Measure cost\"\n",
        "assess crux.jsonl 1 5 4 2\n",
        "assess crux.jsonl 2 2 2 4\n",
        "observe crux.jsonl 1 \"Heat is acceptable\"\n",
        "rank crux.jsonl\n",
        "journal crux.jsonl\n",
        "exit\n",
    );
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("1  score=10.00"), "{stdout}");
    assert!(stdout.contains("2  score=1.00"), "{stdout}");
    assert!(stdout.contains("OBSERVATION for 1"), "{stdout}");
    assert!(stdout.contains("ASSESSMENT for 1"), "{stdout}");
    let events = henosis_crux::read(&directory.path().join("crux.jsonl")).unwrap();
    assert_eq!(events.len(), 5);
}

#[test]
fn journal_content_cannot_inject_terminal_control_sequences() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("crux.jsonl");
    henosis_crux::append(&path, henosis_crux::Event::Proposed {
        goal: "safe\x1b[2J".into(), hypothesis: "line\nnext".into(), test: "test".into(),
    }).unwrap();
    henosis_crux::append(&path, henosis_crux::Event::Assessed {
        proposal: 1, information: 1, failure: 1, cost: 1,
    }).unwrap();
    henosis_crux::append(&path, henosis_crux::Event::Observed {
        proposal: 1, outcome: "\x1b]0;unsafe\x07".into(),
    }).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .current_dir(directory.path()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"journal crux.jsonl\nrank crux.jsonl\nexit\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains('\x1b'));
    assert!(!stdout.contains('\x07'));
    assert!(stdout.contains(r"safe\u{1b}[2J"), "{stdout}");
    assert!(stdout.contains(r"line\nnext"), "{stdout}");
}

#[test]
fn show_selects_only_the_requested_proposal_history() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("crux.jsonl");
    for goal in ["first goal", "second goal"] {
        henosis_crux::append(&path, henosis_crux::Event::Proposed {
            goal: goal.into(), hypothesis: "hypothesis".into(), test: "test".into(),
        }).unwrap();
    }
    henosis_crux::append(&path, henosis_crux::Event::Observed { proposal: 2, outcome: "second outcome".into() }).unwrap();
    henosis_crux::append(&path, henosis_crux::Event::Observed { proposal: 1, outcome: "first outcome".into() }).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .current_dir(directory.path()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"show crux.jsonl 1\nshow crux.jsonl 3\nexit\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("first goal"));
    assert!(stdout.contains("first outcome"));
    assert!(!stdout.contains("second goal"));
    assert!(!stdout.contains("second outcome"));
    assert!(stderr.contains("No proposal with ID 3"));
}

#[test]
fn workspace_closes_and_reopens_a_proposal() {
    let directory = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .current_dir(directory.path()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(concat!(
        "propose crux.jsonl goal hypothesis test\n",
        "assess crux.jsonl 1 5 4 2\n",
        "close crux.jsonl 1 \"Test finished\"\n",
        "rank crux.jsonl\n",
        "reopen crux.jsonl 1 \"New evidence\"\n",
        "rank crux.jsonl\n",
        "show crux.jsonl 1\n",
        "exit\n",
    ).as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("No open, assessed proposals."), "{stdout}");
    assert_eq!(stdout.matches("1  score=10.00").count(), 1, "{stdout}");
    assert!(stdout.contains("CLOSED proposal 1"));
    assert!(stdout.contains("REOPENED proposal 1"));
}

#[cfg(unix)]
#[test]
fn process_list_escapes_executable_names() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sleep\x1b[2J");
    std::os::unix::fs::symlink("/bin/sleep", &path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let input = format!("launch \"{}\" 30\nlist\nexit\n", path.display());
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains('\x1b'), "{stdout}");
    assert!(stdout.contains(r"sleep\u{1b}[2J"), "{stdout}");
}

#[test]
fn workspace_backup_is_create_only_and_readable() {
    let directory = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .current_dir(directory.path()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(concat!(
        "propose crux.jsonl goal hypothesis test\n",
        "backup crux.jsonl backup.jsonl\n",
        "propose crux.jsonl second other test\n",
        "backup crux.jsonl backup.jsonl\n",
        "exit\n",
    ).as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("Backed up 1 events (plaintext)."), "{stdout}");
    assert!(stderr.contains("Could not back up journal:"), "{stderr}");
    assert_eq!(henosis_crux::read(&directory.path().join("backup.jsonl")).unwrap().len(), 1);
    assert_eq!(henosis_crux::read(&directory.path().join("crux.jsonl")).unwrap().len(), 2);
}

#[test]
fn trusted_experiment_is_recorded_and_visible_in_proposal_history() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("artifact"), b"abc").unwrap();
    let project = directory.path().to_str().unwrap().replace('\\', "/");
    let executable = env!("CARGO_BIN_EXE_henosis-shell").replace('\\', "/");
    let input = format!("propose crux.jsonl goal hypothesis test\nrun crux.jsonl 1 \"{project}\" artifact 2 \"{executable}\" relative\nshow crux.jsonl 1\nexit\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .current_dir(directory.path()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("COMMAND RESULT for 1 (not a verified capability)"), "{stdout}");
    assert!(stdout.contains("Match: true"), "{stdout}");
    assert!(stdout.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "{stdout}");
    assert_eq!(henosis_crux::read(&directory.path().join("crux.jsonl")).unwrap().len(), 3);
}

#[test]
fn unfinished_attempt_and_runner_failure_are_visible() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("crux.jsonl");
    let project = directory.path().to_str().unwrap().replace('\\', "/");
    let missing_program = directory.path().join("no-such-executable").to_str().unwrap().replace('\\', "/");
    henosis_crux::append(&path, henosis_crux::Event::Proposed { goal: "g".into(), hypothesis: "h".into(), test: "t".into() }).unwrap();
    henosis_crux::append(&path, henosis_crux::Event::ExperimentStarted { proposal: 1, request: henosis_evidence::Request {
        project: project.clone(), artifact: "artifact".into(), program: missing_program.clone(), expected_exit: 0, arguments: vec![],
    }}).unwrap();
    let input = format!("pending crux.jsonl\nrun crux.jsonl 1 \"{project}\" artifact 0 \"{missing_program}\"\npending crux.jsonl\nshow crux.jsonl 1\nexit\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .current_dir(directory.path()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("Attempt 2 for proposal 1: outcome not recorded"), "{stdout}");
    assert!(stdout.contains("RUNNER ERROR for proposal 1, attempt 3"), "{stdout}");
    let events = henosis_crux::read(&path).unwrap();
    assert_eq!(henosis_crux::unfinished(&events).unwrap(), vec![(2, 1)]);
}
