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
