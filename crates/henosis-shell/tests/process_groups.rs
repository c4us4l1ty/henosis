//! Exercise the same group-launch protocol used by the native desktop.
#[cfg(unix)]
#[test]
fn workspace_can_launch_and_stop_a_unix_group() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_henosis-shell"))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"launch-group /bin/sleep 30\nstop-group 1\nexit\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Started process 1."), "{text}");
    assert!(text.contains("Process group 1:"), "{text}");
}
