//! The desktop owns one persistent workspace; no command is run through a shell.
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::Duration;

pub struct Backend {
    pub child: Child,
    pub output: mpsc::Receiver<String>,
    commands: mpsc::SyncSender<String>,
    closing: Arc<AtomicBool>,
}

pub fn encode(words: &[&str]) -> Result<String, String> {
    if words.iter().any(|s| s.contains(['\n', '\r', '\0'])) {
        return Err("Fields cannot contain newlines or NUL characters.".into());
    }
    Ok(shell_words::join(words.iter().copied()))
}

impl Backend {
    pub fn start(path: &Path) -> std::io::Result<Self> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let (tx, output) = mpsc::sync_channel(256);
        for mut stream in [Box::new(stdout) as Box<dyn Read + Send>, Box::new(stderr)] {
            let tx = tx.clone();
            thread::spawn(move || {
                let mut buffer = [0; 4096];
                let mut pending = Vec::new();
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => pending.extend_from_slice(&buffer[..n]),
                    }
                    // Preserve multibyte UTF-8 characters split across reads.
                    let valid = match std::str::from_utf8(&pending) {
                        Ok(_) => pending.len(),
                        Err(e) if e.error_len().is_none() => e.valid_up_to(),
                        Err(_) => pending.len(),
                    };
                    if valid > 0 {
                        if tx
                            .send(String::from_utf8_lossy(&pending[..valid]).into_owned())
                            .is_err()
                        {
                            return;
                        }
                        pending.drain(..valid);
                    }
                }
                if !pending.is_empty() {
                    let _ = tx.send(String::from_utf8_lossy(&pending).into_owned());
                }
            });
        }
        let (commands, rx) = mpsc::sync_channel::<String>(32);
        let closing = Arc::new(AtomicBool::new(false));
        let shutdown = closing.clone();
        thread::spawn(move || {
            loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(line) => {
                        if writeln!(stdin, "{line}").is_err() {
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            // EOF makes the workspace stop and reap direct children.
        });
        Ok(Self {
            child,
            output,
            commands,
            closing,
        })
    }

    pub fn send(&self, line: String) -> Result<(), String> {
        if self.closing.load(Ordering::Relaxed) {
            return Err("Workspace is closing.".into());
        }
        if line.contains(['\r', '\n', '\0']) {
            return Err("Enter one command at a time.".into());
        }
        self.commands
            .try_send(line)
            .map_err(|e| format!("Cannot send command: {e}"))
    }

    pub fn close(&self) {
        self.closing.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let words = [
            "propose",
            "a path.jsonl",
            "it's a goal",
            "",
            "測定",
            "a\\b\"c",
        ];
        assert_eq!(shell_words::split(&encode(&words).unwrap()).unwrap(), words);
    }
    #[test]
    fn rejects_command_injection() {
        for text in ["ok\nexit", "ok\rexit", "\0"] {
            assert!(encode(&[text]).is_err());
        }
        assert_eq!(
            shell_words::split(&encode(&["; echo hi"]).unwrap()).unwrap(),
            ["; echo hi"]
        );
    }

    #[test]
    #[ignore = "requires HENOSIS_TEST_BACKEND pointing to the built Rust workspace"]
    fn persistent_workspace_commands_and_graceful_eof() {
        let path = std::env::var_os("HENOSIS_TEST_BACKEND").expect("set HENOSIS_TEST_BACKEND");
        let mut backend = Backend::start(Path::new(&path)).unwrap();
        assert!(backend.send("list\nexit".into()).is_err());
        backend.send(encode(&["list"]).unwrap()).unwrap();
        backend.send(encode(&["help"]).unwrap()).unwrap();
        backend.close();
        assert!(backend.send("list".into()).is_err());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut output = String::new();
        loop {
            for chunk in backend.output.try_iter() { output.push_str(&chunk); }
            if let Some(status) = backend.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = backend.child.kill();
                let _ = backend.child.wait();
                panic!("workspace did not shut down after EOF: {output}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        while let Ok(chunk) = backend.output.recv_timeout(Duration::from_secs(1)) {
            output.push_str(&chunk);
        }
        assert!(output.contains("No processes."), "{output}");
        assert!(output.contains("Commands:"), "{output}");
    }

}
