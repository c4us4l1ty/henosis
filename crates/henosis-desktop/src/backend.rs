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

#[derive(Debug)]
pub enum Event {
    Output(String),
    Error(String),
}

pub struct Backend {
    pub child: Child,
    pub output: mpsc::Receiver<Event>,
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
        let mut command = Command::new(path);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // Keep the CLI backend hidden when launched from the native GUI.
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let (tx, output) = mpsc::sync_channel(256);
        for (name, stream) in [
            ("stdout", Box::new(stdout) as Box<dyn Read + Send>),
            ("stderr", Box::new(stderr)),
        ] {
            let tx = tx.clone();
            thread::spawn(move || read_output(stream, name, tx));
        }
        let (commands, rx) = mpsc::sync_channel::<String>(32);
        let closing = Arc::new(AtomicBool::new(false));
        let shutdown = closing.clone();
        thread::spawn(move || {
            loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(line) => {
                        if let Err(error) = writeln!(stdin, "{line}") {
                            let _ = tx.send(Event::Error(format!("Workspace input failed: {error}. A command may be partially written; inspect before retrying.")));
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

    pub fn send(&mut self, line: String) -> Result<(), String> {
        if self.closing.load(Ordering::Relaxed) {
            return Err("Workspace is closing.".into());
        }
        if line.contains(['\r', '\n', '\0']) {
            return Err("Enter one command at a time.".into());
        }
        if self
            .child
            .try_wait()
            .map_err(|e| format!("Cannot inspect workspace: {e}"))?
            .is_some()
        {
            return Err("Workspace has exited. Start a new connection.".into());
        }
        self.commands
            .try_send(line)
            .map_err(|e| format!("Cannot send command: {e}"))
    }

    pub fn close(&self) {
        self.closing.store(true, Ordering::Relaxed);
    }
}

// Consume malformed bytes without throwing away a valid but incomplete UTF-8 tail.
fn decode(pending: &mut Vec<u8>, eof: bool) -> String {
    let mut text = String::new();
    let mut consumed = 0;
    while consumed < pending.len() {
        match std::str::from_utf8(&pending[consumed..]) {
            Ok(rest) => {
                text.push_str(rest);
                consumed = pending.len();
            }
            Err(error) => {
                let valid = error.valid_up_to();
                text.push_str(
                    std::str::from_utf8(&pending[consumed..consumed + valid])
                        .expect("valid prefix"),
                );
                consumed += valid;
                if let Some(len) = error.error_len() {
                    text.push('\u{fffd}');
                    consumed += len;
                } else if eof {
                    text.push('\u{fffd}');
                    consumed = pending.len();
                } else {
                    break;
                }
            }
        }
    }
    pending.drain(..consumed);
    text
}

fn read_output(mut stream: Box<dyn Read + Send>, name: &str, tx: mpsc::SyncSender<Event>) {
    let mut buffer = [0; 4096];
    let mut pending = Vec::new();
    loop {
        let eof = match stream.read(&mut buffer) {
            Ok(0) => true,
            Ok(n) => {
                pending.extend_from_slice(&buffer[..n]);
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let _ = tx.send(Event::Error(format!(
                    "Workspace {name} read failed: {error}"
                )));
                true
            }
        };
        let text = decode(&mut pending, eof);
        if !text.is_empty() && tx.send(Event::Output(text)).is_err() {
            return;
        }
        if eof {
            return;
        }
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
            for chunk in backend.output.try_iter() {
                match chunk {
                    Event::Output(text) => output.push_str(&text),
                    Event::Error(error) => panic!("{error}"),
                }
            }
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
            match chunk {
                Event::Output(text) => output.push_str(&text),
                Event::Error(error) => panic!("{error}"),
            }
        }
        assert!(output.contains("No processes."), "{output}");
        assert!(output.contains("Commands:"), "{output}");
    }
    #[test]
    fn malformed_bytes_do_not_corrupt_split_unicode() {
        let mut pending = vec![0xff, 0xe6, 0xb8];
        assert_eq!(decode(&mut pending, false), "\u{fffd}");
        pending.extend_from_slice(&[0xac, b'!']);
        assert_eq!(decode(&mut pending, false), "測!");
        assert!(pending.is_empty());
        pending.push(0xe6);
        assert_eq!(decode(&mut pending, true), "\u{fffd}");
        assert!(pending.is_empty());
    }

    #[test]
    fn read_errors_are_reported_and_interrupted_reads_retry() {
        struct Broken(bool);
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                let kind = if self.0 {
                    std::io::ErrorKind::Other
                } else {
                    self.0 = true;
                    std::io::ErrorKind::Interrupted
                };
                Err(std::io::Error::from(kind))
            }
        }
        let (tx, rx) = mpsc::sync_channel(4);
        read_output(Box::new(Broken(false)), "stdout", tx);
        assert!(
            matches!(rx.recv().unwrap(), Event::Error(text) if text.contains("stdout read failed"))
        );
    }

    #[test]
    #[ignore = "requires HENOSIS_TEST_BACKEND pointing to the built Rust workspace"]
    fn rejects_commands_after_backend_exit() {
        let path = std::env::var_os("HENOSIS_TEST_BACKEND").expect("set HENOSIS_TEST_BACKEND");
        let mut backend = Backend::start(Path::new(&path)).unwrap();
        backend.send("exit".into()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while backend.child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = backend.child.kill();
                let _ = backend.child.wait();
                panic!("backend did not exit");
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(backend.send("list".into()).unwrap_err().contains("exited"));
    }
}
