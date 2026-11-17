#![deny(unsafe_code)]
//! A deliberately small process launcher. This is not an OS sandbox.
//!
//! Child environments are cleared rather than filtered: new credential names
//! therefore cannot accidentally pass through. This does not prevent a child
//! from reading files, communicating over the network, or inspecting processes.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// A command and its explicitly chosen environment. Nothing is inherited from
/// the parent environment unless it is deliberately added here.
#[derive(Debug)]
pub struct LauncherSpec {
    program: OsString,
    args: Vec<OsString>,
    directory: Option<PathBuf>,
    environment: Vec<(OsString, OsString)>,
}

impl LauncherSpec {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self { program: program.into(), args: Vec::new(), directory: None, environment: Vec::new() }
    }

    pub fn arg(&mut self, arg: impl Into<OsString>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    pub fn current_dir(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.directory = Some(path.as_ref().to_path_buf());
        self
    }

    /// Add a non-secret environment entry required by the launched application.
    /// Callers are responsible for deciding what is safe to share.
    pub fn env(&mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> &mut Self {
        self.environment.push((key.into(), value.into()));
        self
    }

    /// Spawn attached to the current terminal. Dropping the returned handle does
    /// not terminate the process; the caller must wait for or terminate it.
    pub fn spawn(&self) -> io::Result<Child> {
        let mut command = Command::new(&self.program);
        command.args(&self.args).env_clear().envs(self.environment.iter().map(|(k, v)| (k, v)));
        if let Some(directory) = &self.directory {
            command.current_dir(directory);
        }
        command.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
        command.spawn()
    }

    pub fn program(&self) -> &OsStr { &self.program }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn child_only_receives_explicit_environment() {
        // No mutation of the test runner's environment: this is safe under
        // parallel tests, and `env` prints exactly what the child receives.
        let output = Command::new("/usr/bin/env")
            .env_clear().env("HENOSIS_TEST", "visible").output().unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "HENOSIS_TEST=visible\n");
    }

    #[cfg(unix)]
    #[test]
    fn launcher_clears_parent_environment_and_passes_arguments() {
        // The shell checks a ubiquitous inherited variable and an explicit one.
        let mut spec = LauncherSpec::new("/bin/sh");
        spec.arg("-c").arg("test -z \"${HOME+x}\" && test \"$HENOSIS_TEST\" = yes && test \"$1\" = 'two words'")
            .arg("henosis-test").arg("two words").env("HENOSIS_TEST", "yes");
        assert!(spec.spawn().unwrap().wait().unwrap().success());
    }

    #[test]
    fn missing_program_is_an_error() {
        assert!(LauncherSpec::new("/henosis/nonexistent/program").spawn().is_err());
    }
}
