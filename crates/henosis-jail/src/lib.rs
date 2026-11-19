#![deny(unsafe_code)]
//! A deliberately small process launcher and laboratory worktree cloner.
//! This is not an OS sandbox.
//!
//! Child environments are cleared rather than filtered: new credential names
//! therefore cannot accidentally pass through. This does not prevent a child
//! from reading files, communicating over the network, or inspecting processes.
//!
//! Process group supervision (Unix only) confines a command and its
//! descendants to a new process group so `stop_group` can signal the whole
//! tree. Without an OS process namespace, descendants can still escape via
//! `setsid()` or reparenting; group supervision is a best-effort barrier.

/// Worktree cloning utilities for perturbation runs.
pub mod worktree;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

/// A command and its explicitly chosen environment. Nothing is inherited from
/// the parent environment unless it is deliberately added here.
#[derive(Debug, Clone)]
pub struct LauncherSpec {
    program: OsString,
    args: Vec<OsString>,
    directory: Option<PathBuf>,
    environment: Vec<(OsString, OsString)>,
    /// On Unix, place the child in a new process group so descendants can be
    /// signaled together. Ignored on non-Unix platforms.
    process_group: bool,
}

impl LauncherSpec {
    /// Create a new launcher spec for `program` with no arguments, directory,
    /// environment entries, or process group.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            directory: None,
            environment: Vec::new(),
            process_group: false,
        }
    }

    /// Add an argument to pass to the child process.
    pub fn arg(&mut self, arg: impl Into<OsString>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    /// Set the working directory for the child process.
    pub fn current_dir(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.directory = Some(path.as_ref().to_path_buf());
        self
    }

    /// Add a non-secret (or ephemeral capability token) environment entry
    /// required by the launched application. Callers are responsible for
    /// deciding what is safe to share; never pass master provider API keys.
    pub fn env(&mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> &mut Self {
        self.environment.push((key.into(), value.into()));
        self
    }

    /// Place the child in a new process group on Unix (process group ID equals
    /// the child's PID). Descendants remain in the group unless they call
    /// `setsid()`. Use [`Supervisor::stop_group`] to signal the whole tree.
    pub fn process_group(&mut self) -> &mut Self {
        self.process_group = true;
        self
    }

    fn build_command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .env_clear()
            .envs(self.environment.iter().map(|(k, v)| (k, v)));
        if let Some(directory) = &self.directory {
            command.current_dir(directory);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            if self.process_group {
                command.process_group(0);
            }
        }
        command
    }

    /// Spawn attached to the current terminal. Dropping the returned handle does
    /// not terminate the process; the caller must wait for or terminate it.
    pub fn spawn(&self) -> io::Result<Child> {
        self.build_command()
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
    }

    /// Spawn without terminal input, suitable for a background workspace.
    pub fn spawn_background(&self) -> io::Result<Child> {
        self.build_command()
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
    }

    /// Spawn with captured stdout and stderr for structured inspection.
    pub fn spawn_piped(&self) -> io::Result<Child> {
        self.build_command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    /// Return the program path.
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// Return the arguments slice.
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// Return the environment entries slice.
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }

    /// Return whether the child was requested to run in its own process group
    /// (Unix only).
    pub fn uses_process_group(&self) -> bool {
        self.process_group
    }
}

/// Supervises direct child processes; on Unix, optionally tracks process
/// groups so `stop_group` can signal an entire command tree.
#[derive(Default)]
pub struct Supervisor {
    next_id: u64,
    children: BTreeMap<u64, ManagedChild>,
}

struct ManagedChild {
    program: OsString,
    child: Child,
    status: Option<ExitStatus>,
    /// On Unix, the process group ID equals the child PID when `process_group`
    /// was requested; None otherwise.
    process_group_id: Option<u32>,
}

/// Information about a supervised child process.
#[derive(Debug)]
pub struct ProcessInfo {
    /// Supervisor-assigned process ID.
    pub id: u64,
    /// Operating system process ID.
    pub pid: u32,
    /// Program path.
    pub program: OsString,
    /// Exit status if the process has finished.
    pub status: Option<ExitStatus>,
    /// On Unix, the process group ID if `process_group` was requested.
    pub process_group_id: Option<u32>,
}

impl Supervisor {
    /// Create a new empty supervisor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Launch a background child process described by `spec` and return its
    /// supervisor-assigned ID.
    pub fn launch(&mut self, spec: &LauncherSpec) -> io::Result<u64> {
        let id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("process ID space exhausted"))?;
        let mut child = spec.spawn_background()?;
        let pgid = if spec.uses_process_group() {
            Some(child.id())
        } else {
            None
        };
        self.next_id = id;
        self.children.insert(
            id,
            ManagedChild {
                program: spec.program().to_owned(),
                child,
                status: None,
                process_group_id: pgid,
            },
        );
        Ok(id)
    }

    /// Refresh exit statuses without blocking. Completed processes stay visible.
    pub fn list(&mut self) -> io::Result<Vec<ProcessInfo>> {
        let mut result = Vec::with_capacity(self.children.len());
        for (&id, managed) in &mut self.children {
            if managed.status.is_none() {
                managed.status = managed.child.try_wait()?;
            }
            result.push(ProcessInfo {
                id,
                pid: managed.child.id(),
                program: managed.program.clone(),
                status: managed.status,
                process_group_id: managed.process_group_id,
            });
        }
        Ok(result)
    }

    /// Stop and reap one direct child. Finished children are returned unchanged.
    pub fn stop(&mut self, id: u64) -> io::Result<ExitStatus> {
        let managed = self
            .children
            .get_mut(&id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown process ID"))?;
        if let Some(status) = managed.status {
            return Ok(status);
        }
        if let Some(status) = managed.child.try_wait()? {
            managed.status = Some(status);
            return Ok(status);
        }
        // A process can exit between try_wait and kill. Check again on error.
        if let Err(error) = managed.child.kill() {
            if let Some(status) = managed.child.try_wait()? {
                managed.status = Some(status);
                return Ok(status);
            }
            return Err(error);
        }
        let status = managed.child.wait()?;
        managed.status = Some(status);
        Ok(status)
    }

    /// Stop and reap one direct child, and on Unix signal its entire process
    /// group so descendants are also terminated. Without an OS process
    /// namespace, descendants that called `setsid()` may survive.
    pub fn stop_group(&mut self, id: u64) -> io::Result<ExitStatus> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let pgid = {
                let managed = self
                    .children
                    .get(&id)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown process ID"))?;
                managed.process_group_id.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "process was not launched with process_group",
                    )
                })?
            };
            // Signal the whole process group (negative PID means process group).
            if let Err(error) = std::process::Command::new("kill")
                .arg(format!("-{}", pgid))
                .arg("TERM")
                .spawn()
                .and_then(|mut cmd| cmd.wait())
            {
                return Err(error);
            }
        }
        // Fall back to stopping the direct child too.
        let status = self.stop(id)?;
        Ok(status)
    }

    /// Best effort stop of all direct children, returning errors for reporting.
    pub fn shutdown(&mut self) -> Vec<(u64, io::Error)> {
        let ids: Vec<_> = self.children.keys().copied().collect();
        ids.into_iter()
            .filter_map(|id| self.stop(id).err().map(|err| (id, err)))
            .collect()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn child_only_receives_explicit_environment() {
        let output = Command::new("/usr/bin/env")
            .env_clear()
            .env("HENOSIS_TEST", "visible")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "HENOSIS_TEST=visible\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn launcher_clears_parent_environment_and_passes_arguments() {
        let mut spec = LauncherSpec::new("/bin/sh");
        spec.arg("-c")
            .arg("test -z \"${HOME+x}\" && test \"$HENOSIS_TEST\" = yes && test \"$1\" = 'two words'")
            .arg("henosis-test")
            .arg("two words")
            .env("HENOSIS_TEST", "yes");
        assert!(spec.spawn().unwrap().wait().unwrap().success());
    }

    #[test]
    fn missing_program_is_an_error() {
        assert!(LauncherSpec::new("/henosis/nonexistent/program")
            .spawn()
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_launches_lists_and_stops_child() {
        let mut supervisor = Supervisor::new();
        let mut spec = LauncherSpec::new("/bin/sh");
        spec.arg("-c").arg("exec /bin/sleep 30");
        let id = supervisor.launch(&spec).unwrap();
        let processes = supervisor.list().unwrap();
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].id, id);
        assert!(processes[0].status.is_none());
        supervisor.stop(id).unwrap();
        assert!(supervisor.list().unwrap()[0].status.is_some());
        assert!(supervisor.stop(id).is_ok());
        assert_eq!(
            supervisor.stop(id + 1).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_group_spawned_child_has_pgid() {
        let mut supervisor = Supervisor::new();
        let mut spec = LauncherSpec::new("/bin/sh");
        spec.arg("-c").arg("exec /bin/sleep 30").process_group();
        let id = supervisor.launch(&spec).unwrap();
        let processes = supervisor.list().unwrap();
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].id, id);
        assert!(processes[0].process_group_id.is_some());
        assert_eq!(processes[0].process_group_id, Some(processes[0].pid));
        supervisor.stop(id).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stop_group_signals_entire_process_group() {
        let mut supervisor = Supervisor::new();
        let mut spec = LauncherSpec::new("/bin/sh");
        spec.arg("-c")
            .arg("(/bin/sleep 30 &) ; exec /bin/sleep 30")
            .process_group();
        let id = supervisor.launch(&spec).unwrap();
        let processes = supervisor.list().unwrap();
        assert!(processes[0].process_group_id.is_some());
        let status = supervisor.stop_group(id).unwrap();
        assert!(!status.success());
        let mut spec2 = LauncherSpec::new("/bin/sh");
        spec2.arg("-c").arg("exit 0");
        let id2 = supervisor.launch(&spec2).unwrap();
        assert_eq!(supervisor.stop(id2).unwrap().code(), Some(0));
    }

    #[test]
    fn failed_launch_is_not_recorded() {
        let mut supervisor = Supervisor::new();
        assert!(supervisor
            .launch(&LauncherSpec::new("/henosis/nonexistent/program"))
            .is_err());
        assert!(supervisor.list().unwrap().is_empty());
    }
}
