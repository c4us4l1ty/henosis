#![deny(unsafe_code)]
//! A deliberately small process launcher. This is not an OS sandbox.
//!
//! Child environments are cleared rather than filtered: new credential names
//! therefore cannot accidentally pass through. This does not prevent a child
//! from reading files, communicating over the network, or inspecting processes.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

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
        self.spawn_with_stdin(Stdio::inherit())
    }

    /// Spawn without terminal input, suitable for a background workspace.
    pub fn spawn_background(&self) -> io::Result<Child> {
        self.spawn_with_stdin(Stdio::null())
    }

    fn spawn_with_stdin(&self, stdin: Stdio) -> io::Result<Child> {
        let mut command = Command::new(&self.program);
        command.args(&self.args).env_clear().envs(self.environment.iter().map(|(k, v)| (k, v)));
        if let Some(directory) = &self.directory {
            command.current_dir(directory);
        }
        command.stdin(stdin).stdout(Stdio::inherit()).stderr(Stdio::inherit());
        command.spawn()
    }

    pub fn program(&self) -> &OsStr { &self.program }
}

/// Supervises direct child processes only; this is not a process-tree jail.
#[derive(Default)]
pub struct Supervisor {
    next_id: u64,
    children: BTreeMap<u64, ManagedChild>,
}

struct ManagedChild {
    program: OsString,
    child: Child,
    status: Option<ExitStatus>,
}

#[derive(Debug)]
pub struct ProcessInfo {
    pub id: u64,
    pub pid: u32,
    pub program: OsString,
    pub status: Option<ExitStatus>,
}

impl Supervisor {
    pub fn new() -> Self { Self::default() }

    pub fn launch(&mut self, spec: &LauncherSpec) -> io::Result<u64> {
        let id = self.next_id.checked_add(1)
            .ok_or_else(|| io::Error::other("process ID space exhausted"))?;
        let child = spec.spawn_background()?;
        self.next_id = id;
        self.children.insert(id, ManagedChild {
            program: spec.program().to_owned(), child, status: None,
        });
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
                id, pid: managed.child.id(), program: managed.program.clone(), status: managed.status,
            });
        }
        Ok(result)
    }

    /// Stop and reap one direct child. Finished children are returned unchanged.
    pub fn stop(&mut self, id: u64) -> io::Result<ExitStatus> {
        let managed = self.children.get_mut(&id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown process ID"))?;
        if let Some(status) = managed.status { return Ok(status); }
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

    /// Best effort stop of all direct children, returning errors for reporting.
    pub fn shutdown(&mut self) -> Vec<(u64, io::Error)> {
        let ids: Vec<_> = self.children.keys().copied().collect();
        ids.into_iter().filter_map(|id| self.stop(id).err().map(|err| (id, err))).collect()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) { let _ = self.shutdown(); }
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
        assert_eq!(supervisor.stop(id + 1).unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn failed_launch_is_not_recorded() {
        let mut supervisor = Supervisor::new();
        assert!(supervisor.launch(&LauncherSpec::new("/henosis/nonexistent/program")).is_err());
        assert!(supervisor.list().unwrap().is_empty());
    }

}
