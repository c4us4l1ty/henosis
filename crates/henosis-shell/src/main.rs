#![deny(unsafe_code)]

use henosis_jail::LauncherSpec;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(command) = args.next() else {
        eprintln!("Henosis — early process launcher\n\nUsage: henosis-shell /absolute/path/to/program [arguments...]\n\nThe child receives an empty environment. This is not a sandbox.");
        return ExitCode::from(2);
    };
    if !std::path::Path::new(&command).is_absolute() {
        eprintln!("Provide an absolute executable path; the child has no PATH.");
        return ExitCode::from(2);
    }
    let mut spec = LauncherSpec::new(command);
    for arg in args { spec.arg(arg); }
    match spec.spawn().and_then(|mut child| child.wait()) {
        Ok(status) => ExitCode::from(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1)),
        Err(error) => {
            eprintln!("Could not launch or wait for process: {error}");
            ExitCode::FAILURE
        }
    }
}
