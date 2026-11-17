#![deny(unsafe_code)]

use henosis_jail::{LauncherSpec, Supervisor};
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

const HELP: &str = "Commands:\n  launch /absolute/path [arguments...]  Start a background process\n  list                                 Show direct children and their status\n  stop ID                              Stop a direct child\n  help                                 Show this help\n  exit                                 Stop direct children and exit\n\nArguments support shell-style quoting; no shell is invoked.";

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if let Some(command) = args.next() {
        if !Path::new(&command).is_absolute() {
            eprintln!("Provide an absolute executable path; the child has no PATH.");
            return ExitCode::from(2);
        }
        let mut spec = LauncherSpec::new(command);
        for arg in args { spec.arg(arg); }
        return match spec.spawn().and_then(|mut child| child.wait()) {
            Ok(status) => ExitCode::from(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1)),
            Err(error) => {
                eprintln!("Could not launch or wait for process: {error}");
                ExitCode::FAILURE
            }
        };
    }
    match workspace() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("Workspace error: {error}"); ExitCode::FAILURE }
    }
}

fn workspace() -> io::Result<()> {
    println!("Henosis — process workspace\nNot a sandbox. Children get an empty environment.\nType help for commands.");
    let mut supervisor = Supervisor::new();
    loop {
        print!("henosis> ");
        io::stdout().flush()?;
        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 { break; }
        let words = match shell_words::split(&input) {
            Ok(words) => words,
            Err(error) => { eprintln!("Invalid command: {error}"); continue; }
        };
        let Some(command) = words.first().map(String::as_str) else { continue; };
        match command {
            "help" if words.len() == 1 => println!("{HELP}"),
            "exit" if words.len() == 1 => break,
            "list" if words.len() == 1 => match supervisor.list() {
                Ok(processes) if processes.is_empty() => println!("No processes."),
                Ok(processes) => for process in processes {
                    let state = process.status.map_or_else(|| "running".to_owned(), |s| format!("exited ({s})"));
                    println!("{}  pid={}  {}  {}", process.id, process.pid, state, process.program.to_string_lossy());
                },
                Err(error) => eprintln!("Could not list processes: {error}"),
            },
            "launch" if words.len() >= 2 => {
                if !Path::new(&words[1]).is_absolute() {
                    eprintln!("Provide an absolute executable path; the child has no PATH.");
                    continue;
                }
                let mut spec = LauncherSpec::new(&words[1]);
                for arg in &words[2..] { spec.arg(arg); }
                match supervisor.launch(&spec) {
                    Ok(id) => println!("Started process {id}."),
                    Err(error) => eprintln!("Could not launch process: {error}"),
                }
            },
            "stop" if words.len() == 2 => match words[1].parse::<u64>() {
                Ok(id) => match supervisor.stop(id) {
                    Ok(status) => println!("Process {id}: {status}"),
                    Err(error) => eprintln!("Could not stop process {id}: {error}"),
                },
                Err(_) => eprintln!("Process ID must be a number."),
            },
            _ => eprintln!("Unknown or malformed command. Type help."),
        }
    }
    let errors = supervisor.shutdown();
    if !errors.is_empty() {
        for (id, error) in errors { eprintln!("Could not stop process {id}: {error}"); }
        return Err(io::Error::other("some child processes could not be stopped"));
    }
    Ok(())
}
