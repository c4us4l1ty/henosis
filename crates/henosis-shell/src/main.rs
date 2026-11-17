#![deny(unsafe_code)]

use henosis_jail::{LauncherSpec, Supervisor};
use henosis_crux::Event;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

const HELP: &str = "Commands:\n  launch /absolute/path [arguments...]  Start a background process\n  list                                 Show direct children and their status\n  stop ID                              Stop a direct child\n  propose FILE GOAL HYPOTHESIS TEST    Record a proposed crux and test\n  observe FILE ID OUTCOME              Record an experiment outcome\n  assess FILE ID INFO FAILURE COST      Score each estimate from 1 to 5\n  rank FILE                            Rank assessed proposals\n  journal FILE                         Show recorded events\n  help                                 Show this help\n  exit                                 Stop direct children and exit\n\nArguments support shell-style quoting; no shell is invoked.";

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
            "propose" if words.len() == 5 => {
                let event = Event::Proposed { goal: words[2].clone(), hypothesis: words[3].clone(), test: words[4].clone() };
                match henosis_crux::append(Path::new(&words[1]), event) {
                    Ok(id) => println!("Recorded proposal {id} (unverified)."),
                    Err(error) => eprintln!("Could not record proposal: {error}"),
                }
            },
            "observe" if words.len() == 4 => match words[2].parse::<u64>() {
                Ok(proposal) => {
                    let event = Event::Observed { proposal, outcome: words[3].clone() };
                    match henosis_crux::append(Path::new(&words[1]), event) {
                        Ok(id) => println!("Recorded observation {id} (unverified)."),
                        Err(error) => eprintln!("Could not record observation: {error}"),
                    }
                },
                Err(_) => eprintln!("Proposal ID must be a number."),
            },
            "assess" if words.len() == 6 => {
                let parsed = (words[2].parse::<u64>(), words[3].parse::<u8>(), words[4].parse::<u8>(), words[5].parse::<u8>());
                match parsed {
                    (Ok(proposal), Ok(information), Ok(failure), Ok(cost)) => {
                        let event = Event::Assessed { proposal, information, failure, cost };
                        match henosis_crux::append(Path::new(&words[1]), event) {
                            Ok(id) => println!("Recorded assessment {id} (subjective)."),
                            Err(error) => eprintln!("Could not record assessment: {error}"),
                        }
                    },
                    _ => eprintln!("Proposal ID and estimates must be numbers; estimates must be between 1 and 5."),
                }
            },
            "rank" if words.len() == 2 => match henosis_crux::read(Path::new(&words[1])).and_then(|events| henosis_crux::rank(&events)) {
                Ok(ranked) if ranked.is_empty() => println!("No assessed proposals."),
                Ok(ranked) => {
                    println!("Subjective estimates: information × failure / cost (not verified):");
                    for item in ranked {
                        println!("{}  score={:.2} ({} × {} / {})  Goal: {}\n  Hypothesis: {}\n  Test: {}", item.id, f64::from(item.information) * f64::from(item.failure) / f64::from(item.cost), item.information, item.failure, item.cost, item.goal, item.hypothesis, item.test);
                    }
                },
                Err(error) => eprintln!("Could not rank journal: {error}"),
            },
            "journal" if words.len() == 2 => match henosis_crux::read(Path::new(&words[1])) {
                Ok(events) if events.is_empty() => println!("No events."),
                Ok(events) => for (index, event) in events.iter().enumerate() {
                    match event {
                        Event::Proposed { goal, hypothesis, test } => println!("{}  PROPOSAL (unverified)\n  Goal: {}\n  Hypothesis: {}\n  Test: {}", index + 1, goal, hypothesis, test),
                        Event::Observed { proposal, outcome } => println!("{}  OBSERVATION for {} (unverified)\n  Outcome: {}", index + 1, proposal, outcome),
                        Event::Assessed { proposal, information, failure, cost } => println!("{}  ASSESSMENT for {} (subjective)\n  Information: {}  Failure: {}  Cost: {}", index + 1, proposal, information, failure, cost),
                    }
                },
                Err(error) => eprintln!("Could not read journal: {error}"),
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
