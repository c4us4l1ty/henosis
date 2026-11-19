#![deny(unsafe_code)]

use henosis_jail::{LauncherSpec, Supervisor};
use henosis_crux::Event;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

const HELP: &str = "Commands:\n  launch /absolute/path [arguments...]  Start a background process\n  list                                 Show direct children and their status\n  stop ID                              Stop a direct child\n  propose FILE GOAL HYPOTHESIS TEST    Record a proposed crux and test\n  observe FILE ID OUTCOME              Record an experiment outcome\n  assess FILE ID INFO FAILURE COST      Score each estimate from 1 to 5\n  rank FILE                            Rank assessed proposals\n  close FILE ID REASON                 Close a proposal\n  reopen FILE ID REASON                Reopen a proposal\n  show FILE ID                         Show a proposal and its history\n  run FILE ID PROJECT ARTIFACT EXIT PROGRAM [ARGS...]  Run trusted experiment\n  runenv FILE ID PROJECT ARTIFACT EXIT KEY[,KEY...] PROGRAM [ARGS...]\n  compare FILE RESULT_ID               Compare current artifact with recorded hash\n  review FILE ATTEMPT NOTE              Record a user recovery note\n  pending FILE                         List unfinished attempts\n  backup FILE DEST                     Save a new plaintext snapshot\n  journal FILE                         Show recorded events\n  help                                 Show this help\n  exit                                 Stop direct children and exit\n\nArguments support shell-style quoting; no shell is invoked.";

// User-controlled text must not emit terminal control sequences.
// Keep ordinary Unicode intact while making control characters visible.
fn terminal_text(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() { output.extend(ch.escape_default()); }
        else { output.push(ch); }
    }
    output
}

fn print_event(id: usize, event: &Event) {
    match event {
        Event::Proposed { goal, hypothesis, test } => println!("{}  PROPOSAL (unverified)\n  Goal: {}\n  Hypothesis: {}\n  Test: {}", id, terminal_text(goal), terminal_text(hypothesis), terminal_text(test)),
        Event::Observed { proposal, outcome } => println!("{}  OBSERVATION for {} (unverified)\n  Outcome: {}", id, proposal, terminal_text(outcome)),
        Event::Assessed { proposal, information, failure, cost } => println!("{}  ASSESSMENT for {} (subjective)\n  Information: {}  Failure: {}  Cost: {}", id, proposal, information, failure, cost),
        Event::ExperimentStarted { proposal, request } => println!("{}  ATTEMPT for {} (recorded before execution; outcome unknown until a result is recorded)\n  Project: {}  Program: {}\n  Arguments: {:?}  Artifact: {}  Expected exit: {}\n  Environment names only: {:?}", id, proposal, terminal_text(&request.project), terminal_text(&request.program), request.arguments.iter().map(|arg| terminal_text(arg)).collect::<Vec<_>>(), terminal_text(&request.artifact), request.expected_exit, request.env_keys.iter().map(|key| terminal_text(key)).collect::<Vec<_>>()),
        Event::AttemptReviewed { proposal, attempt, note } => println!("{}  USER REVIEW for proposal {}, attempt {} (not a command result)\n  Note: {}", id, proposal, attempt, terminal_text(note)),
        Event::ExperimentFailed { proposal, attempt, error } => println!("{}  RUNNER ERROR for proposal {}, attempt {} (command may have run)\n  Error: {}", id, proposal, attempt, terminal_text(error)),
        Event::CommandResult { proposal, attempt, evidence } => {
            let matched = !evidence.timed_out && evidence.exit_code == Some(evidence.expected_exit);
            let cleanup = match &evidence.timeout_cleanup {
                None => "not recorded (legacy result)".to_owned(),
                Some(henosis_evidence::TimeoutCleanup::NotNeeded) => "not attempted (no timeout)".to_owned(),
                Some(henosis_evidence::TimeoutCleanup::DirectChild) => "direct child only".to_owned(),
                Some(henosis_evidence::TimeoutCleanup::UnixProcessGroup { signal_error: None }) => "Unix group signal sent; direct child reaped (not proof all descendants stopped)".to_owned(),
                Some(henosis_evidence::TimeoutCleanup::UnixProcessGroup { signal_error: Some(error) }) => format!("Unix group signal failed: {}; direct child reaped", terminal_text(error)),
            };
            let before = match &evidence.artifact_before {
                Some(henosis_evidence::ArtifactBefore::NotFound) => "not found".to_owned(),
                Some(henosis_evidence::ArtifactBefore::Hashed { sha256 }) => format!("SHA-256: {}", terminal_text(sha256)),
                Some(henosis_evidence::ArtifactBefore::Unavailable { error }) => format!("unavailable: {}", terminal_text(error)),
                None => "not recorded (legacy result)".to_owned(),
            };
            let change = match evidence.artifact_change() {
                henosis_evidence::ArtifactChange::Appeared => "APPEARED",
                henosis_evidence::ArtifactChange::Changed => "CHANGED",
                henosis_evidence::ArtifactChange::Unchanged => "UNCHANGED",
                henosis_evidence::ArtifactChange::Unavailable => "UNAVAILABLE",
            };
            println!("{}  COMMAND RESULT for {} (not a verified capability)\n  Attempt: {:?}\n  Project: {}\n  Program: {}\n  Arguments: {:?}\n  Environment names only: {:?}\n  Expected exit: {}  Actual exit: {:?}  Match: {}  Timed out: {}\n  Timeout cleanup: {}\n  Artifact: {}  SHA-256: {}\n  Artifact before: {}  Comparison: {} (observations, not proof of authorship)\n  Artifact error: {}\n  Output incomplete: {}  Stdout truncated: {}  Stderr truncated: {}\n  Stdout lossy: {:?}  Stderr lossy: {:?} (None means unknown)\n  Stdout: {}\n  Stderr: {}", id, proposal, attempt,
                terminal_text(&evidence.project), terminal_text(&evidence.program), evidence.arguments.iter().map(|arg| terminal_text(arg)).collect::<Vec<_>>(), evidence.env_keys.iter().map(|key| terminal_text(key)).collect::<Vec<_>>(),
                evidence.expected_exit, evidence.exit_code, matched, evidence.timed_out, cleanup, terminal_text(&evidence.artifact),
                evidence.artifact_sha256.as_deref().map(terminal_text).unwrap_or_else(|| "unavailable".into()),
                before, change,
                evidence.artifact_error.as_deref().map(terminal_text).unwrap_or_else(|| "none".into()),
                evidence.output_incomplete, evidence.stdout_truncated, evidence.stderr_truncated, evidence.stdout_lossy, evidence.stderr_lossy,
                terminal_text(&evidence.stdout), terminal_text(&evidence.stderr));
        },
        Event::StatusChanged { proposal, closed, reason } => println!("{}  {} proposal {} (user-reported)\n  Reason: {}", id, if *closed { "CLOSED" } else { "REOPENED" }, proposal, terminal_text(reason)),
    }
}

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
                    println!("{}  pid={}  {}  {}", process.id, process.pid, state, terminal_text(&process.program.to_string_lossy()));
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
                Ok(ranked) if ranked.is_empty() => println!("No open, assessed proposals."),
                Ok(ranked) => {
                    println!("Subjective estimates: information × failure / cost (not verified):");
                    for item in ranked {
                        println!("{}  score={:.2} ({} × {} / {})  Goal: {}\n  Hypothesis: {}\n  Test: {}", item.id, f64::from(item.information) * f64::from(item.failure) / f64::from(item.cost), item.information, item.failure, item.cost, terminal_text(&item.goal), terminal_text(&item.hypothesis), terminal_text(&item.test));
                    }
                },
                Err(error) => eprintln!("Could not rank journal: {error}"),
            },
            "run" | "runenv" if (command == "run" && words.len() >= 7) || (command == "runenv" && words.len() >= 8) => {
                match (words[2].parse::<u64>(), words[5].parse::<i32>()) {
                    (Ok(proposal), Ok(expected_exit)) => {
                        let path = Path::new(&words[1]);
                        let program_index = if command == "runenv" { 7 } else { 6 };
                        let keys: Vec<String> = if command == "runenv" { words[6].split(',').map(str::to_owned).collect() } else { Vec::new() };
                        match henosis_evidence::resolve_parent_environment(&keys) {
                            Err(error) => eprintln!("Experiment not started; environment selection failed: {error}"),
                            Ok(environment) => {
                                let request = henosis_evidence::Request { project: words[3].clone(), artifact: words[4].clone(), expected_exit, program: words[program_index].clone(), arguments: words[program_index + 1..].to_vec(), env_keys: keys };
                                let started = Event::ExperimentStarted { proposal, request };
                                match henosis_crux::append(path, started) {
                                    Err(error) => eprintln!("Experiment not started; could not record intent: {error}. Inspect the journal before retrying."),
                                    Ok(attempt) => {
                                        println!("Recorded attempt {attempt}. Running trusted command; this is not a sandbox or capability verification.");
                                        if command == "runenv" { println!("Selected environment values are visible to the child and may appear in captured output. Never pass secrets."); }
                                        let result = match henosis_evidence::run_with_env(&words[3], &words[4], expected_exit, &words[program_index], &words[program_index + 1..], &environment) {
                                            Ok(evidence) => Event::CommandResult { proposal, attempt: Some(attempt), evidence: Box::new(evidence) },
                                            Err(error) => Event::ExperimentFailed { proposal, attempt, error: error.to_string() },
                                        };
                                        match henosis_crux::append(path, result.clone()) {
                                            Ok(_id) => print_event(proposal as usize, &result),
                                            Err(error) => eprintln!("Attempt {attempt} may have run, but recording its outcome failed: {error}. Inspect the journal and project before retrying."),
                                        }
                                    },
                                }
                            },
                        }
                    },
                    _ => eprintln!("Proposal ID and expected exit must be numbers."),
                }
            },
            "close" | "reopen" if words.len() == 4 => match words[2].parse::<u64>() {
                Ok(proposal) => {
                    let event = Event::StatusChanged { proposal, closed: command == "close", reason: words[3].clone() };
                    match henosis_crux::append(Path::new(&words[1]), event) {
                        Ok(id) => println!("Recorded status change {id} (user-reported)."),
                        Err(error) => eprintln!("Could not change status: {error}"),
                    }
                },
                Err(_) => eprintln!("Proposal ID must be a number."),
            },
            "show" if words.len() == 3 => match words[2].parse::<u64>() {
                Ok(id) => match henosis_crux::read(Path::new(&words[1])) {
                    Ok(events) => {
                        let proposal_index = id.checked_sub(1).and_then(|n| usize::try_from(n).ok());
                        match proposal_index.and_then(|index| events.get(index)) {
                            Some(event @ Event::Proposed { .. }) => {
                                print_event(usize::try_from(id).expect("validated proposal ID"), event);
                                for (index, event) in events.iter().enumerate() {
                                    if matches!(event, Event::Observed { proposal, .. } | Event::Assessed { proposal, .. } | Event::StatusChanged { proposal, .. } | Event::ExperimentStarted { proposal, .. } | Event::ExperimentFailed { proposal, .. } | Event::AttemptReviewed { proposal, .. } | Event::CommandResult { proposal, .. } if *proposal == id) {
                                        print_event(index + 1, event);
                                    }
                                }
                            },
                            _ => eprintln!("No proposal with ID {id}."),
                        }
                    },
                    Err(error) => eprintln!("Could not read journal: {error}"),
                },
                Err(_) => eprintln!("Proposal ID must be a number."),
            },
            "compare" if words.len() == 3 => match words[2].parse::<u64>() {
                Ok(id) => match henosis_crux::read(Path::new(&words[1])) {
                    Ok(events) => {
                        let event = id.checked_sub(1).and_then(|n| usize::try_from(n).ok()).and_then(|n| events.get(n));
                        match event {
                            Some(Event::CommandResult { evidence, .. }) => match henosis_evidence::compare_artifact(&evidence) {
                                Ok(comparison) => println!("Artifact comparison for result {id}: {}\n  Recorded SHA-256: {}\n  Current SHA-256: {}\nNot proof of authorship, correctness, or capability.", if comparison.matches { "MATCH" } else { "DIFFERENT" }, comparison.recorded, comparison.current),
                                Err(error) => eprintln!("Could not compare artifact: {error}"),
                            },
                            _ => eprintln!("No command result with ID {id}."),
                        }
                    },
                    Err(error) => eprintln!("Could not read journal: {error}"),
                },
                Err(_) => eprintln!("Result ID must be a number."),
            },
            "review" if words.len() == 4 => match words[2].parse::<u64>() {
                Ok(attempt) => {
                    let path = Path::new(&words[1]);
                    match henosis_crux::read(path) {
                        Ok(events) => {
                            let started = attempt.checked_sub(1).and_then(|n| usize::try_from(n).ok()).and_then(|n| events.get(n));
                            match started {
                                Some(Event::ExperimentStarted { proposal, .. }) => {
                                    let review = Event::AttemptReviewed { proposal: *proposal, attempt, note: words[3].clone() };
                                    match henosis_crux::append(path, review) {
                                        Ok(id) => println!("Recorded user review {id}; this does not establish an outcome."),
                                        Err(error) => eprintln!("Could not record review: {error}"),
                                    }
                                },
                                _ => eprintln!("No attempt with ID {attempt}."),
                            }
                        },
                        Err(error) => eprintln!("Could not read journal: {error}"),
                    }
                },
                Err(_) => eprintln!("Attempt ID must be a number."),
            },
            "pending" if words.len() == 2 => match henosis_crux::read(Path::new(&words[1])) {
                Ok(events) => match henosis_crux::unfinished(&events) {
                    Ok(attempts) if attempts.is_empty() => println!("No unfinished attempts."),
                    Ok(attempts) => {
                        let reviewed: std::collections::HashSet<u64> = events.iter().filter_map(|event| match event {
                            Event::AttemptReviewed { attempt, .. } => Some(*attempt),
                            _ => None,
                        }).collect();
                        for (attempt, proposal) in attempts {
                            println!("Attempt {attempt} for proposal {proposal}: outcome not recorded; command may have run. Inspect before retrying.{}", if reviewed.contains(&attempt) { " User review recorded; outcome remains unknown." } else { "" });
                        }
                    },
                    Err(error) => eprintln!("Could not inspect attempts: {error}"),
                },
                Err(error) => eprintln!("Could not inspect attempts: {error}"),
            },
            "backup" if words.len() == 3 => match henosis_crux::backup(Path::new(&words[1]), Path::new(&words[2])) {
                Ok(count) => println!("Backed up {count} events (plaintext)."),
                Err(error) => eprintln!("Could not back up journal: {error}"),
            },
            "journal" if words.len() == 2 => match henosis_crux::read(Path::new(&words[1])) {
                Ok(events) if events.is_empty() => println!("No events."),
                Ok(events) => for (index, event) in events.iter().enumerate() {
                    print_event(index + 1, event);
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
