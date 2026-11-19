#![deny(unsafe_code)]

use henosis_jail::{LauncherSpec, Supervisor};
use henosis_crux::Event;
use henosis_dag::{
    AssistanceProvenance, EntityKind, EpistemicStatus, FailureRecord, Node, ProofOperator,
    QuarantineItem, RealizationContract, VerificationEntry, Worldline, WorldlineOp,
};
use henosis_vault::{Identity, keyring::{AuthScheme, UnlockedVault}};
use henosis_akashi::{
    build_bundle, load_bundle, run_suite, save_bundle, verify_from_evidence, BundleInput,
    FileMutation, PredictedOutcome, PerturbationCase,
};
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

const HELP: &str = "Commands:\n  launch /absolute/path [arguments...]  Start a background process\n  list                                 Show direct children and their status\n  stop ID                              Stop a direct child\n  stop-group ID                        Stop a child and its process group (Unix)\n  propose FILE GOAL HYPOTHESIS TEST    Record a proposed crux and test\n  observe FILE ID OUTCOME              Record an experiment outcome\n  assess FILE ID INFO FAILURE COST      Score each estimate from 1 to 5\n  rank FILE                            Rank assessed proposals\n  close FILE ID REASON                 Close a proposal\n  reopen FILE ID REASON                Reopen a proposal\n  show FILE ID                         Show a proposal and its history\n  run FILE ID PROJECT ARTIFACT EXIT PROGRAM [ARGS...]  Run trusted experiment\n  runenv FILE ID PROJECT ARTIFACT EXIT KEY[,KEY...] PROGRAM [ARGS...]\n  compare FILE RESULT_ID               Compare current artifact with recorded hash\n  drift FILE                           Report artifact drift across journal command results\n  stats FILE                           Show journal event statistics\n  search FILE PATTERN                  Search journal events by text pattern\n  export FILE FORMAT                   Export journal to json or csv\n  review FILE ATTEMPT NOTE              Record a user recovery note\n  pending FILE                         List unfinished attempts\n  backup FILE DEST                     Save a new plaintext snapshot\n  journal FILE                         Show recorded events\n  dag init FILE                        Create a new Worldline Merkle-DAG file\n  dag node FILE ID KIND TITLE DOMAIN SUMMARY STATUS PROVENANCE  Upsert a World Model node\n  dag contract FILE ID TITLE OUTPUT VERIFICATION COST [PREREQ...]  Upsert a realization contract\n  dag verify FILE NODE OPERATOR PROVENANCE EVIDENCE_SHA BLACKOUT SUMMARY  Record a verification\n  dag fail FILE ID TARGET ASSUMPTION TRIGGER PREDICTED OBSERVED [EVIDENCE_SHA]  Record a failure atlas entry\n  dag expose FILE ID SOURCE TOPIC NOTES [PROMPT_SHA]  Quarantine an exposure\n  dag resolve FILE EXPOSURE_ID NODE_ID  Resolve a quarantined exposure\n  dag tag FILE TAGNAME COMMITID        Tag a commit\n  dag log FILE [BRANCH]                Show commit log\n  dag state FILE                       Materialize head World Model state\n  dag verifyall FILE [REQUIRE_SIGS]    Verify every commit\n  dag branch FILE NAME [FROM_COMMIT]   Create a branch\n  dag checkout FILE BRANCH             Switch branches\n  dag merge FILE SOURCE_BRANCH RATIONALE  Merge a branch into head\n  dag key PHRASE [PASSPHRASE]             Recover an Ed25519 identity into this session\n  dag whoami                              Show the session key fingerprint\n  akashi bundle FILE NODE OUTPUT.hcap [SIGN true/false]  Build and sign a capability bundle\n  akashi verify-bundle FILE.hcap [STRICT true/false]     Load and verify a capability bundle\n  akashi verify-from-evidence JOURNAL RESULT_ID NODE_ID OPERATOR PROVENANCE SUMMARY DAG_FILE\n                                                          Verify a crux command result and record it in a dag worldline\n  akashi import BUNDLE.hcap DAG_FILE                      Import a signed peer bundle (provenance=External)\n  akashi perturb CASES.json PROJECT_DIR TARGET_ID DAG_FILE  Run perturbation suite, record failures in dag\n  vault create PATH PASSWORD PASSPHRASE  Create a new keyring vault\n  vault open PATH PASSPHRASE           Open an existing keyring vault into session\n  vault summary                        Show session vault summary\n  vault set NAME SCHEME [URL] SECRET   Store a provider credential\n  vault list                           List stored credentials\n  vault remove NAME                    Remove a stored credential\n  vault save PATH PASSWORD               Save session vault to disk\n  help                                 Show this help\n  exit                                 Stop direct children and exit\n\nArguments support shell-style quoting; no shell is invoked.";

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
    // Session-scoped signing key, recovered from a mnemonic with `dag key`.
    // It lives only for this REPL session and is never written to disk.
    let mut session_key: Option<Identity> = None;
    // Session-scoped unlocked keyring vault, opened with `vault open`.
    // It lives only for this REPL session and is never written to disk.
    let mut session_vault: Option<UnlockedVault> = None;
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
            "dag" if words.len() >= 2 => match words[1].as_str() {
                "init" if words.len() == 3 => match Worldline::create(Path::new(&words[2])) {
                    Ok(_) => println!("Created Worldline {}.", words[2]),
                    Err(error) => eprintln!("Could not create worldline: {error}"),
                },
                "node" if words.len() == 10 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let kind = match EntityKind::parse(words[4].as_str()) {
                        Ok(k) => k,
                        Err(error) => { eprintln!("{error}"); continue; }
                    };
                    let status = match EpistemicStatus::parse(words[8].as_str()) {
                        Ok(s) => s,
                        Err(error) => { eprintln!("{error}"); continue; }
                    };
                    let provenance = match AssistanceProvenance::parse(words[9].as_str()) {
                        Ok(p) => p,
                        Err(error) => { eprintln!("{error}"); continue; }
                    };
                    let node = Node {
                        id: words[3].clone(),
                        kind,
                        title: words[5].clone(),
                        domain: words[6].clone(),
                        summary: words[7].clone(),
                        status,
                        provenance,
                        evidence_sha256: vec![],
                        proof_operators: vec![],
                    };
                    match wl.commit(
                        format!("Shell: upsert node {}", words[3]),
                        vec![WorldlineOp::UpsertNode { node: Box::new(node) }],
                        session_key.as_ref(),
                    ) {
                        Ok(id) => match wl.save(path) {
                            Ok(()) => println!("Committed node {} as commit {}.", words[3], id),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not commit node: {error}"),
                    }
                },
                "contract" if words.len() >= 8 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let cost: u32 = match words[7].parse() {
                        Ok(c) => c,
                        Err(error) => { eprintln!("Invalid cost units: {error}"); continue; }
                    };
                    let prerequisites: Vec<String> = words[8..].iter().cloned().collect();
                    let contract = RealizationContract {
                        id: words[3].clone(),
                        title: words[4].clone(),
                        prerequisites,
                        assumptions: vec![],
                        resources: vec![],
                        output: words[5].clone(),
                        verification: words[6].clone(),
                        failure_boundary: vec![],
                        status: EpistemicStatus::Hypothesized,
                        cost_units: cost,
                    };
                    match wl.commit(
                        format!("Shell: upsert contract {}", words[3]),
                        vec![WorldlineOp::UpsertContract { contract: Box::new(contract) }],
                        session_key.as_ref(),
                    ) {
                        Ok(id) => match wl.save(path) {
                            Ok(()) => println!("Committed contract {} as commit {}.", words[3], id),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not commit contract: {error}"),
                    }
                },
                "verify" if words.len() == 9 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let operator = match ProofOperator::parse(words[4].as_str()) {
                        Ok(o) => o,
                        Err(error) => { eprintln!("{error}"); continue; }
                    };
                    let provenance = match AssistanceProvenance::parse(words[5].as_str()) {
                        Ok(p) => p,
                        Err(error) => { eprintln!("{error}"); continue; }
                    };
                    let blackout = match words[7].as_str() {
                        "true" => true,
                        "false" => false,
                        _ => { eprintln!("blackout must be 'true' or 'false'."); continue; }
                    };
                    let entry = VerificationEntry {
                        node_id: words[3].clone(),
                        operator,
                        provenance,
                        evidence_sha256: words[6].clone(),
                        proxy_blackout_verified: blackout,
                        summary: words[8].clone(),
                    };
                    match wl.commit(
                        format!("Shell: verify node {}", words[3]),
                        vec![WorldlineOp::RecordVerification { entry: Box::new(entry) }],
                        session_key.as_ref(),
                    ) {
                        Ok(id) => match wl.save(path) {
                            Ok(()) => println!("Recorded verification for {} as commit {}.", words[3], id),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not commit verification: {error}"),
                    }
                },
                "fail" if words.len() >= 9 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let evidence_sha256 = if words.len() >= 10 { Some(words[9].clone()) } else { None };
                    let failure = FailureRecord {
                        id: words[3].clone(),
                        target_id: words[4].clone(),
                        broken_assumption: words[5].clone(),
                        trigger: words[6].clone(),
                        predicted: words[7].clone(),
                        observed: words[8].clone(),
                        evidence_sha256,
                    };
                    match wl.commit(
                        format!("Shell: record failure {}", words[3]),
                        vec![WorldlineOp::RecordFailure { failure: Box::new(failure) }],
                        session_key.as_ref(),
                    ) {
                        Ok(id) => match wl.save(path) {
                            Ok(()) => println!("Recorded failure {} as commit {}.", words[3], id),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not commit failure: {error}"),
                    }
                },
                "expose" if words.len() >= 7 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let prompt_sha256 = if words.len() >= 8 { Some(words[7].clone()) } else { None };
                    let item = QuarantineItem {
                        id: words[3].clone(),
                        source: words[4].clone(),
                        topic: words[5].clone(),
                        prompt_sha256,
                        notes: words[6].clone(),
                        resolved_by_node: None,
                    };
                    match wl.commit(
                        format!("Shell: enqueue exposure {}", words[3]),
                        vec![WorldlineOp::EnqueueExposure { item: Box::new(item) }],
                        session_key.as_ref(),
                    ) {
                        Ok(id) => match wl.save(path) {
                            Ok(()) => println!("Enqueued exposure {} as commit {}.", words[3], id),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not commit exposure: {error}"),
                    }
                },
                "resolve" if words.len() == 5 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    match wl.commit(
                        format!("Shell: resolve exposure {}", words[3]),
                        vec![WorldlineOp::ResolveExposure { exposure_id: words[3].clone(), resolved_by_node: words[4].clone() }],
                        session_key.as_ref(),
                    ) {
                        Ok(id) => match wl.save(path) {
                            Ok(()) => println!("Resolved exposure {} as commit {}.", words[3], id),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not commit resolution: {error}"),
                    }
                },
                "tag" if words.len() == 5 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    match wl.tag(words[3].as_str(), words[4].as_str()) {
                        Ok(()) => match wl.save(path) {
                            Ok(()) => println!("Tagged commit {} as {}.", words[4], words[3]),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not tag: {error}"),
                    }
                },
                "log" if words.len() == 3 || words.len() == 4 => {
                    let path = Path::new(&words[2]);
                    let wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let branch = if words.len() == 4 { Some(words[3].as_str()) } else { None };
                    match wl.log(branch) {
                        Ok(commits) => {
                            if commits.is_empty() { println!("No commits."); }
                            for commit in commits {
                                let signer = if commit.signature_hex.is_some() { "signed" } else { "unsigned" };
                                println!("{}  seq={}  {}  {}", commit.id, commit.seq, signer, commit.message);
                                for op in &commit.ops {
                                    println!("    op: {:?}", op);
                                }
                            }
                        },
                        Err(error) => eprintln!("Could not read log: {error}"),
                    }
                },
                "state" if words.len() == 3 => {
                    let path = Path::new(&words[2]);
                    let wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    match wl.materialize_head() {
                        Ok(state) => {
                            println!("World state: {} nodes, {} contracts, {} failures, {} verifications, {} unresolved exposures",
                                state.nodes.len(), state.contracts.len(), state.failures.len(),
                                state.verifications.len(), state.unresolved_quarantine().len());
                            println!("  Unassisted capabilities (H): {}", state.unassisted_capabilities().len());
                            for id in state.unassisted_capabilities() {
                                println!("    H: {id}");
                            }
                            println!("  Assisted verified: {}", state.assisted_verified_nodes().len());
                            for id in state.assisted_verified_nodes() {
                                println!("    A: {id}");
                            }
                        },
                        Err(error) => eprintln!("Could not materialize state: {error}"),
                    }
                },
                "verifyall" if words.len() == 3 || words.len() == 4 => {
                    let path = Path::new(&words[2]);
                    let wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let require_sigs = if words.len() == 4 { words[3] == "true" } else { false };
                    match wl.verify_all(require_sigs) {
                        Ok(count) => println!("Verified {} signed commits (require_signatures={require_sigs}).", count),
                        Err(error) => eprintln!("Verification failed: {error}"),
                    }
                },
                "branch" if words.len() == 4 || words.len() == 5 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let from = if words.len() == 5 { Some(words[4].as_str()) } else { None };
                    match wl.create_branch(words[3].as_str(), from) {
                        Ok(_) => match wl.save(path) {
                            Ok(()) => println!("Created branch {}.", words[3]),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not create branch: {error}"),
                    }
                },
                "checkout" if words.len() == 4 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    match wl.checkout(words[3].as_str()) {
                        Ok(()) => match wl.save(path) {
                            Ok(()) => println!("Checked out branch {}.", words[3]),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not checkout: {error}"),
                    }
                },
                "merge" if words.len() >= 5 => {
                    let path = Path::new(&words[2]);
                    let mut wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let rationale = words[4..].join(" ");
                    match wl.merge(words[3].as_str(), rationale, session_key.as_ref()) {
                        Ok(id) => match wl.save(path) {
                            Ok(()) => println!("Merged {} as commit {}.", words[3], id),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not merge: {error}"),
                    }
                },
                "key" if words.len() == 3 || words.len() == 4 => {
                    let passphrase = if words.len() == 4 { words[3].as_str() } else { "" };
                    match Identity::recover(words[2].as_str(), passphrase) {
                        Ok(identity) => {
                            session_key = Some(identity);
                            let key = session_key.as_ref().unwrap();
                            println!("Session key loaded: fingerprint={} pubkey={}", key.fingerprint(), key.public_key_hex());
                        },
                        Err(error) => eprintln!("Could not recover identity: {error}"),
                    }
                },
                "whoami" if words.len() == 2 => {
                    match &session_key {
                        Some(identity) => println!("Session key: fingerprint={} pubkey={}", identity.fingerprint(), identity.public_key_hex()),
                        None => println!("No session key. Use: dag key PHRASE [PASSPHRASE]"),
                    }
                },
                _ => eprintln!("Unknown dag subcommand. Try: init, node, contract, verify, fail, expose, resolve, tag, log, state, verifyall, branch, checkout, merge, key, whoami."),
            },
            "akashi" if words.len() >= 2 => match words[1].as_str() {
                "bundle" if words.len() == 5 || words.len() == 6 => {
                    let path = Path::new(&words[2]);
                    let node_id = words[3].as_str();
                    let output = Path::new(&words[4]);
                    let sign = if words.len() == 6 { words[5] == "true" } else { false };
                    let wl = match Worldline::load(path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let state = match wl.materialize_head() {
                        Ok(s) => s,
                        Err(error) => { eprintln!("Could not materialize state: {error}"); continue; }
                    };
                    let capability = match state.nodes.get(node_id) {
                        Some(n) => n.clone(),
                        None => { eprintln!("No node '{node_id}' in head state."); continue; }
                    };
                    let contract = state.contracts.values()
                        .find(|c| c.output == node_id)
                        .cloned();
                    let verifications: Vec<VerificationEntry> = state.verifications.iter()
                        .filter(|v| v.node_id == node_id)
                        .cloned()
                        .collect();
                    let failures: Vec<FailureRecord> = state.failures.values()
                        .filter(|f| f.target_id == node_id)
                        .cloned()
                        .collect();
                    let input = BundleInput {
                        capability,
                        contract,
                        verifications,
                        failures,
                        perturbation_report: None,
                        blackout_receipt: None,
                        disclosed_capabilities: [node_id.to_owned()].into_iter().collect(),
                        scope_limits: "Shell-built bundle from head state; independent replication required before trusting unverified assumptions.".to_owned(),
                    };
                    let signer = session_key.as_ref().filter(|_| sign);
                    match build_bundle(input, signer) {
                        Ok(bundle) => match save_bundle(output, &bundle) {
                            Ok(()) => println!("Bundle {} saved to {} (signed={}).", bundle.bundle_id, output.display(), signer.is_some()),
                            Err(error) => eprintln!("Could not save bundle: {error}"),
                        },
                        Err(error) => eprintln!("Could not build bundle: {error}"),
                    }
                },
                "verify-bundle" if words.len() == 3 || words.len() == 4 => {
                    let strict = if words.len() == 4 { words[3] == "true" } else { false };
                    match load_bundle(Path::new(&words[2]), strict) {
                        Ok(bundle) => {
                            println!("Bundle {} verified (signed={}, format={}).", bundle.bundle_id, bundle.signature_hex.is_some(), bundle.format);
                            println!("  Capability: {} ({}) status={:?} provenance={:?}", bundle.capability.id, bundle.capability.title, bundle.capability.status, bundle.capability.provenance);
                            println!("  Verifications: {}  Failures: {}  Disclosed: {}", bundle.verifications.len(), bundle.failures.len(), bundle.disclosed_capabilities.len());
                            if let Some(contract) = &bundle.contract {
                                println!("  Contract: {} output={}", contract.id, contract.output);
                            }
                        },
                        Err(error) => eprintln!("Could not verify bundle: {error}"),
                    }
                },
                "verify-from-evidence" if words.len() == 9 => {
                    let journal_path = Path::new(&words[2]);
                    let result_id: u64 = match words[3].parse() {
                        Ok(id) => id,
                        Err(error) => { eprintln!("Result ID must be a number: {error}"); continue; }
                    };
                    let node_id = words[4].clone();
                    let operator = match ProofOperator::parse(words[5].as_str()) {
                        Ok(o) => o,
                        Err(error) => { eprintln!("{error}"); continue; }
                    };
                    let provenance = match AssistanceProvenance::parse(words[6].as_str()) {
                        Ok(p) => p,
                        Err(error) => { eprintln!("{error}"); continue; }
                    };
                    let summary = words[7].clone();
                    let dag_path = Path::new(&words[8]);

                    // Read the crux journal and locate the CommandResult evidence for this result ID.
                    let events = match henosis_crux::read(journal_path) {
                        Ok(ev) => ev,
                        Err(error) => { eprintln!("Could not read journal: {error}"); continue; }
                    };
                    let evidence = match result_id.checked_sub(1)
                        .and_then(|n| usize::try_from(n).ok())
                        .and_then(|n| events.get(n))
                        .cloned()
                    {
                        Some(Event::CommandResult { evidence, .. }) => evidence,
                        Some(_) => { eprintln!("Event {result_id} is not a command result."); continue; },
                        None => { eprintln!("No command result with ID {result_id} in journal."); continue; },
                    };

                    // Verify the evidence via Akashi Operator-implemented check.
                    let entry = match verify_from_evidence(
                        &node_id,
                        operator,
                        provenance,
                        &evidence,
                        None, // no proxy blackout receipt wired into the shell yet
                        &summary,
                    ) {
                        Ok(e) => e,
                        Err(error) => { eprintln!("Verification failed: {error}"); continue; }
                    };

                    // Record the verification into the dag worldline. Upsert a minimal
                    // node first if the capability isn't tracked yet.
                    let mut wl = match Worldline::load(dag_path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let state = match wl.materialize_head() {
                        Ok(s) => s,
                        Err(error) => { eprintln!("Could not materialize state: {error}"); continue; }
                    };
                    let mut ops: Vec<WorldlineOp> = Vec::new();
                    if !state.nodes.contains_key(&node_id) {
                        ops.push(WorldlineOp::UpsertNode {
                            node: Box::new(Node {
                                id: node_id.clone(),
                                kind: EntityKind::Capability,
                                title: node_id.clone(),
                                domain: "shell".into(),
                                summary: "Created from akashi verify-from-evidence; status set by verification.".into(),
                                status: EpistemicStatus::Hypothesized,
                                provenance: AssistanceProvenance::External,
                                evidence_sha256: vec![],
                                proof_operators: vec![],
                            }),
                        });
                    }
                    ops.push(WorldlineOp::RecordVerification { entry: Box::new(entry) });
                    match wl.commit(
                        format!("Shell: verify node {node_id} from evidence {result_id}"),
                        ops,
                        session_key.as_ref(),
                    ) {
                        Ok(id) => match wl.save(dag_path) {
                            Ok(()) => println!("Recorded verification for {node_id} as commit {id}."),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not commit verification: {error}"),
                    }
                },
                "import" if words.len() == 4 => {
                    let bundle_path = Path::new(&words[2]);
                    let dag_path = Path::new(&words[3]);

                    // Load and verify the peer bundle (signature required for trust).
                    let bundle = match load_bundle(bundle_path, true) {
                        Ok(b) => b,
                        Err(error) => { eprintln!("Could not load bundle: {error}"); continue; }
                    };

                    // Convert to import ops: peer provenance is stamped External so it never
                    // inflates the local unassisted capability state H.
                    let ops = match bundle.to_peer_import_ops() {
                        Ok(ops) => ops,
                        Err(error) => { eprintln!("Bundle not importable: {error}"); continue; }
                    };

                    let mut wl = match Worldline::load(dag_path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    match wl.commit(
                        format!("Shell: import bundle {} ({})", bundle.bundle_id, bundle.capability.id),
                        ops,
                        session_key.as_ref(),
                    ) {
                        Ok(id) => match wl.save(dag_path) {
                            Ok(()) => println!("Imported bundle {} into worldline as commit {}.", bundle.bundle_id, id),
                            Err(error) => eprintln!("Could not save worldline: {error}"),
                        },
                        Err(error) => eprintln!("Could not commit import: {error}"),
                    }
                },
                "perturb" if words.len() == 5 => {
                    let cases_path = Path::new(&words[2]);
                    let project_path = Path::new(&words[3]);
                    let target_id = words[4].as_str();
                    let dag_path = Path::new(&words[5]);

                    // Read perturbation cases from JSON file.
                    let cases_json = match std::fs::read_to_string(cases_path) {
                        Ok(s) => s,
                        Err(error) => { eprintln!("Could not read cases file: {error}"); continue; }
                    };
                    let cases: Vec<PerturbationCase> = match serde_json::from_str(&cases_json) {
                        Ok(c) => c,
                        Err(error) => { eprintln!("Could not parse cases JSON: {error}"); continue; }
                    };

                    // Run the perturbation suite.
                    let report = match run_suite(project_path, target_id, &cases) {
                        Ok(r) => r,
                        Err(error) => { eprintln!("Perturbation suite failed: {error}"); continue; }
                    };

                    // Print report.
                    println!("Perturbation suite {}: {} cases, {} accurate predictions", report.target_id, report.outcomes.len(), report.accurate_predictions);
                    for outcome in &report.outcomes {
                        println!("  {}: {} (exit={:?}, timed_out={})", outcome.case_id, outcome.verdict.as_str(), outcome.exit_code, outcome.timed_out);
                    }

                    // Record exposed failures in the dag worldline.
                    let mut wl = match Worldline::load(dag_path) {
                        Ok(wl) => wl,
                        Err(error) => { eprintln!("Could not load worldline: {error}"); continue; }
                    };
                    let mut ops: Vec<WorldlineOp> = Vec::new();
                    for failure in &report.exposed_failures {
                        ops.push(WorldlineOp::RecordFailure { failure: Box::new(failure.clone()) });
                    }
                    if !ops.is_empty() {
                        match wl.commit(
                            format!("Shell: record {} failures from perturbation suite {}", ops.len(), report.target_id),
                            ops,
                            session_key.as_ref(),
                        ) {
                            Ok(id) => match wl.save(dag_path) {
                                Ok(()) => println!("Recorded {} failure(s) as commit {}.", ops.len(), id),
                                Err(error) => eprintln!("Could not save worldline: {error}"),
                            },
                            Err(error) => eprintln!("Could not commit failures: {error}"),
                        }
                    } else {
                        println!("No failures exposed.");
                    }
                },
                _ => eprintln!("Unknown akashi subcommand. Try: bundle, verify-bundle, verify-from-evidence, import, perturb."),
            },
            "vault" if words.len() >= 2 => match words[1].as_str() {
                "create" if words.len() == 5 => {
                    let path = Path::new(&words[2]);
                    let password = words[3].as_bytes();
                    let passphrase = words[4].as_str();
                    if UnlockedVault::create_new(path, password, passphrase).is_err() {
                        eprintln!("Could not create vault.");
                        continue;
                    }
                    match UnlockedVault::open(path, password) {
                        Ok(vault) => {
                            session_vault = Some(vault);
                            println!("Created new keyring vault at {}.", words[2]);
                        },
                        Err(error) => eprintln!("Could not open vault: {error}"),
                    }
                },
                "open" if words.len() == 4 => {
                    let path = Path::new(&words[2]);
                    let password = words[3].as_bytes();
                    match UnlockedVault::open(path, password) {
                        Ok(vault) => {
                            session_vault = Some(vault);
                            println!("Opened keyring vault at {}.", words[2]);
                        },
                        Err(error) => eprintln!("Could not open vault: {error}"),
                    }
                },
                "summary" if words.len() == 2 => {
                    match &session_vault {
                        Some(vault) => {
                            let summary = vault.summary();
                            println!("Vault summary:");
                            println!("  Public key: {}", summary.public_key_hex);
                            println!("  Fingerprint: {}", summary.fingerprint);
                            println!("  Credentials: {}", summary.credential_count);
                        },
                        None => eprintln!("No vault open. Use: vault open PATH PASSPHRASE"),
                    }
                },
                "set" if words.len() >= 6 => {
                    let vault = match &mut session_vault {
                        Some(v) => v,
                        None => { eprintln!("No vault open. Use: vault open PATH PASSPHRASE"); continue; }
                    };
                    let name = words[2].as_str();
                    let scheme = match AuthScheme::parse(words[3].as_str()) {
                        Ok(s) => s,
                        Err(error) => { eprintln!("{error}"); continue; }
                    };
                    let (base_url, secret_idx) = if words.len() >= 7 && words[4] != "-" {
                        (Some(words[4].clone()), 5)
                    } else {
                        (None, 4)
                    };
                    let secret = words[secret_idx].as_str();
                    match vault.set_credential(name, secret, scheme, base_url) {
                        Ok(_) => println!("Set credential {}.", name),
                        Err(error) => eprintln!("Could not set credential: {error}"),
                    }
                },
                "list" if words.len() == 2 => {
                    let vault = match &session_vault {
                        Some(v) => v,
                        None => { eprintln!("No vault open. Use: vault open PATH PASSPHRASE"); continue; }
                    };
                    for summary in vault.list_credentials() {
                        println!("  {} ({}) {} bytes{}", summary.name, summary.auth_scheme.as_str(), summary.secret_len, summary.base_url.as_deref().map_or("".into(), |u| format!(" @ {}", u)));
                    }
                },
                "remove" if words.len() == 3 => {
                    let vault = match &mut session_vault {
                        Some(v) => v,
                        None => { eprintln!("No vault open. Use: vault open PATH PASSPHRASE"); continue; }
                    };
                    match vault.remove_credential(words[2].as_str()) {
                        Ok(()) => println!("Removed credential {}.", words[2]),
                        Err(error) => eprintln!("Could not remove credential: {error}"),
                    }
                },
                "save" if words.len() == 4 => {
                    let vault = match &mut session_vault {
                        Some(v) => v,
                        None => { eprintln!("No vault open. Use: vault open PATH PASSPHRASE"); continue; }
                    };
                    let password = words[3].as_bytes();
                    match vault.save(Path::new(&words[2]), password) {
                        Ok(()) => println!("Saved vault to {}.", words[2]),
                        Err(error) => eprintln!("Could not save vault: {error}"),
                    }
                },
                _ => eprintln!("Unknown vault subcommand. Try: create, open, summary, set, list, remove, save."),
            },
            "drift" if words.len() == 2 => match henosis_leverage::detect_drift(Path::new(&words[1])) {
                Ok(report) => {
                    println!("Artifact drift report for {}: {} command results", words[1], report.total);
                    println!("  unchanged={} changed={} missing={} unavailable={}  drift_rate={:.1}%",
                        report.unchanged, report.changed, report.missing, report.unavailable,
                        report.drift_rate() * 100.0);
                    if !report.review_targets().is_empty() {
                        println!("  Review targets:");
                        for entry in report.review_targets() {
                            println!("    event {} proposal {} attempt {:?} artifact {} status={} recorded={:?} current={:?}",
                                entry.event_position, entry.proposal_id, entry.attempt, entry.artifact,
                                entry.status.as_str(), entry.recorded_sha256, entry.current_sha256);
                        }
                    } else {
                        println!("  No drift detected — all recorded artifacts match.");
                    }
                },
                Err(error) => eprintln!("Could not detect drift: {error}"),
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
            "stats" if words.len() == 2 => match henosis_crux::read(Path::new(&words[1])) {
                Ok(events) => {
                    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
                    let mut command_results = 0usize;
                    for event in &events {
                        let kind = match event {
                            Event::Proposed { .. } => "proposed",
                            Event::Observed { .. } => "observed",
                            Event::Assessed { .. } => "assessed",
                            Event::StatusChanged { .. } => "status_changed",
                            Event::ExperimentStarted { .. } => "experiment_started",
                            Event::ExperimentFailed { .. } => "experiment_failed",
                            Event::AttemptReviewed { .. } => "attempt_reviewed",
                            Event::CommandResult { .. } => "command_result",
                        };
                        *counts.entry(kind.to_owned()).or_insert(0) += 1;
                        if matches!(event, Event::CommandResult { .. }) {
                            command_results += 1;
                        }
                    }
                    println!("Journal stats for {}: {} total events", words[1], events.len());
                    for (kind, count) in &counts {
                        println!("  {kind}: {count}");
                    }
                    if command_results > 0 {
                        match henosis_leverage::detect_drift(Path::new(&words[1])) {
                            Ok(report) => {
                                println!("  drift_rate: {:.1}%  review_targets: {}", report.drift_rate() * 100.0, report.review_targets().len());
                            },
                            Err(error) => eprintln!("  drift check failed: {error}"),
                        }
                    }
                },
                Err(error) => eprintln!("Could not read journal: {error}"),
            },
            "search" if words.len() == 3 => match henosis_crux::read(Path::new(&words[1])) {
                Ok(events) => {
                    let pattern = words[2].as_str();
                    let mut found = 0;
                    for (index, event) in events.iter().enumerate() {
                        let text = format!("{event:?}");
                        if text.contains(pattern) {
                            println!("{}: {}", index + 1, terminal_text(&text));
                            found += 1;
                        }
                    }
                    if found == 0 {
                        println!("No events matching '{pattern}'.");
                    } else {
                        println!("{found} event(s) matching '{pattern}'.");
                    }
                },
                Err(error) => eprintln!("Could not read journal: {error}"),
            },
            "export" if words.len() == 3 => match words[2].as_str() {
                "json" => match henosis_crux::read(Path::new(&words[1])) {
                    Ok(events) => {
                        let json = serde_json::to_string_pretty(&events)
                            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
                        println!("{json}");
                    },
                    Err(error) => eprintln!("Could not read journal: {error}"),
                },
                "csv" => match henosis_crux::read(Path::new(&words[1])) {
                    Ok(events) => {
                        println!("position,type,details");
                        for (index, event) in events.iter().enumerate() {
                            let kind = match event {
                                Event::Proposed { .. } => "proposed",
                                Event::Observed { .. } => "observed",
                                Event::Assessed { .. } => "assessed",
                                Event::StatusChanged { .. } => "status_changed",
                                Event::ExperimentStarted { .. } => "experiment_started",
                                Event::ExperimentFailed { .. } => "experiment_failed",
                                Event::AttemptReviewed { .. } => "attempt_reviewed",
                                Event::CommandResult { .. } => "command_result",
                            };
                            let details = format!("{event:?}").replace('"', "\"\"");
                            println!("{index},{kind},\"{details}\"");
                        }
                    },
                    Err(error) => eprintln!("Could not read journal: {error}"),
                },
                _ => eprintln!("Export format must be 'json' or 'csv'."),
            },
            "stop" if words.len() == 2 => match words[1].parse::<u64>() {
                Ok(id) => match supervisor.stop(id) {
                    Ok(status) => println!("Process {id}: {status}"),
                    Err(error) => eprintln!("Could not stop process {id}: {error}"),
                },
                Err(_) => eprintln!("Process ID must be a number."),
            },
            "stop-group" if words.len() == 2 => match words[1].parse::<u64>() {
                Ok(id) => match supervisor.stop_group(id) {
                    Ok(status) => println!("Process group {id}: {status}"),
                    Err(error) => eprintln!("Could not stop process group {id}: {error}"),
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
