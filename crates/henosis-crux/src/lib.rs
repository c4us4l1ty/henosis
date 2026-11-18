#![deny(unsafe_code)]
//! A deliberately modest, user-authored record of goals and falsification tests.
//! Records and estimates are user assertions, not verified capabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Proposed { goal: String, hypothesis: String, test: String },
    Observed { proposal: u64, outcome: String },
    Assessed { proposal: u64, information: u8, failure: u8, cost: u8 },
    StatusChanged { proposal: u64, closed: bool, reason: String },
    ExperimentStarted { proposal: u64, request: henosis_evidence::Request },
    ExperimentFailed { proposal: u64, attempt: u64, error: String },
    AttemptReviewed { proposal: u64, attempt: u64, note: String },
    CommandResult { proposal: u64, #[serde(default, skip_serializing_if = "Option::is_none")] attempt: Option<u64>, evidence: henosis_evidence::Evidence },
}

/// Maximum journal size accepted by this experimental implementation.
pub const MAX_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;

fn open_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    // Avoid blocking indefinitely while opening a FIFO without a writer.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

fn snapshot(file: &File) -> io::Result<(Vec<Event>, Vec<u8>)> {
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "journal is not a regular file"));
    }
    let mut file = file;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "journal exceeds the size limit"));
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated journal line"));
    }
    let mut events = Vec::new();
    let mut resolved = HashSet::new();
    for (index, line) in bytes.strip_suffix(b"\n").unwrap_or(&[]).split(|byte| *byte == b'\n').enumerate() {
        if bytes.is_empty() { break; }
        let number = index + 1;
        let event: Event = serde_json::from_slice(line).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid journal line {number}: {error}"))
        })?;
        validate(&events, &event, &resolved).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid journal line {number}: {error}"))
        })?;
        if let Some(attempt) = resolved_attempt(&event) { resolved.insert(attempt); }
        events.push(event);
    }
    Ok((events, bytes))
}

fn read_file(file: &File) -> io::Result<Vec<Event>> {
    Ok(snapshot(file)?.0)
}

/// Read the entire append-only journal. Proposal IDs are one-based event positions.
/// Invalid, oversized or truncated records are errors, never silently skipped.
/// The parent directory must be trusted; symbolic links are followed.
pub fn read(path: &Path) -> io::Result<Vec<Event>> {
    let file = open_read(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "journal is not a regular file"));
    }
    fs2::FileExt::lock_shared(&file)?;
    read_file(&file)
}

/// Copy a validated, point-in-time snapshot to a new file without replacing an
/// existing path. Both directories must be trusted and writers must cooperate
/// with the journal's file locks. The backup is plaintext, not a secure vault.
/// The file is synced before publication; directory durability is not promised.
pub fn backup(source: &Path, destination: &Path) -> io::Result<usize> {
    let source_file = open_read(source)?;
    if !source_file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "journal is not a regular file"));
    }
    fs2::FileExt::lock_shared(&source_file)?;
    let (events, bytes) = snapshot(&source_file)?;
    // The complete snapshot is held in memory, so the source lock can be released
    // before potentially slow backup I/O. Later appends are not in this backup.
    drop(source_file);
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(destination).map_err(|error| error.error)?;
    Ok(events.len())
}

fn resolved_attempt(event: &Event) -> Option<u64> {
    match event {
        Event::ExperimentFailed { attempt, .. } | Event::CommandResult { attempt: Some(attempt), .. } => Some(*attempt),
        _ => None,
    }
}

fn validate(events: &[Event], event: &Event, resolved: &HashSet<u64>) -> io::Result<()> {
    if resolved_attempt(event).is_some_and(|id| resolved.contains(&id)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "attempt already has a recorded outcome"));
    }
    let nonempty = |s: &str| !s.trim().is_empty();
    let is_proposal = |id: &u64| id.checked_sub(1)
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| events.get(n))
        .is_some_and(|event| matches!(event, Event::Proposed { .. }));
    let attempt_request = |id: u64, proposal_id: u64| id.checked_sub(1)
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| events.get(n))
        .and_then(|event| match event {
            Event::ExperimentStarted { proposal, request } if *proposal == proposal_id => Some(request),
            _ => None,
        });
    let valid = match event {
        Event::Proposed { goal, hypothesis, test } => nonempty(goal) && nonempty(hypothesis) && nonempty(test),
        Event::Observed { proposal, outcome } => nonempty(outcome) && is_proposal(proposal),
        Event::ExperimentStarted { proposal, request } => is_proposal(proposal) && nonempty(&request.project) && nonempty(&request.program) && nonempty(&request.artifact)
            && henosis_evidence::validate_env_keys(&request.env_keys).is_ok(),
        Event::ExperimentFailed { proposal, attempt, error } => is_proposal(proposal) && nonempty(error) && attempt_request(*attempt, *proposal).is_some(),
        Event::AttemptReviewed { proposal, attempt, note } => is_proposal(proposal) && nonempty(note) && attempt_request(*attempt, *proposal).is_some(),
        Event::CommandResult { proposal, attempt, evidence } => is_proposal(proposal)
            && henosis_evidence::validate_env_keys(&evidence.env_keys).is_ok()
            && attempt.is_none_or(|id| attempt_request(id, *proposal).is_some_and(|request| request.matches(evidence))),
        Event::StatusChanged { proposal, reason, .. } => nonempty(reason) && is_proposal(proposal),
        Event::Assessed { proposal, information, failure, cost } => {
            is_proposal(proposal) && [*information, *failure, *cost].iter().all(|n| (1..=5).contains(n))
        }
    };
    if valid { Ok(()) } else { Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid fields, event references, attempt details, or estimates")) }
}

/// Return attempts with no recorded result or runner error. An unfinished
/// attempt may have executed: never assume it is safe to retry automatically.
pub fn unfinished(events: &[Event]) -> io::Result<Vec<(u64, u64)>> {
    use std::collections::BTreeMap;
    let mut pending = BTreeMap::new();
    let mut resolved = HashSet::new();
    for (index, event) in events.iter().enumerate() {
        validate(&events[..index], event, &resolved)?;
        if let Some(attempt) = resolved_attempt(event) { resolved.insert(attempt); }
        match event {
            Event::ExperimentStarted { proposal, .. } => {
                let id = u64::try_from(index).ok().and_then(|n| n.checked_add(1))
                    .ok_or_else(|| io::Error::other("journal is too large"))?;
                pending.insert(id, *proposal);
            },
            Event::ExperimentFailed { attempt, .. } | Event::CommandResult { attempt: Some(attempt), .. } => { pending.remove(attempt); },
            _ => (),
        }
    }
    Ok(pending.into_iter().collect())
}

/// A proposal with its most recent user-supplied assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedProposal {
    pub id: u64,
    pub goal: String,
    pub hypothesis: String,
    pub test: String,
    pub information: u8,
    pub failure: u8,
    pub cost: u8,
}

/// Rank assessed proposals by information × failure / cost, highest first.
/// Estimates are ordinal heuristics, not probabilities or measured information.
/// Ties use proposal ID ascending. Closed proposals are excluded; observations
/// alone do not close proposals. The latest status event determines the status.
/// Rejects invalid event sequences, including references to future proposals.
pub fn rank(events: &[Event]) -> io::Result<Vec<RankedProposal>> {
    use std::collections::BTreeMap;
    let mut assessments = BTreeMap::new();
    let mut statuses = BTreeMap::new();
    let mut resolved = HashSet::new();
    for (index, event) in events.iter().enumerate() {
        validate(&events[..index], event, &resolved)?;
        if let Some(attempt) = resolved_attempt(event) { resolved.insert(attempt); }
        if let Event::Assessed { proposal, information, failure, cost } = event {
            assessments.insert(*proposal, (*information, *failure, *cost));
        }
        if let Event::StatusChanged { proposal, closed, .. } = event {
            statuses.insert(*proposal, *closed);
        }
    }
    let mut ranked = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if let Event::Proposed { goal, hypothesis, test } = event {
            let id = u64::try_from(index).ok().and_then(|n| n.checked_add(1))
                .ok_or_else(|| io::Error::other("journal is too large"))?;
            if let Some(&(information, failure, cost)) = assessments.get(&id).filter(|_| !statuses.get(&id).copied().unwrap_or(false)) {
                ranked.push(RankedProposal { id, goal: goal.clone(), hypothesis: hypothesis.clone(), test: test.clone(), information, failure, cost });
            }
        }
    }
    ranked.sort_by(|a, b| {
        let a_score = u32::from(a.information) * u32::from(a.failure) * u32::from(b.cost);
        let b_score = u32::from(b.information) * u32::from(b.failure) * u32::from(a.cost);
        b_score.cmp(&a_score).then_with(|| a.id.cmp(&b.id))
    });
    Ok(ranked)
}

// Bound serialized output while producing it, including JSON escaping. Checking
// only after `to_vec` could allocate far beyond the documented journal limit.
struct RecordBuffer {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl Write for RecordBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > (MAX_JOURNAL_BYTES as usize - 1).saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "journal would exceed the size limit"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// Append one event and return its one-based position. Readers and writers
/// cooperate using advisory file locks. The journal is plaintext and is not
/// encrypted, signed, or tamper-evident. Use only in a trusted directory.
/// An error may occur after some or all bytes were written, including on sync
/// failure; inspect the journal before retrying. Directory creation is not synced.
pub fn append(path: &Path, event: Event) -> io::Result<u64> {
    // Reject invalid proposals before creating a new file.
    if matches!(&event, Event::Proposed { .. }) { validate(&[], &event, &HashSet::new())?; }
    let mut buffer = RecordBuffer { bytes: Vec::new(), exceeded: false };
    if let Err(error) = serde_json::to_writer(&mut buffer, &event) {
        return Err(if buffer.exceeded {
            io::Error::new(io::ErrorKind::InvalidInput, "journal would exceed the size limit")
        } else {
            io::Error::other(error)
        });
    }
    let mut record = buffer.bytes;
    record.push(b'\n');
    let mut options = OpenOptions::new();
    options.read(true).append(true);
    // Referencing events cannot be valid in a journal that does not exist.
    if matches!(&event, Event::Proposed { .. }) { options.create(true); }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "journal is not a regular file"));
    }
    fs2::FileExt::lock_exclusive(&file)?;
    let events = read_file(&file)?;
    let resolved = events.iter().filter_map(resolved_attempt).collect();
    validate(&events, &event, &resolved)?;
    let id = u64::try_from(events.len()).ok().and_then(|n| n.checked_add(1))
        .ok_or_else(|| io::Error::other("journal is too large"))?;
    if file.metadata()?.len().saturating_add(record.len() as u64) > MAX_JOURNAL_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "journal would exceed the size limit"));
    }
    file.write_all(&record)?;
    file.sync_all()?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("henosis-crux-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()))
    }
    fn proposal() -> Event {
        Event::Proposed { goal: "Build a reactor".into(), hypothesis: "Heat is the bottleneck".into(), test: "Measure heat loss\nunder load".into() }
    }
    #[test]
    fn round_trip_and_reference_validation() {
        let path = path();
        assert_eq!(read(&path).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(append(&path, Event::Observed { proposal: 1, outcome: "No".into() }).is_err());
        assert_eq!(append(&path, proposal()).unwrap(), 1);
        let observation = Event::Observed { proposal: 1, outcome: "Unexpected loss".into() };
        assert_eq!(append(&path, observation.clone()).unwrap(), 2);
        assert_eq!(read(&path).unwrap(), vec![proposal(), observation]);
        assert!(append(&path, Event::Observed { proposal: 2, outcome: "x".into() }).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn unfinished_attempts_track_results_and_reject_mismatched_references() {
        let path = path();
        append(&path, proposal()).unwrap();
        let request = henosis_evidence::Request { project: "/project".into(), program: "/tool".into(), arguments: vec!["arg".into()], artifact: "out".into(), expected_exit: 0, env_keys: vec![] };
        let mut invalid_request = request.clone();
        invalid_request.env_keys = vec!["SECRET=value".into()];
        assert!(append(&path, Event::ExperimentStarted { proposal: 1, request: invalid_request }).is_err());
        assert_eq!(append(&path, Event::ExperimentStarted { proposal: 1, request: request.clone() }).unwrap(), 2);
        let evidence = henosis_evidence::Evidence {
            project: request.project.clone(), program: request.program.clone(), arguments: request.arguments.clone(), artifact: request.artifact.clone(), expected_exit: 0, env_keys: vec![],
            exit_code: Some(0), timed_out: false, stdout: String::new(), stderr: String::new(),
            stdout_truncated: false, stderr_truncated: false, stdout_lossy: Some(false), stderr_lossy: Some(false), output_incomplete: false,
            artifact_sha256: None, artifact_error: Some("missing".into()), artifact_before: None,
        };
        assert_eq!(unfinished(&read(&path).unwrap()).unwrap(), vec![(2, 1)]);
        assert!(append(&path, Event::AttemptReviewed { proposal: 1, attempt: 1, note: "x".into() }).is_err());
        assert!(append(&path, Event::AttemptReviewed { proposal: 1, attempt: 2, note: " ".into() }).is_err());
        // Reviews are observations, not outcomes; a later result is still valid.
        let review = Event::AttemptReviewed { proposal: 1, attempt: 2, note: "inspected".into() };
        assert_eq!(append(&path, review).unwrap(), 3);
        assert_eq!(unfinished(&read(&path).unwrap()).unwrap(), vec![(2, 1)]);
        let mut bad = evidence.clone();
        bad.program = "/different".into();
        assert!(append(&path, Event::CommandResult { proposal: 1, attempt: Some(2), evidence: bad }).is_err());
        let mut bad_env = evidence.clone();
        bad_env.env_keys.push("EXTRA".into());
        assert!(append(&path, Event::CommandResult { proposal: 1, attempt: Some(2), evidence: bad_env }).is_err());
        let mut invalid_evidence = evidence.clone();
        invalid_evidence.env_keys = vec!["DUPLICATE".into(), "DUPLICATE".into()];
        assert!(append(&path, Event::CommandResult { proposal: 1, attempt: None, evidence: invalid_evidence }).is_err());
        let request_json = serde_json::to_string(&request).unwrap();
        assert!(!request_json.contains("env_keys"));
        assert_eq!(serde_json::from_str::<henosis_evidence::Request>(&request_json).unwrap(), request);
        let evidence_json = serde_json::to_string(&evidence).unwrap();
        assert!(!evidence_json.contains("env_keys"));
        assert_eq!(serde_json::from_str::<henosis_evidence::Evidence>(&evidence_json).unwrap(), evidence);
        assert!(append(&path, Event::ExperimentFailed { proposal: 1, attempt: 1, error: "bad".into() }).is_err());
        assert_eq!(append(&path, Event::CommandResult { proposal: 1, attempt: Some(2), evidence: evidence.clone() }).unwrap(), 4);
        assert!(unfinished(&read(&path).unwrap()).unwrap().is_empty());
        assert!(append(&path, Event::ExperimentFailed { proposal: 1, attempt: 2, error: "duplicate".into() }).is_err());
        assert!(append(&path, Event::CommandResult { proposal: 1, attempt: Some(2), evidence: evidence.clone() }).is_err());
        // Earlier journals have no attempt field; they remain readable.
        let mut legacy = serde_json::to_value(Event::CommandResult { proposal: 1, attempt: None, evidence }).unwrap();
        assert!(legacy.as_object_mut().unwrap().remove("attempt").is_none());
        let decoded: Event = serde_json::from_value(legacy).unwrap();
        assert!(matches!(decoded, Event::CommandResult { attempt: None, .. }));
        assert_eq!(append(&path, Event::ExperimentStarted { proposal: 1, request }).unwrap(), 5);
        append(&path, Event::ExperimentFailed { proposal: 1, attempt: 5, error: "spawn failed".into() }).unwrap();
        assert!(unfinished(&read(&path).unwrap()).unwrap().is_empty());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn empty_existing_journal_is_distinct_from_missing_journal() {
        let path = path();
        assert_eq!(read(&path).unwrap_err().kind(), io::ErrorKind::NotFound);
        std::fs::write(&path, b"").unwrap();
        assert!(read(&path).unwrap().is_empty());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn ranking_uses_latest_assessment_and_exact_tie_breaking() {
        let events = vec![
            proposal(), proposal(), proposal(),
            Event::Assessed { proposal: 1, information: 5, failure: 5, cost: 1 },
            Event::Assessed { proposal: 2, information: 4, failure: 3, cost: 2 },
            Event::Assessed { proposal: 1, information: 3, failure: 4, cost: 2 },
            Event::Observed { proposal: 2, outcome: "tested".into() },
        ];
        let ranked = rank(&events).unwrap();
        assert_eq!(ranked.iter().map(|p| p.id).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!((ranked[0].information, ranked[0].failure, ranked[0].cost), (3, 4, 2));
        let mut changed = events;
        changed.push(Event::Assessed { proposal: 2, information: 5, failure: 5, cost: 2 });
        assert_eq!(rank(&changed).unwrap()[0].id, 2);
    }
    #[test]
    fn closing_excludes_and_reopening_restores_assessed_proposal() {
        let path = path();
        append(&path, proposal()).unwrap();
        append(&path, Event::Assessed { proposal: 1, information: 5, failure: 2, cost: 1 }).unwrap();
        let closed = Event::StatusChanged { proposal: 1, closed: true, reason: "test complete".into() };
        append(&path, closed).unwrap();
        assert!(rank(&read(&path).unwrap()).unwrap().is_empty());
        let reopened = Event::StatusChanged { proposal: 1, closed: false, reason: "new evidence".into() };
        append(&path, reopened).unwrap();
        let ranked = rank(&read(&path).unwrap()).unwrap();
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].id, 1);
        assert_eq!(ranked[0].information, 5);
        assert!(append(&path, Event::StatusChanged { proposal: 2, closed: true, reason: "x".into() }).is_err());
        assert!(append(&path, Event::StatusChanged { proposal: 1, closed: true, reason: " ".into() }).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn assessment_validation_applies_to_read_append_and_rank() {
        let path = path();
        append(&path, proposal()).unwrap();
        for event in [
            Event::Assessed { proposal: 1, information: 0, failure: 1, cost: 1 },
            Event::Assessed { proposal: 1, information: 1, failure: 6, cost: 1 },
            Event::Assessed { proposal: 1, information: 1, failure: 1, cost: 0 },
            Event::Assessed { proposal: 2, information: 1, failure: 1, cost: 1 },
        ] {
            assert!(append(&path, event.clone()).is_err());
            assert!(rank(&[proposal(), event]).is_err());
        }
        let event = Event::Assessed { proposal: 1, information: 5, failure: 4, cost: 3 };
        append(&path, event.clone()).unwrap();
        assert_eq!(read(&path).unwrap(), vec![proposal(), event]);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn corruption_is_not_ignored_or_overwritten() {
        let path = path();
        std::fs::write(&path, b"{broken\n").unwrap();
        assert_eq!(read(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(append(&path, proposal()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{broken\n");
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn unknown_fields_are_not_silently_ignored() {
        let path = path();
        let bytes = br#"{"type":"proposed","goal":"g","hypothesis":"h","test":"t","future_semantics":true}
"#;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(read(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(append(&path, proposal()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn valid_but_unterminated_line_is_rejected() {
        let path = path();
        let record = serde_json::to_vec(&proposal()).unwrap();
        std::fs::write(&path, &record).unwrap();
        assert_eq!(read(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(append(&path, proposal()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), record);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn backup_preserves_exact_bytes_and_does_not_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("journal");
        let destination = dir.path().join("backup");
        append(&source, proposal()).unwrap();
        append(&source, Event::Observed { proposal: 1, outcome: "observed".into() }).unwrap();
        assert_eq!(backup(&source, &destination).unwrap(), 2);
        assert_eq!(std::fs::read(&source).unwrap(), std::fs::read(&destination).unwrap());
        assert_eq!(read(&source).unwrap(), read(&destination).unwrap());
        append(&source, proposal()).unwrap();
        assert_eq!(backup(&source, &destination).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(read(&destination).unwrap().len(), 2);
        assert_eq!(backup(&source, &source).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(read(&source).unwrap().len(), 3);
    }
    #[test]
    fn backup_rejects_missing_or_corrupt_source_without_creating_destination() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("journal");
        let destination = dir.path().join("backup");
        assert_eq!(backup(&source, &destination).unwrap_err().kind(), io::ErrorKind::NotFound);
        std::fs::write(&source, b"{broken\n").unwrap();
        assert_eq!(backup(&source, &destination).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(!destination.exists());
    }
    #[test]
    fn racing_backups_never_clobber_or_mix_snapshots() {
        use std::sync::{Arc, Barrier};
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        let destination = dir.path().join("backup");
        append(&first, proposal()).unwrap();
        append(&second, proposal()).unwrap();
        append(&second, Event::Observed { proposal: 1, outcome: "second".into() }).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [first.clone(), second.clone()].into_iter().map(|source| {
            let destination = destination.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                backup(&source, &destination)
            })
        }).collect();
        let results: Vec<_> = threads.into_iter().map(|thread| thread.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|r| matches!(r, Err(e) if e.kind() == io::ErrorKind::AlreadyExists)).count(), 1);
        let bytes = std::fs::read(&destination).unwrap();
        assert!(bytes == std::fs::read(first).unwrap() || bytes == std::fs::read(second).unwrap());
        assert!(read(&destination).is_ok());
    }
    #[test]
    fn empty_journal_can_be_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("journal");
        let destination = dir.path().join("backup");
        std::fs::write(&source, b"").unwrap();
        assert_eq!(backup(&source, &destination).unwrap(), 0);
        assert!(read(&destination).unwrap().is_empty());
    }
    #[cfg(unix)]
    #[test]
    fn backup_does_not_replace_symlink_or_its_target() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("journal");
        let destination = dir.path().join("backup-link");
        let target = dir.path().join("target");
        append(&source, proposal()).unwrap();
        std::fs::write(&target, b"untouched").unwrap();
        symlink(&target, &destination).unwrap();
        assert_eq!(backup(&source, &destination).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(std::fs::symlink_metadata(&destination).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    }
    #[cfg(unix)]
    #[test]
    fn backup_does_not_follow_dangling_destination_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("journal");
        let destination = dir.path().join("backup-link");
        let target = dir.path().join("missing-target");
        append(&source, proposal()).unwrap();
        symlink(&target, &destination).unwrap();
        assert_eq!(backup(&source, &destination).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(std::fs::symlink_metadata(destination).unwrap().file_type().is_symlink());
        assert!(!target.exists());
    }
    #[cfg(unix)]
    #[test]
    fn backup_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("journal");
        let destination = dir.path().join("backup");
        append(&source, proposal()).unwrap();
        backup(&source, &destination).unwrap();
        assert_eq!(std::fs::metadata(destination).unwrap().permissions().mode() & 0o077, 0);
    }
    #[test]
    fn backup_during_writes_is_a_valid_prefix() {
        use std::sync::{Arc, Barrier};
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("journal");
        let destination = dir.path().join("backup");
        append(&source, proposal()).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let writer_path = source.clone();
        let writer_barrier = Arc::clone(&barrier);
        let writer = std::thread::spawn(move || {
            writer_barrier.wait();
            for _ in 0..20 { append(&writer_path, proposal()).unwrap(); }
        });
        barrier.wait();
        let count = backup(&source, &destination).unwrap();
        writer.join().unwrap();
        let backup_events = read(&destination).unwrap();
        let all_events = read(&source).unwrap();
        assert_eq!(count, backup_events.len());
        assert!((1..=21).contains(&count));
        assert_eq!(backup_events, all_events[..count]);
        assert!(std::fs::read(&source).unwrap().starts_with(&std::fs::read(&destination).unwrap()));
    }
    #[test]
    fn concurrent_writers_get_distinct_ids_and_leave_a_valid_journal() {
        use std::sync::{Arc, Barrier};
        let path = path();
        let barrier = Arc::new(Barrier::new(12));
        let threads: Vec<_> = (0..12).map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                append(&path, proposal()).unwrap()
            })
        }).collect();
        let mut ids: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        ids.sort_unstable();
        assert_eq!(ids, (1..=12).collect::<Vec<_>>());
        assert_eq!(read(&path).unwrap().len(), 12);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn oversized_journals_and_appends_are_rejected() {
        let path = path();
        std::fs::write(&path, vec![b'x'; MAX_JOURNAL_BYTES as usize + 1]).unwrap();
        assert_eq!(read(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(append(&path, proposal()).is_err());
        std::fs::remove_file(&path).unwrap();
        let huge = Event::Proposed { goal: "x".repeat(MAX_JOURNAL_BYTES as usize), hypothesis: "h".into(), test: "t".into() };
        assert!(append(&path, huge).is_err());
        assert!(!path.exists());
    }
    #[test]
    fn json_escaping_cannot_bypass_serialized_size_limit() {
        let path = path();
        let huge = Event::Proposed {
            goal: "\0".repeat(MAX_JOURNAL_BYTES as usize / 5),
            hypothesis: "h".into(), test: "t".into(),
        };
        assert_eq!(append(&path, huge).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(!path.exists());
    }
    #[cfg(unix)]
    #[test]
    fn fifo_is_rejected_without_waiting_for_a_writer() {
        let path = path();
        assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
        assert_eq!(read(&path).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(append(&path, proposal()).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn empty_fields_are_rejected() {
        let path = path();
        assert!(append(&path, Event::Proposed { goal: " ".into(), hypothesis: "h".into(), test: "t".into() }).is_err());
        assert!(!path.exists());
    }
}
