#![deny(unsafe_code)]
//! A deliberately modest, user-authored record of goals and falsification tests.
//! Records and estimates are user assertions, not verified capabilities.

use serde::{Deserialize, Serialize};
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

fn read_file(file: &File) -> io::Result<Vec<Event>> {
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
    for (index, line) in bytes.strip_suffix(b"\n").unwrap_or(&[]).split(|byte| *byte == b'\n').enumerate() {
        if bytes.is_empty() { break; }
        let number = index + 1;
        let event: Event = serde_json::from_slice(line).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid journal line {number}: {error}"))
        })?;
        validate(&events, &event).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid journal line {number}: {error}"))
        })?;
        events.push(event);
    }
    Ok(events)
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

fn validate(events: &[Event], event: &Event) -> io::Result<()> {
    let nonempty = |s: &str| !s.trim().is_empty();
    let is_proposal = |id: &u64| id.checked_sub(1)
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| events.get(n))
        .is_some_and(|event| matches!(event, Event::Proposed { .. }));
    let valid = match event {
        Event::Proposed { goal, hypothesis, test } => nonempty(goal) && nonempty(hypothesis) && nonempty(test),
        Event::Observed { proposal, outcome } => nonempty(outcome) && is_proposal(proposal),
        Event::StatusChanged { proposal, reason, .. } => nonempty(reason) && is_proposal(proposal),
        Event::Assessed { proposal, information, failure, cost } => {
            is_proposal(proposal) && [*information, *failure, *cost].iter().all(|n| (1..=5).contains(n))
        }
    };
    if valid { Ok(()) } else { Err(io::Error::new(io::ErrorKind::InvalidInput, "fields must be nonempty, references must name an existing proposal, and estimates must be between 1 and 5")) }
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
    for (index, event) in events.iter().enumerate() {
        validate(&events[..index], event)?;
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
pub fn append(path: &Path, event: Event) -> io::Result<u64> {
    // Reject invalid proposals before creating a new file.
    if matches!(&event, Event::Proposed { .. }) { validate(&[], &event)?; }
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
    validate(&events, &event)?;
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
