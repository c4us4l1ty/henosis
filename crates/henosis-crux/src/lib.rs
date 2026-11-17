#![deny(unsafe_code)]
//! A deliberately modest, user-authored record of goals and falsification tests.
//! Records are observations, not verified capabilities or an automated crux ranking.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Proposed { goal: String, hypothesis: String, test: String },
    Observed { proposal: u64, outcome: String },
}

/// Read the entire append-only journal. Proposal IDs are one-based event positions.
/// Invalid or truncated records are errors, never silently skipped.
pub fn read(path: &Path) -> io::Result<Vec<Event>> {
    let file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut events = Vec::new();
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 { break; }
        let number = events.len() + 1;
        if !line.ends_with('\n') {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("truncated journal line {number}")));
        }
        let event: Event = serde_json::from_str(&line).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid journal line {number}: {error}"))
        })?;
        validate(&events, &event).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid journal line {number}: {error}"))
        })?;
        events.push(event);
    }
    Ok(events)
}

fn validate(events: &[Event], event: &Event) -> io::Result<()> {
    let nonempty = |s: &str| !s.trim().is_empty();
    let valid = match event {
        Event::Proposed { goal, hypothesis, test } => nonempty(goal) && nonempty(hypothesis) && nonempty(test),
        Event::Observed { proposal, outcome } => {
            nonempty(outcome) && proposal.checked_sub(1)
                .and_then(|n| usize::try_from(n).ok())
                .and_then(|n| events.get(n))
                .is_some_and(|event| matches!(event, Event::Proposed { .. }))
        }
    };
    if valid { Ok(()) } else { Err(io::Error::new(io::ErrorKind::InvalidInput, "fields must be nonempty and observations must reference an existing proposal")) }
}

/// Append one event and return its one-based position. This journal is plaintext
/// and intended for a single writer; it is not encrypted, signed, or tamper-evident.
pub fn append(path: &Path, event: Event) -> io::Result<u64> {
    let events = read(path)?;
    validate(&events, &event)?;
    let id = u64::try_from(events.len()).ok().and_then(|n| n.checked_add(1))
        .ok_or_else(|| io::Error::other("journal is too large"))?;
    let mut record = serde_json::to_vec(&event).map_err(io::Error::other)?;
    record.push(b'\n');
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
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
        assert!(read(&path).unwrap().is_empty());
        assert!(append(&path, Event::Observed { proposal: 1, outcome: "No".into() }).is_err());
        assert_eq!(append(&path, proposal()).unwrap(), 1);
        let observation = Event::Observed { proposal: 1, outcome: "Unexpected loss".into() };
        assert_eq!(append(&path, observation.clone()).unwrap(), 2);
        assert_eq!(read(&path).unwrap(), vec![proposal(), observation]);
        assert!(append(&path, Event::Observed { proposal: 2, outcome: "x".into() }).is_err());
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
    fn empty_fields_are_rejected() {
        let path = path();
        assert!(append(&path, Event::Proposed { goal: " ".into(), hypothesis: "h".into(), test: "t".into() }).is_err());
        assert!(!path.exists());
    }
}
