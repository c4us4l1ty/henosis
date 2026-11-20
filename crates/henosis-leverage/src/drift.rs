//! Artifact drift detection for crux journals.
//!
//! Scans a crux journal for `CommandResult` events and checks whether each
//! recorded artifact still matches its recorded SHA-256 digest. Drift means
//! the artifact file has changed, disappeared, or appeared since the command
//! ran — it is an observation, not proof of tampering or misconduct.
//!
//! Honest boundaries: a missing hash means the evidence was recorded before
//! artifact observation existed, not that anything is wrong. A changed hash
//! means the bytes differ; it does not say who changed them or why.

use henosis_crux::Event;
use henosis_evidence::compare_artifact;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io;
use std::path::Path;

/// Whether a single artifact has drifted since its command ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftStatus {
    /// Current SHA-256 matches the recorded digest.
    Unchanged,
    /// Current SHA-256 differs from the recorded digest.
    Changed,
    /// The artifact file no longer exists.
    Missing,
    /// No digest was recorded (legacy evidence) or the digest is unreadable.
    Unavailable,
}

impl DriftStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Changed => "changed",
            Self::Missing => "missing",
            Self::Unavailable => "unavailable",
        }
    }
}

/// One CommandResult event plus its current artifact drift status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftEntry {
    /// One-based position of the event in the journal.
    pub event_position: u64,
    /// Proposal ID the result belongs to.
    pub proposal_id: u64,
    /// Attempt number, if the result references one.
    pub attempt: Option<u64>,
    /// Project directory the artifact lives in.
    pub project: String,
    /// Relative artifact path within the project.
    pub artifact: String,
    /// SHA-256 recorded at run time, if any.
    pub recorded_sha256: Option<String>,
    /// SHA-256 read now, if the file exists and is readable.
    pub current_sha256: Option<String>,
    pub status: DriftStatus,
    /// Whether the command run timed out.
    pub evidence_timed_out: bool,
    /// Actual exit code, if the process finished.
    pub exit_code: Option<i32>,
    /// Exit code the caller expected.
    pub expected_exit: i32,
}

/// Aggregate drift report for a journal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftReport {
    pub total: usize,
    pub unchanged: usize,
    pub changed: usize,
    pub missing: usize,
    pub unavailable: usize,
    pub entries: Vec<DriftEntry>,
}

impl DriftReport {
    /// Fraction of entries whose current state cannot be confirmed unchanged.
    pub fn drift_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.changed + self.missing + self.unavailable) as f64 / self.total as f64
    }

    /// Entries that warrant operator review: changed, missing, or unavailable.
    pub fn review_targets(&self) -> Vec<&DriftEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.status, DriftStatus::Changed | DriftStatus::Missing | DriftStatus::Unavailable))
            .collect()
    }
}

/// Scan a crux journal for artifact drift.
///
/// Reads every `CommandResult` event and re-hashes its artifact. The journal
/// must be a valid crux journal; errors propagate from [`henosis_crux::read`].
/// Artifact re-hashing uses [`henosis_evidence::compare_artifact`], which is
/// bounded to 64 MiB and rejects FIFOs and non-regular files.
pub fn detect_drift(path: &Path) -> io::Result<DriftReport> {
    let events = henosis_crux::read(path)?;
    let mut entries = Vec::new();
    let mut unchanged = 0usize;
    let mut changed = 0usize;
    let mut missing = 0usize;
    let mut unavailable = 0usize;

    for (index, event) in events.iter().enumerate() {
        let Event::CommandResult {
            proposal,
            attempt,
            evidence,
        } = event
        else {
            continue;
        };

        let event_position = u64::try_from(index)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| io::Error::other("journal is too large"))?;

        let recorded = evidence.artifact_sha256.as_deref();
        let comparison = compare_artifact(evidence);

        let (status, current_sha256) = match comparison {
            Ok(comparison) => {
                if comparison.matches {
                    unchanged += 1;
                    (DriftStatus::Unchanged, Some(comparison.current.clone()))
                } else {
                    changed += 1;
                    (DriftStatus::Changed, Some(comparison.current.clone()))
                }
            }
            Err(error) => match error.kind() {
                io::ErrorKind::NotFound => {
                    missing += 1;
                    (DriftStatus::Missing, None)
                }
                _ => {
                    unavailable += 1;
                    (DriftStatus::Unavailable, None)
                }
            },
        };

        entries.push(DriftEntry {
            event_position,
            proposal_id: *proposal,
            attempt: *attempt,
            project: evidence.project.clone(),
            artifact: evidence.artifact.clone(),
            recorded_sha256: recorded.map(String::from),
            current_sha256,
            status,
            evidence_timed_out: evidence.timed_out,
            exit_code: evidence.exit_code,
            expected_exit: evidence.expected_exit,
        });
    }

    entries.sort_by_key(|a| a.event_position);

    Ok(DriftReport {
        total: entries.len(),
        unchanged,
        changed,
        missing,
        unavailable,
        entries,
    })
}

/// Merge two drift reports by event position, deduplicating on position
/// (first occurrence wins).
pub fn merge_reports(a: DriftReport, b: DriftReport) -> DriftReport {
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut entries: Vec<DriftEntry> = Vec::new();

    for entry in a.entries.into_iter().chain(b.entries) {
        if seen.insert(entry.event_position) {
            entries.push(entry);
        }
    }

    entries.sort_by_key(|a| a.event_position);

    let mut unchanged = 0usize;
    let mut changed = 0usize;
    let mut missing = 0usize;
    let mut unavailable = 0usize;
    for entry in &entries {
        match entry.status {
            DriftStatus::Unchanged => unchanged += 1,
            DriftStatus::Changed => changed += 1,
            DriftStatus::Missing => missing += 1,
            DriftStatus::Unavailable => unavailable += 1,
        }
    }

    DriftReport {
        total: entries.len(),
        unchanged,
        changed,
        missing,
        unavailable,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "henosis-drift-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    #[test]
    fn empty_journal_produces_empty_report() {
        let path = temp_path();
        std::fs::write(&path, b"").unwrap();
        let report = detect_drift(&path).unwrap();
        assert_eq!(report.total, 0);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.changed, 0);
        assert_eq!(report.missing, 0);
        assert_eq!(report.unavailable, 0);
        assert_eq!(report.drift_rate(), 0.0);
        assert!(report.review_targets().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drift_rate_and_review_targets() {
        let report = DriftReport {
            total: 3,
            unchanged: 1,
            changed: 1,
            missing: 1,
            unavailable: 0,
            entries: vec![
                DriftEntry {
                    event_position: 1,
                    proposal_id: 1,
                    attempt: None,
                    project: "/tmp".into(),
                    artifact: "a.txt".into(),
                    recorded_sha256: Some("h1".into()),
                    current_sha256: Some("h1".into()),
                    status: DriftStatus::Unchanged,
                    evidence_timed_out: false,
                    exit_code: Some(0),
                    expected_exit: 0,
                },
                DriftEntry {
                    event_position: 2,
                    proposal_id: 1,
                    attempt: None,
                    project: "/tmp".into(),
                    artifact: "b.txt".into(),
                    recorded_sha256: Some("old".into()),
                    current_sha256: Some("new".into()),
                    status: DriftStatus::Changed,
                    evidence_timed_out: false,
                    exit_code: Some(0),
                    expected_exit: 0,
                },
                DriftEntry {
                    event_position: 3,
                    proposal_id: 1,
                    attempt: None,
                    project: "/tmp".into(),
                    artifact: "gone.txt".into(),
                    recorded_sha256: Some("hash".into()),
                    current_sha256: None,
                    status: DriftStatus::Missing,
                    evidence_timed_out: false,
                    exit_code: Some(0),
                    expected_exit: 0,
                },
            ],
        };
        assert_eq!(report.total, 3);
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.changed, 1);
        assert_eq!(report.missing, 1);
        assert!((report.drift_rate() - 2.0 / 3.0).abs() < f64::EPSILON);
        assert_eq!(report.review_targets().len(), 2);
    }

    #[test]
    fn merge_deduplicates_by_position_first_wins() {
        let entry = |pos: u64, status: DriftStatus| DriftEntry {
            event_position: pos,
            proposal_id: 1,
            attempt: None,
            project: "/tmp".into(),
            artifact: "a.txt".into(),
            recorded_sha256: Some("h".into()),
            current_sha256: Some("h".into()),
            status,
            evidence_timed_out: false,
            exit_code: Some(0),
            expected_exit: 0,
        };

        let a = DriftReport {
            total: 2,
            unchanged: 1,
            changed: 1,
            missing: 0,
            unavailable: 0,
            entries: vec![
                entry(1, DriftStatus::Unchanged),
                entry(2, DriftStatus::Changed),
            ],
        };
        let b = DriftReport {
            total: 1,
            unchanged: 0,
            changed: 0,
            missing: 0,
            unavailable: 1,
            entries: vec![entry(1, DriftStatus::Unavailable)],
        };

        let merged = merge_reports(a, b);
        assert_eq!(merged.total, 2);
        assert_eq!(merged.entries[0].status, DriftStatus::Unchanged);
        assert_eq!(merged.entries[1].status, DriftStatus::Changed);
    }
}
