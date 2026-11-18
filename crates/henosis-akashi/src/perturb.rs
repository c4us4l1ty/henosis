//! Controlled perturbation harness and Operator 07 (`PredictFailure`) evaluator.
//!
//! Each perturbation case runs inside a fresh [`henosis_jail::worktree::Worktree`]
//! copy so the user's original project directory is never modified. Observed
//! breakdowns are compiled directly into [`FailureRecord`] entries for the
//! Worldline Failure Atlas.
//!
//! Security note: uses `henosis-evidence` on trusted executables only; worktree
//! cloning prevents accidental project mutation, not malicious sandbox escape.

use crate::evidence_digest;
use henosis_dag::{validate_id, FailureRecord};
use henosis_jail::worktree::Worktree;
use henosis_vault::hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

const MAX_CASES: usize = 64;
const MAX_MUTATION_BYTES: usize = 1024 * 1024;

/// Controlled edit applied inside a disposable worktree clone before execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileMutation {
    WriteFile {
        path: String,
        content: String,
    },
    /// Replace every occurrence of `find` with `replace`. Fails if `find` is absent
    /// so a mistyped perturbation cannot silently behave like an unperturbed run.
    ReplaceExact {
        path: String,
        find: String,
        replace: String,
    },
    AppendText {
        path: String,
        text: String,
    },
    RemoveFile {
        path: String,
    },
}

/// User prediction committed *before* executing a perturbation case (Operator 07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "expect", rename_all = "snake_case", deny_unknown_fields)]
pub enum PredictedOutcome {
    /// System should remain inside its valid regime and produce its artifact.
    Survive { expected_exit: i32 },
    /// System should break (time out or exit with something other than `baseline_exit`).
    Break { baseline_exit: i32, reason: String },
}

/// Specification of one adversarial or boundary-probing perturbation test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerturbationCase {
    pub id: String,
    pub assumption_tested: String,
    pub trigger_description: String,
    pub mutations: Vec<FileMutation>,
    pub prediction: PredictedOutcome,
    pub artifact: String,
    /// Absolute path to a trusted executable, or `@worktree/<relative>` to run
    /// a compiled executable copied into the isolated worktree.
    pub program: String,
    #[serde(default)]
    pub arguments: Vec<String>,
}

/// Four-way classification comparing pre-run prediction against observed outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionVerdict {
    /// Predicted survival and the run succeeded with a readable artifact.
    ConfirmedResilience,
    /// Predicted failure and the run indeed broke (non-baseline exit or timeout).
    ConfirmedBreak,
    /// Predicted survival, but the perturbation broke the run (hidden fragility!).
    UnexpectedBreak,
    /// Predicted failure, but the run still succeeded (model mismatch or weak test).
    UnexpectedSurvival,
}

impl PredictionVerdict {
    pub fn prediction_accurate(self) -> bool {
        matches!(self, Self::ConfirmedResilience | Self::ConfirmedBreak)
    }

    pub fn broke(self) -> bool {
        matches!(self, Self::ConfirmedBreak | Self::UnexpectedBreak)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfirmedResilience => "confirmed_resilience",
            Self::ConfirmedBreak => "confirmed_break",
            Self::UnexpectedBreak => "unexpected_break",
            Self::UnexpectedSurvival => "unexpected_survival",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerturbationOutcome {
    pub case_id: String,
    pub assumption_tested: String,
    pub trigger_description: String,
    pub verdict: PredictionVerdict,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub artifact_sha256: Option<String>,
    pub evidence_sha256: String,
    pub observed_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerturbationSuiteReport {
    pub target_id: String,
    pub outcomes: Vec<PerturbationOutcome>,
    pub accurate_predictions: usize,
    pub exposed_failures: Vec<FailureRecord>,
    pub report_sha256: String,
}

fn apply_mutation(worktree: &Worktree, mutation: &FileMutation) -> io::Result<()> {
    match mutation {
        FileMutation::WriteFile { path, content } => {
            if content.len() > MAX_MUTATION_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mutation content exceeds 1 MiB",
                ));
            }
            let target = worktree.resolve_relative(path)?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(target, content.as_bytes())
        }
        FileMutation::ReplaceExact {
            path,
            find,
            replace,
        } => {
            if find.is_empty() || replace.len() > MAX_MUTATION_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ReplaceExact requires non-empty search text and bounded replacement",
                ));
            }
            let target = worktree.resolve_relative(path)?;
            let original = fs::read_to_string(&target)?;
            if !original.contains(find.as_str()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("perturbation pattern not found in '{path}'"),
                ));
            }
            let updated = original.replace(find.as_str(), replace.as_str());
            if updated.len() > MAX_MUTATION_BYTES * 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "perturbed file exceeds size limit",
                ));
            }
            fs::write(target, updated.as_bytes())
        }
        FileMutation::AppendText { path, text } => {
            if text.len() > MAX_MUTATION_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "appended perturbation exceeds 1 MiB",
                ));
            }
            let target = worktree.resolve_relative(path)?;
            let mut file = OpenOptions::new().append(true).open(target)?;
            file.write_all(text.as_bytes())
        }
        FileMutation::RemoveFile { path } => {
            let target = worktree.resolve_relative(path)?;
            fs::remove_file(target)
        }
    }
}

fn resolve_program(worktree: &Worktree, program: &str) -> io::Result<String> {
    if let Some(rel) = program.strip_prefix("@worktree/") {
        let resolved = worktree.resolve_relative(rel)?;
        resolved.to_str().map(str::to_owned).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "worktree executable path is not valid UTF-8",
            )
        })
    } else {
        Ok(program.to_owned())
    }
}

/// Run a suite of perturbation cases against fresh temporary clones of
/// `source_project`, scoring failure predictions and collecting Failure Atlas records.
pub fn run_suite(
    source_project: &Path,
    target_id: &str,
    cases: &[PerturbationCase],
) -> io::Result<PerturbationSuiteReport> {
    validate_id(target_id).map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    if cases.is_empty() || cases.len() > MAX_CASES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "perturbation suite must contain 1..=64 cases",
        ));
    }

    let mut outcomes = Vec::with_capacity(cases.len());
    let mut exposed_failures = Vec::new();
    let mut accurate_predictions = 0usize;

    for case in cases {
        validate_id(&case.id).map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
        if case.assumption_tested.trim().is_empty() || case.trigger_description.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "perturbation case requires non-empty assumption_tested and trigger_description",
            ));
        }

        let worktree = Worktree::clone_from(source_project)?;
        for mutation in &case.mutations {
            apply_mutation(&worktree, mutation)?;
        }
        let project_str = worktree.path().to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "temporary worktree path is not valid UTF-8",
            )
        })?;
        let executable = resolve_program(&worktree, &case.program)?;
        let nominal_exit = match &case.prediction {
            PredictedOutcome::Survive { expected_exit } => *expected_exit,
            PredictedOutcome::Break { baseline_exit, .. } => *baseline_exit,
        };

        let evidence = henosis_evidence::run(
            project_str,
            &case.artifact,
            nominal_exit,
            &executable,
            &case.arguments,
        )?;
        let ev_sha = evidence_digest(&evidence);

        let (verdict, predicted_text) = match &case.prediction {
            PredictedOutcome::Survive { expected_exit } => {
                let survived = !evidence.timed_out
                    && evidence.exit_code == Some(*expected_exit)
                    && evidence.artifact_sha256.is_some();
                let v = if survived {
                    PredictionVerdict::ConfirmedResilience
                } else {
                    PredictionVerdict::UnexpectedBreak
                };
                (v, format!("survive with exit {expected_exit}"))
            }
            PredictedOutcome::Break {
                baseline_exit,
                reason,
            } => {
                let broke = evidence.timed_out || evidence.exit_code != Some(*baseline_exit);
                let v = if broke {
                    PredictionVerdict::ConfirmedBreak
                } else {
                    PredictionVerdict::UnexpectedSurvival
                };
                (v, format!("break (exit != {baseline_exit}): {reason}"))
            }
        };

        if verdict.prediction_accurate() {
            accurate_predictions += 1;
        }

        let stderr_snippet: String = evidence
            .stderr
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_control())
            .take(160)
            .collect();
        let observed_summary = if evidence.timed_out {
            "timed out under perturbation".to_owned()
        } else if stderr_snippet.is_empty() {
            format!("exit={:?}, artifact={}", evidence.exit_code, evidence.artifact_sha256.is_some())
        } else {
            format!("exit={:?}: {stderr_snippet}", evidence.exit_code)
        };

        if verdict.broke() {
            exposed_failures.push(FailureRecord {
                id: format!("fail-{}-{}", target_id, case.id)
                    .chars()
                    .take(96)
                    .collect(),
                target_id: target_id.to_owned(),
                broken_assumption: case.assumption_tested.clone(),
                trigger: case.trigger_description.clone(),
                predicted: predicted_text,
                observed: observed_summary.clone(),
                evidence_sha256: Some(ev_sha.clone()),
            });
        }

        outcomes.push(PerturbationOutcome {
            case_id: case.id.clone(),
            assumption_tested: case.assumption_tested.clone(),
            trigger_description: case.trigger_description.clone(),
            verdict,
            exit_code: evidence.exit_code,
            timed_out: evidence.timed_out,
            artifact_sha256: evidence.artifact_sha256,
            evidence_sha256: ev_sha,
            observed_summary,
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(b"henosis.akashi.perturbation.v1\0");
    hasher.update(target_id.as_bytes());
    hasher.update(
        serde_json::to_vec(&outcomes).map_err(io::Error::other)?,
    );
    let report_sha256 = hex::encode(&hasher.finalize());

    Ok(PerturbationSuiteReport {
        target_id: target_id.to_owned(),
        outcomes,
        accurate_predictions,
        exposed_failures,
        report_sha256,
    })
}
