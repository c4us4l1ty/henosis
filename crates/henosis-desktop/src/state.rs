//! Structured desktop state, file-change synchronization, and non-blocking actions.
use henosis_akashi::{
    build_bundle, load_bundle, run_suite, save_bundle, verify_from_evidence,
    verify_from_perturbation, written_artifact_digest, BundleInput, PerturbationCase,
    PerturbationSuiteReport,
};
use henosis_crux::Event as CruxEvent;
use henosis_dag::{
    AssistanceProvenance, Commit, CsrHypergraph, EntityKind, EpistemicStatus, FailureRecord, Node,
    ProofOperator, QuarantineItem, RealizationContract, VerificationEntry, WorldState, Worldline,
    WorldlineOp,
};
use henosis_evidence::{Evidence, Request as ExperimentRequest};
use henosis_leverage::{detect_drift, DriftReport};
use henosis_proxy::{
    impedance::ImpedanceMode, BlackoutReceipt, ExposureRecord, ProxyServer, SessionBudget,
    UpstreamTarget,
};
use henosis_vault::{
    keyring::{AuthScheme, UnlockedVault},
    Identity,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Crux,
    Worldline,
    Akashi,
    VaultProxy,
    Processes,
    Settings,
}

impl Page {
    pub const PRIMARY: [Self; 5] = [
        Self::Crux,
        Self::Worldline,
        Self::Akashi,
        Self::VaultProxy,
        Self::Processes,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Crux => "Crux",
            Self::Worldline => "Worldline",
            Self::Akashi => "Akashi",
            Self::VaultProxy => "Vault & Proxy",
            Self::Processes => "Processes",
            Self::Settings => "Settings",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CruxFilter {
    Open,
    Ranked,
    Closed,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CruxInlinePanel {
    Observe(u64),
    Score(u64),
    Run(u64),
    Close(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldlineSubtab {
    Nodes,
    Contracts,
    Quarantine,
    Failures,
    History,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AkashiMethod {
    CommandResult,
    WrittenArtifact,
    PerturbationSuite,
    BundleTransfer,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProposalCard {
    pub id: u64,
    pub goal: String,
    pub hypothesis: String,
    pub test: String,
    pub closed: bool,
    pub latest_score: Option<(u8, u8, u8)>,
    pub rank_position: Option<usize>,
    pub history: Vec<(u64, CruxEvent)>,
}

#[derive(Debug, Clone, Default)]
pub struct CruxSnapshot {
    pub exists: bool,
    pub proposals: Vec<ProposalCard>,
    pub unfinished: Vec<(u64, u64)>,
    pub command_results: Vec<(u64, u64, Evidence)>,
    pub drift: Option<DriftReport>,
    pub load_error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WorldlineSnapshot {
    pub exists: bool,
    pub worldline: Option<Worldline>,
    pub state: WorldState,
    pub hypergraph: Option<CsrHypergraph>,
    pub commits: Vec<Commit>,
    pub load_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    path: String,
    exists: bool,
    len: u64,
    modified: Option<SystemTime>,
}

impl FileStamp {
    fn probe(path_str: &str) -> Self {
        let trimmed = path_str.trim();
        if trimmed.is_empty() {
            return Self {
                path: String::new(),
                exists: false,
                len: 0,
                modified: None,
            };
        }
        match std::fs::metadata(trimmed) {
            Ok(meta) => Self {
                path: trimmed.to_owned(),
                exists: true,
                len: meta.len(),
                modified: meta.modified().ok(),
            },
            Err(_) => Self {
                path: trimmed.to_owned(),
                exists: false,
                len: 0,
                modified: None,
            },
        }
    }
}

pub enum AsyncNotice {
    CruxRunFinished {
        proposal: u64,
        result: Result<String, String>,
    },
    PerturbFinished {
        target_id: String,
        result: Result<(PerturbationSuiteReport, Option<String>), String>,
    },
}

pub struct WorkspaceData {
    pub page: Page,
    pub crux_path: String,
    pub worldline_path: String,
    pub vault_path: String,

    crux_stamp: Option<FileStamp>,
    worldline_stamp: Option<FileStamp>,
    pub crux: CruxSnapshot,
    pub worldline: WorldlineSnapshot,

    // Status & compact bottom drawer
    pub status_line: String,
    pub status_is_error: bool,
    pub drawer_open: bool,

    // Background task channel (keeps 30s runs off the UI thread)
    async_tx: mpsc::Sender<AsyncNotice>,
    async_rx: mpsc::Receiver<AsyncNotice>,
    pub running_task: Option<String>,

    // Crux UI state
    pub crux_filter: CruxFilter,
    pub crux_search: String,
    pub crux_new_open: bool,
    pub crux_goal: String,
    pub crux_hypothesis: String,
    pub crux_test: String,
    pub crux_inline: Option<CruxInlinePanel>,
    pub crux_expanded_history: BTreeSet<u64>,
    pub crux_outcome_draft: String,
    pub crux_info_score: u8,
    pub crux_fail_score: u8,
    pub crux_cost_score: u8,
    pub crux_close_reason: String,
    pub crux_review_notes: BTreeMap<u64, String>,
    pub crux_run_project: String,
    pub crux_run_artifact: String,
    pub crux_run_exit: String,
    pub crux_run_program: String,
    pub crux_run_args: String,
    pub crux_run_env_keys: String,
    pub crux_backup_dest: String,

    // Worldline UI state
    pub wl_subtab: WorldlineSubtab,
    pub wl_selected_goal_contract: Option<String>,
    pub wl_new_branch: String,
    pub wl_merge_source: String,
    pub wl_merge_rationale: String,
    pub wl_add_open: bool,
    pub wl_node_id: String,
    pub wl_node_kind_idx: usize,
    pub wl_node_title: String,
    pub wl_node_domain: String,
    pub wl_node_summary: String,
    pub wl_contract_id: String,
    pub wl_contract_title: String,
    pub wl_contract_output: String,
    pub wl_contract_verification: String,
    pub wl_contract_cost: String,
    pub wl_contract_prereqs: String,
    pub wl_fail_id: String,
    pub wl_fail_target: String,
    pub wl_fail_assumption: String,
    pub wl_fail_trigger: String,
    pub wl_fail_predicted: String,
    pub wl_fail_observed: String,
    pub wl_expose_id: String,
    pub wl_expose_source: String,
    pub wl_expose_topic: String,
    pub wl_expose_notes: String,
    pub wl_resolve_targets: BTreeMap<String, String>,

    // Akashi UI state
    pub akashi_method: AkashiMethod,
    pub akashi_node_id: String,
    pub akashi_operator_idx: usize,
    pub akashi_provenance_idx: usize,
    pub akashi_selected_result_id: Option<u64>,
    pub akashi_summary: String,
    pub akashi_attach_blackout: bool,
    pub akashi_written_text: String,
    pub akashi_perturb_cases_path: String,
    pub akashi_perturb_project_dir: String,
    pub akashi_last_perturb: Option<PerturbationSuiteReport>,
    pub akashi_bundle_path: String,
    pub akashi_bundle_scope: String,
    pub akashi_sign_bundle: bool,
    pub akashi_last_inspected_bundle: Option<String>,

    // Vault & Proxy UI state
    pub vault: Option<UnlockedVault>,
    pub active_identity: Option<Identity>,
    pub vault_password: String,
    pub vault_passphrase: String,
    pub session_mnemonic_input: String,
    pub pending_backup_mnemonic: Option<Zeroizing<String>>,
    pub cred_name: String,
    pub cred_scheme_idx: usize,
    pub cred_url: String,
    pub cred_secret: String,

    pub proxy: Option<ProxyServer>,
    pub session_label_input: String,
    pub session_provider_input: String,
    pub session_max_requests: String,
    pub last_minted_token: Option<Zeroizing<String>>,
    pub last_blackout_receipt: Option<BlackoutReceipt>,

    // Processes UI state
    pub proc_program: String,
    pub proc_args: String,
    pub proc_as_group: bool,
}

impl Default for WorkspaceData {
    fn default() -> Self {
        let (async_tx, async_rx) = mpsc::channel();
        let default_project = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| ".".into());
        Self {
            page: Page::Crux,
            crux_path: "crux.jsonl".into(),
            worldline_path: "worldline.json".into(),
            vault_path: "vault.hnv".into(),
            crux_stamp: None,
            worldline_stamp: None,
            crux: CruxSnapshot::default(),
            worldline: WorldlineSnapshot::default(),
            status_line: "Ready.".into(),
            status_is_error: false,
            drawer_open: false,
            async_tx,
            async_rx,
            running_task: None,

            crux_filter: CruxFilter::Open,
            crux_search: String::new(),
            crux_new_open: false,
            crux_goal: String::new(),
            crux_hypothesis: String::new(),
            crux_test: String::new(),
            crux_inline: None,
            crux_expanded_history: BTreeSet::new(),
            crux_outcome_draft: String::new(),
            crux_info_score: 3,
            crux_fail_score: 3,
            crux_cost_score: 2,
            crux_close_reason: String::new(),
            crux_review_notes: BTreeMap::new(),
            crux_run_project: default_project.clone(),
            crux_run_artifact: "Cargo.toml".into(),
            crux_run_exit: "0".into(),
            crux_run_program: String::new(),
            crux_run_args: String::new(),
            crux_run_env_keys: String::new(),
            crux_backup_dest: "crux.backup.jsonl".into(),

            wl_subtab: WorldlineSubtab::Nodes,
            wl_selected_goal_contract: None,
            wl_new_branch: String::new(),
            wl_merge_source: String::new(),
            wl_merge_rationale: "Merge branch".into(),
            wl_add_open: false,
            wl_node_id: String::new(),
            wl_node_kind_idx: 0,
            wl_node_title: String::new(),
            wl_node_domain: "core".into(),
            wl_node_summary: String::new(),
            wl_contract_id: String::new(),
            wl_contract_title: String::new(),
            wl_contract_output: String::new(),
            wl_contract_verification: String::new(),
            wl_contract_cost: "1".into(),
            wl_contract_prereqs: String::new(),
            wl_fail_id: String::new(),
            wl_fail_target: String::new(),
            wl_fail_assumption: String::new(),
            wl_fail_trigger: String::new(),
            wl_fail_predicted: String::new(),
            wl_fail_observed: String::new(),
            wl_expose_id: String::new(),
            wl_expose_source: "ai-proxy".into(),
            wl_expose_topic: String::new(),
            wl_expose_notes: String::new(),
            wl_resolve_targets: BTreeMap::new(),

            akashi_method: AkashiMethod::CommandResult,
            akashi_node_id: String::new(),
            akashi_operator_idx: 2, // Reproduce
            akashi_provenance_idx: 0,
            akashi_selected_result_id: None,
            akashi_summary: String::new(),
            akashi_attach_blackout: true,
            akashi_written_text: String::new(),
            akashi_perturb_cases_path: "perturb.json".into(),
            akashi_perturb_project_dir: default_project,
            akashi_last_perturb: None,
            akashi_bundle_path: "capability.hcap".into(),
            akashi_bundle_scope: "Verified on local machine under recorded test inputs.".into(),
            akashi_sign_bundle: true,
            akashi_last_inspected_bundle: None,

            vault: None,
            active_identity: None,
            vault_password: String::new(),
            vault_passphrase: String::new(),
            session_mnemonic_input: String::new(),
            pending_backup_mnemonic: None,
            cred_name: String::new(),
            cred_scheme_idx: 0,
            cred_url: String::new(),
            cred_secret: String::new(),

            proxy: None,
            session_label_input: "agent-1".into(),
            session_provider_input: "local-stub".into(),
            session_max_requests: "64".into(),
            last_minted_token: None,
            last_blackout_receipt: None,

            proc_program: String::new(),
            proc_args: String::new(),
            proc_as_group: true,
        }
    }
}

pub const ENTITY_KINDS: [EntityKind; 11] = [
    EntityKind::Capability,
    EntityKind::Concept,
    EntityKind::Method,
    EntityKind::Problem,
    EntityKind::Constraint,
    EntityKind::Instrument,
    EntityKind::Realization,
    EntityKind::Evidence,
    EntityKind::Hypothesis,
    EntityKind::Opportunity,
    EntityKind::Failure,
];

pub const PROOF_OPERATORS: [ProofOperator; 7] = [
    ProofOperator::Explain,
    ProofOperator::Reconstruct,
    ProofOperator::Implement,
    ProofOperator::Criticize,
    ProofOperator::Modify,
    ProofOperator::Transfer,
    ProofOperator::PredictFailure,
];

pub const PROVENANCES: [(AssistanceProvenance, &str); 4] = [
    (AssistanceProvenance::UnassistedHuman, "Unassisted Human"),
    (AssistanceProvenance::JointHumanAi, "Joint Human + AI"),
    (AssistanceProvenance::External, "External / Peer"),
    (AssistanceProvenance::AiGenerated, "AI Generated"),
];

pub const AUTH_SCHEMES: [(AuthScheme, &str); 2] = [
    (AuthScheme::Bearer, "Bearer (OpenAI-compatible)"),
    (AuthScheme::XApiKey, "x-api-key (Anthropic-compatible)"),
];

impl WorkspaceData {
    pub fn set_ok(&mut self, msg: impl Into<String>) {
        self.status_line = msg.into();
        self.status_is_error = false;
    }

    pub fn set_err(&mut self, msg: impl Into<String>) {
        self.status_line = msg.into();
        self.status_is_error = true;
    }

    pub fn poll_async(&mut self) -> bool {
        let mut changed = false;
        while let Ok(notice) = self.async_rx.try_recv() {
            self.running_task = None;
            changed = true;
            match notice {
                AsyncNotice::CruxRunFinished { proposal, result } => {
                    self.invalidate_files();
                    match result {
                        Ok(summary) => self.set_ok(format!("Proposal #{proposal}: {summary}")),
                        Err(err) => self.set_err(err),
                    }
                }
                AsyncNotice::PerturbFinished { target_id, result } => {
                    self.invalidate_files();
                    match result {
                        Ok((report, commit_note)) => {
                            let summary = format!(
                                "Perturbation '{}': {}/{} accurate, {} failure(s){}",
                                target_id,
                                report.accurate_predictions,
                                report.outcomes.len(),
                                report.exposed_failures.len(),
                                commit_note
                                    .map(|c| format!(" (commit {})", &c[..12.min(c.len())]))
                                    .unwrap_or_default()
                            );
                            self.akashi_last_perturb = Some(report);
                            self.set_ok(summary);
                        }
                        Err(err) => self.set_err(err),
                    }
                }
            }
        }
        changed
    }

    pub fn invalidate_files(&mut self) {
        self.crux_stamp = None;
        self.worldline_stamp = None;
    }

    pub fn sync_files_if_changed(&mut self) {
        let next_crux = FileStamp::probe(&self.crux_path);
        if self.crux_stamp.as_ref() != Some(&next_crux) {
            self.crux = load_crux_snapshot(&next_crux);
            if self.akashi_selected_result_id.is_none() {
                self.akashi_selected_result_id =
                    self.crux.command_results.last().map(|(id, _, _)| *id);
            }
            self.crux_stamp = Some(next_crux);
        }

        let next_wl = FileStamp::probe(&self.worldline_path);
        if self.worldline_stamp.as_ref() != Some(&next_wl) {
            self.worldline = load_worldline_snapshot(&next_wl);
            self.worldline_stamp = Some(next_wl);
        }
    }

    // --- Crux actions ---

    pub fn create_proposal(&mut self) {
        let path = PathBuf::from(self.crux_path.trim());
        if path.as_os_str().is_empty() {
            self.set_err("Choose a Crux journal path in the top bar.");
            return;
        }
        let event = CruxEvent::Proposed {
            goal: self.crux_goal.trim().to_owned(),
            hypothesis: self.crux_hypothesis.trim().to_owned(),
            test: self.crux_test.trim().to_owned(),
        };
        match henosis_crux::append(&path, event) {
            Ok(id) => {
                self.crux_goal.clear();
                self.crux_hypothesis.clear();
                self.crux_test.clear();
                self.crux_new_open = false;
                self.invalidate_files();
                self.sync_files_if_changed();
                self.set_ok(format!("Recorded proposal #{id}."));
            }
            Err(err) => self.set_err(format!("Could not add proposal: {err}")),
        }
    }

    pub fn record_observation(&mut self, proposal: u64) {
        let path = PathBuf::from(self.crux_path.trim());
        let event = CruxEvent::Observed {
            proposal,
            outcome: self.crux_outcome_draft.trim().to_owned(),
        };
        match henosis_crux::append(&path, event) {
            Ok(_) => {
                self.crux_outcome_draft.clear();
                self.crux_inline = None;
                self.invalidate_files();
                self.sync_files_if_changed();
                self.set_ok(format!("Recorded observation on proposal #{proposal}."));
            }
            Err(err) => self.set_err(format!("Could not record observation: {err}")),
        }
    }

    pub fn record_assessment(&mut self, proposal: u64) {
        let path = PathBuf::from(self.crux_path.trim());
        let event = CruxEvent::Assessed {
            proposal,
            information: self.crux_info_score,
            failure: self.crux_fail_score,
            cost: self.crux_cost_score,
        };
        match henosis_crux::append(&path, event) {
            Ok(_) => {
                self.crux_inline = None;
                self.invalidate_files();
                self.sync_files_if_changed();
                self.set_ok(format!("Updated priority score for proposal #{proposal}."));
            }
            Err(err) => self.set_err(format!("Could not score proposal: {err}")),
        }
    }

    pub fn set_proposal_closed(&mut self, proposal: u64, closed: bool, reason: String) {
        let path = PathBuf::from(self.crux_path.trim());
        let event = CruxEvent::StatusChanged {
            proposal,
            closed,
            reason: reason.trim().to_owned(),
        };
        match henosis_crux::append(&path, event) {
            Ok(_) => {
                self.crux_close_reason.clear();
                self.crux_inline = None;
                self.invalidate_files();
                self.sync_files_if_changed();
                let verb = if closed { "Closed" } else { "Reopened" };
                self.set_ok(format!("{verb} proposal #{proposal}."));
            }
            Err(err) => self.set_err(format!("Could not update status: {err}")),
        }
    }

    pub fn review_unfinished_attempt(&mut self, proposal: u64, attempt: u64) {
        let note = self
            .crux_review_notes
            .get(&attempt)
            .cloned()
            .unwrap_or_default();
        let path = PathBuf::from(self.crux_path.trim());
        let event = CruxEvent::AttemptReviewed {
            proposal,
            attempt,
            note: note.trim().to_owned(),
        };
        match henosis_crux::append(&path, event) {
            Ok(_) => {
                self.crux_review_notes.remove(&attempt);
                self.invalidate_files();
                self.sync_files_if_changed();
                self.set_ok(format!("Recorded recovery note for attempt #{attempt}."));
            }
            Err(err) => self.set_err(format!("Could not record review note: {err}")),
        }
    }

    pub fn backup_crux_journal(&mut self) {
        let src = PathBuf::from(self.crux_path.trim());
        let dst = PathBuf::from(self.crux_backup_dest.trim());
        if dst.as_os_str().is_empty() {
            self.set_err("Enter a backup destination path.");
            return;
        }
        match henosis_crux::backup(&src, &dst) {
            Ok(count) => self.set_ok(format!(
                "Saved snapshot of {count} event(s) to {}.",
                dst.display()
            )),
            Err(err) => self.set_err(format!("Backup failed: {err}")),
        }
    }

    pub fn start_crux_experiment(&mut self, proposal: u64) {
        if self.running_task.is_some() {
            self.set_err("Wait for the active background run to finish.");
            return;
        }
        let expected_exit: i32 = match self.crux_run_exit.trim().parse() {
            Ok(code) => code,
            Err(_) => {
                self.set_err("Expected exit code must be an integer (e.g. 0).");
                return;
            }
        };
        let args = match shell_words::split(&self.crux_run_args) {
            Ok(list) => list,
            Err(err) => {
                self.set_err(format!("Invalid argument quoting: {err}"));
                return;
            }
        };
        let env_keys: Vec<String> = self
            .crux_run_env_keys
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let resolved_env = match henosis_evidence::resolve_parent_environment(&env_keys) {
            Ok(env) => env,
            Err(err) => {
                self.set_err(format!("Environment selection failed: {err}"));
                return;
            }
        };

        let project_abs = resolve_project_path(self.crux_run_project.trim());
        let journal_path = PathBuf::from(self.crux_path.trim());
        let request = ExperimentRequest {
            project: project_abs,
            program: self.crux_run_program.trim().to_owned(),
            arguments: args.clone(),
            artifact: self.crux_run_artifact.trim().to_owned(),
            expected_exit,
            env_keys,
        };

        let attempt = match henosis_crux::append(
            &journal_path,
            CruxEvent::ExperimentStarted {
                proposal,
                request: request.clone(),
            },
        ) {
            Ok(id) => id,
            Err(err) => {
                self.set_err(format!("Could not start experiment: {err}"));
                return;
            }
        };

        self.crux_inline = None;
        self.invalidate_files();
        self.sync_files_if_changed();
        self.running_task = Some(format!("Running test for proposal #{proposal}…"));

        let tx = self.async_tx.clone();
        thread::spawn(move || {
            let outcome = match henosis_evidence::run_with_env(
                &request.project,
                &request.artifact,
                request.expected_exit,
                &request.program,
                &args,
                &resolved_env,
            ) {
                Ok(evidence) => {
                    let matched =
                        !evidence.timed_out && evidence.exit_code == Some(evidence.expected_exit);
                    match henosis_crux::append(
                        &journal_path,
                        CruxEvent::CommandResult {
                            proposal,
                            attempt: Some(attempt),
                            evidence: Box::new(evidence),
                        },
                    ) {
                        Ok(res_id) => Ok(format!(
                            "recorded result #{res_id} ({})",
                            if matched { "matched" } else { "mismatch" }
                        )),
                        Err(err) => Err(format!("Result write failed: {err}")),
                    }
                }
                Err(run_err) => {
                    let err_msg = run_err.to_string();
                    let _ = henosis_crux::append(
                        &journal_path,
                        CruxEvent::ExperimentFailed {
                            proposal,
                            attempt,
                            error: err_msg.clone(),
                        },
                    );
                    Err(format!("Runner error: {err_msg}"))
                }
            };
            let _ = tx.send(AsyncNotice::CruxRunFinished {
                proposal,
                result: outcome,
            });
        });
    }

    // --- Worldline actions ---

    pub fn init_worldline(&mut self) {
        let path = PathBuf::from(self.worldline_path.trim());
        if path.as_os_str().is_empty() {
            self.set_err("Choose a Worldline path in the top bar.");
            return;
        }
        match Worldline::create(&path) {
            Ok(_) => {
                self.invalidate_files();
                self.sync_files_if_changed();
                self.set_ok(format!("Created Worldline at {}.", path.display()));
            }
            Err(err) => self.set_err(format!("Could not create Worldline: {err}")),
        }
    }

    fn mutate_worldline(
        &mut self,
        f: impl FnOnce(&mut Worldline, Option<&Identity>) -> Result<String, String>,
    ) {
        let path = PathBuf::from(self.worldline_path.trim());
        let mut wl = match Worldline::load(&path) {
            Ok(wl) => wl,
            Err(err) => {
                self.set_err(format!("Could not load Worldline: {err}"));
                return;
            }
        };
        let signer = self.active_identity.as_ref();
        match f(&mut wl, signer) {
            Ok(msg) => match wl.save(&path) {
                Ok(()) => {
                    self.invalidate_files();
                    self.sync_files_if_changed();
                    self.set_ok(msg);
                }
                Err(err) => self.set_err(format!("Could not save Worldline: {err}")),
            },
            Err(err) => self.set_err(err),
        }
    }

    pub fn checkout_branch(&mut self, branch: &str) {
        let branch_owned = branch.to_owned();
        self.mutate_worldline(|wl, _| {
            wl.checkout(&branch_owned).map_err(|e| e.to_string())?;
            Ok(format!("Switched to branch '{branch_owned}'."))
        });
    }

    pub fn create_branch(&mut self) {
        let name = self.wl_new_branch.trim().to_owned();
        if name.is_empty() {
            self.set_err("Enter a new branch name.");
            return;
        }
        self.mutate_worldline(|wl, _| {
            wl.create_branch(&name, None).map_err(|e| e.to_string())?;
            wl.checkout(&name).map_err(|e| e.to_string())?;
            Ok(format!("Created and switched to branch '{name}'."))
        });
        if !self.status_is_error {
            self.wl_new_branch.clear();
        }
    }

    pub fn merge_branch(&mut self) {
        let src = self.wl_merge_source.trim().to_owned();
        let rationale = self.wl_merge_rationale.trim().to_owned();
        if src.is_empty() {
            self.set_err("Select a branch to merge.");
            return;
        }
        self.mutate_worldline(|wl, signer| {
            let head = wl.head_branch.clone();
            let id = wl
                .merge(&src, &rationale, signer)
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "Merged '{src}' into '{head}' ({}).",
                &id[..12.min(id.len())]
            ))
        });
    }

    pub fn add_worldline_node(&mut self) {
        let node = Node {
            id: self.wl_node_id.trim().to_owned(),
            kind: ENTITY_KINDS[self.wl_node_kind_idx.min(ENTITY_KINDS.len() - 1)],
            title: self.wl_node_title.trim().to_owned(),
            domain: self.wl_node_domain.trim().to_owned(),
            summary: self.wl_node_summary.trim().to_owned(),
            status: EpistemicStatus::Hypothesized,
            provenance: AssistanceProvenance::UnassistedHuman,
            evidence_sha256: Vec::new(),
            proof_operators: Vec::new(),
        };
        let node_id = node.id.clone();
        self.mutate_worldline(|wl, signer| {
            let commit_id = wl
                .commit(
                    format!("Upsert node {node_id}"),
                    vec![WorldlineOp::UpsertNode {
                        node: Box::new(node),
                    }],
                    signer,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "Saved node '{node_id}' ({}).",
                &commit_id[..12.min(commit_id.len())]
            ))
        });
        if !self.status_is_error {
            self.wl_node_id.clear();
            self.wl_node_title.clear();
            self.wl_node_summary.clear();
            self.wl_add_open = false;
        }
    }

    pub fn add_worldline_contract(&mut self) {
        let cost: u32 = match self.wl_contract_cost.trim().parse() {
            Ok(c) => c,
            Err(_) => {
                self.set_err("Contract cost must be a positive integer.");
                return;
            }
        };
        let prereqs: Vec<String> = self
            .wl_contract_prereqs
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let contract = RealizationContract {
            id: self.wl_contract_id.trim().to_owned(),
            title: self.wl_contract_title.trim().to_owned(),
            prerequisites: prereqs,
            assumptions: Vec::new(),
            resources: Vec::new(),
            output: self.wl_contract_output.trim().to_owned(),
            verification: self.wl_contract_verification.trim().to_owned(),
            failure_boundary: Vec::new(),
            status: EpistemicStatus::Observed,
            cost_units: cost,
        };
        let cid = contract.id.clone();
        self.mutate_worldline(|wl, signer| {
            let commit_id = wl
                .commit(
                    format!("Upsert contract {cid}"),
                    vec![WorldlineOp::UpsertContract {
                        contract: Box::new(contract),
                    }],
                    signer,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "Saved contract '{cid}' ({}).",
                &commit_id[..12.min(commit_id.len())]
            ))
        });
        if !self.status_is_error {
            self.wl_contract_id.clear();
            self.wl_contract_title.clear();
            self.wl_contract_output.clear();
            self.wl_contract_verification.clear();
            self.wl_contract_prereqs.clear();
            self.wl_add_open = false;
        }
    }

    pub fn add_worldline_failure(&mut self) {
        let record = FailureRecord {
            id: self.wl_fail_id.trim().to_owned(),
            target_id: self.wl_fail_target.trim().to_owned(),
            broken_assumption: self.wl_fail_assumption.trim().to_owned(),
            trigger: self.wl_fail_trigger.trim().to_owned(),
            predicted: self.wl_fail_predicted.trim().to_owned(),
            observed: self.wl_fail_observed.trim().to_owned(),
            evidence_sha256: None,
        };
        let fid = record.id.clone();
        self.mutate_worldline(|wl, signer| {
            let commit_id = wl
                .commit(
                    format!("Record failure {fid}"),
                    vec![WorldlineOp::RecordFailure {
                        failure: Box::new(record),
                    }],
                    signer,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "Recorded failure '{fid}' ({}).",
                &commit_id[..12.min(commit_id.len())]
            ))
        });
        if !self.status_is_error {
            self.wl_fail_id.clear();
            self.wl_fail_assumption.clear();
            self.wl_fail_trigger.clear();
            self.wl_fail_predicted.clear();
            self.wl_fail_observed.clear();
            self.wl_add_open = false;
        }
    }

    pub fn add_worldline_exposure(&mut self) {
        let item = QuarantineItem {
            id: self.wl_expose_id.trim().to_owned(),
            source: self.wl_expose_source.trim().to_owned(),
            topic: self.wl_expose_topic.trim().to_owned(),
            prompt_sha256: None,
            notes: self.wl_expose_notes.trim().to_owned(),
            resolved_by_node: None,
        };
        let eid = item.id.clone();
        self.mutate_worldline(|wl, signer| {
            let commit_id = wl
                .commit(
                    format!("Quarantine exposure {eid}"),
                    vec![WorldlineOp::EnqueueExposure {
                        item: Box::new(item),
                    }],
                    signer,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "Quarantined '{eid}' ({}).",
                &commit_id[..12.min(commit_id.len())]
            ))
        });
        if !self.status_is_error {
            self.wl_expose_id.clear();
            self.wl_expose_topic.clear();
            self.wl_expose_notes.clear();
            self.wl_add_open = false;
        }
    }

    pub fn quarantine_proxy_record(&mut self, record: &ExposureRecord) {
        let path = PathBuf::from(self.worldline_path.trim());
        if !path.exists() {
            if let Err(err) = Worldline::create(&path) {
                self.set_err(format!("Could not create Worldline: {err}"));
                return;
            }
        }
        let item_id = format!("exp-seq-{}", record.seq);
        let topic = if record.topic_hints.is_empty() {
            record.endpoint.clone()
        } else {
            record.topic_hints.join(", ")
        };
        let item = QuarantineItem {
            id: item_id.clone(),
            source: record
                .provider
                .clone()
                .unwrap_or_else(|| "ai-proxy".to_owned()),
            topic,
            prompt_sha256: Some(record.prompt_sha256.clone()),
            notes: format!(
                "Intercepted under {} mode ({} bytes)",
                record.impedance.as_str(),
                record.prompt_bytes
            ),
            resolved_by_node: None,
        };
        self.mutate_worldline(|wl, signer| {
            let commit_id = wl
                .commit(
                    format!("Quarantine proxy exposure {item_id}"),
                    vec![WorldlineOp::EnqueueExposure {
                        item: Box::new(item),
                    }],
                    signer,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "Quarantined {item_id} in Worldline ({}).",
                &commit_id[..12.min(commit_id.len())]
            ))
        });
    }

    pub fn resolve_quarantine(&mut self, exposure_id: &str) {
        let Some(node_id) = self.wl_resolve_targets.get(exposure_id).cloned() else {
            self.set_err("Choose a verified capability node first.");
            return;
        };
        if node_id.trim().is_empty() {
            self.set_err("Choose a verified capability node first.");
            return;
        }
        let exp_owned = exposure_id.to_owned();
        self.mutate_worldline(|wl, signer| {
            wl.commit(
                format!("Resolve exposure {exp_owned} via {node_id}"),
                vec![WorldlineOp::ResolveExposure {
                    exposure_id: exp_owned.clone(),
                    resolved_by_node: node_id.clone(),
                }],
                signer,
            )
            .map_err(|e| e.to_string())?;
            Ok(format!("Resolved '{exp_owned}' with '{node_id}'."))
        });
    }

    // --- Akashi actions ---

    pub fn jump_to_akashi(&mut self, node_id: Option<&str>, result_id: Option<u64>) {
        if let Some(nid) = node_id {
            self.akashi_node_id = nid.to_owned();
        }
        if let Some(rid) = result_id {
            self.akashi_selected_result_id = Some(rid);
            self.akashi_method = AkashiMethod::CommandResult;
        }
        self.page = Page::Akashi;
    }

    fn ensure_worldline_ready(&mut self) -> Result<PathBuf, String> {
        let path = PathBuf::from(self.worldline_path.trim());
        if path.as_os_str().is_empty() {
            return Err("Choose a Worldline file path in the top bar.".into());
        }
        if !path.exists() {
            Worldline::create(&path).map_err(|e| e.to_string())?;
        }
        Ok(path)
    }

    fn commit_verification(&mut self, entry: VerificationEntry) {
        let path = match self.ensure_worldline_ready() {
            Ok(p) => p,
            Err(err) => {
                self.set_err(err);
                return;
            }
        };
        let mut wl = match Worldline::load(&path) {
            Ok(wl) => wl,
            Err(err) => {
                self.set_err(format!("Could not load Worldline: {err}"));
                return;
            }
        };
        let state = match wl.materialize_head() {
            Ok(s) => s,
            Err(err) => {
                self.set_err(format!("Could not materialize Worldline: {err}"));
                return;
            }
        };
        let node_id = entry.node_id.clone();
        let mut ops = Vec::new();
        if !state.nodes.contains_key(&node_id) {
            ops.push(WorldlineOp::UpsertNode {
                node: Box::new(Node {
                    id: node_id.clone(),
                    kind: EntityKind::Capability,
                    title: node_id.clone(),
                    domain: "verified".into(),
                    summary: entry.summary.clone(),
                    status: EpistemicStatus::Hypothesized,
                    provenance: AssistanceProvenance::External,
                    evidence_sha256: Vec::new(),
                    proof_operators: Vec::new(),
                }),
            });
        }
        ops.push(WorldlineOp::RecordVerification {
            entry: Box::new(entry),
        });
        match wl.commit(
            format!("Akashi verify {node_id}"),
            ops,
            self.active_identity.as_ref(),
        ) {
            Ok(cid) => match wl.save(&path) {
                Ok(()) => {
                    self.invalidate_files();
                    self.sync_files_if_changed();
                    self.set_ok(format!(
                        "Verified '{node_id}' ({}).",
                        &cid[..12.min(cid.len())]
                    ));
                }
                Err(err) => self.set_err(format!("Could not save Worldline: {err}")),
            },
            Err(err) => self.set_err(format!("Could not commit verification: {err}")),
        }
    }

    pub fn akashi_verify_command_result(&mut self) {
        let Some(result_id) = self.akashi_selected_result_id else {
            self.set_err("Select a Crux command result first.");
            return;
        };
        let Some((_, _, evidence)) = self
            .crux
            .command_results
            .iter()
            .find(|(id, _, _)| *id == result_id)
            .cloned()
        else {
            self.set_err("Selected command result is no longer in the active Crux journal.");
            return;
        };
        let operator = PROOF_OPERATORS[self.akashi_operator_idx.min(PROOF_OPERATORS.len() - 1)];
        let provenance = PROVENANCES[self.akashi_provenance_idx.min(PROVENANCES.len() - 1)].0;
        let blackout = if self.akashi_attach_blackout {
            self.last_blackout_receipt.as_ref()
        } else {
            None
        };
        let summary = if self.akashi_summary.trim().is_empty() {
            format!("Verified from Crux command result #{result_id}")
        } else {
            self.akashi_summary.trim().to_owned()
        };
        match verify_from_evidence(
            self.akashi_node_id.trim(),
            operator,
            provenance,
            &evidence,
            blackout,
            summary,
        ) {
            Ok(entry) => self.commit_verification(entry),
            Err(err) => self.set_err(err),
        }
    }

    pub fn akashi_verify_written(&mut self) {
        let text = self.akashi_written_text.trim();
        if text.is_empty() {
            self.set_err("Write a derivation, explanation, or critique first.");
            return;
        }
        let operator = PROOF_OPERATORS[self.akashi_operator_idx.min(PROOF_OPERATORS.len() - 1)];
        let provenance = PROVENANCES[self.akashi_provenance_idx.min(PROVENANCES.len() - 1)].0;
        let proxy_blackout_verified = if self.akashi_attach_blackout {
            if let Some(receipt) = &self.last_blackout_receipt {
                if let Err(err) = receipt.verify(false) {
                    self.set_err(err);
                    return;
                }
                true
            } else {
                false
            }
        } else {
            false
        };
        let summary = if self.akashi_summary.trim().is_empty() {
            format!("Written {} artifact ({} bytes)", operator.as_str(), text.len())
        } else {
            self.akashi_summary.trim().to_owned()
        };
        let entry = VerificationEntry {
            node_id: self.akashi_node_id.trim().to_owned(),
            operator,
            provenance,
            evidence_sha256: written_artifact_digest(operator, text.as_bytes()),
            proxy_blackout_verified,
            summary,
        };
        if let Err(err) = entry.validate() {
            self.set_err(err);
            return;
        }
        self.commit_verification(entry);
    }

    pub fn akashi_run_perturbation(&mut self) {
        if self.running_task.is_some() {
            self.set_err("Wait for the active background run to finish.");
            return;
        }
        let target_id = self.akashi_node_id.trim().to_owned();
        if let Err(err) = henosis_dag::validate_id(&target_id) {
            self.set_err(err);
            return;
        }
        let cases_json = match std::fs::read_to_string(self.akashi_perturb_cases_path.trim()) {
            Ok(s) => s,
            Err(err) => {
                self.set_err(format!("Could not read cases JSON: {err}"));
                return;
            }
        };
        let cases: Vec<PerturbationCase> = match serde_json::from_str(&cases_json) {
            Ok(c) => c,
            Err(err) => {
                self.set_err(format!("Invalid perturbation cases JSON: {err}"));
                return;
            }
        };
        let dag_path = match self.ensure_worldline_ready() {
            Ok(p) => p,
            Err(err) => {
                self.set_err(err);
                return;
            }
        };
        let project_dir =
            PathBuf::from(resolve_project_path(self.akashi_perturb_project_dir.trim()));
        self.running_task = Some(format!("Running perturbation suite for '{target_id}'…"));
        let tx = self.async_tx.clone();
        let target_clone = target_id.clone();

        thread::spawn(move || {
            let outcome = match run_suite(&project_dir, &target_clone, &cases) {
                Ok(report) => {
                    let mut commit_note = None;
                    if !report.exposed_failures.is_empty() {
                        if let Ok(mut wl) = Worldline::load(&dag_path) {
                            let ops: Vec<WorldlineOp> = report
                                .exposed_failures
                                .iter()
                                .map(|f| WorldlineOp::RecordFailure {
                                    failure: Box::new(f.clone()),
                                })
                                .collect();
                            if let Ok(cid) = wl.commit(
                                format!(
                                    "Record {} failure(s) from perturbation {}",
                                    ops.len(),
                                    target_clone
                                ),
                                ops,
                                None,
                            ) {
                                if wl.save(&dag_path).is_ok() {
                                    commit_note = Some(cid);
                                }
                            }
                        }
                    }
                    Ok((report, commit_note))
                }
                Err(err) => Err(err.to_string()),
            };
            let _ = tx.send(AsyncNotice::PerturbFinished {
                target_id,
                result: outcome,
            });
        });
    }

    pub fn akashi_verify_from_last_perturb(&mut self) {
        let Some(report) = self.akashi_last_perturb.clone() else {
            self.set_err("Run a perturbation suite first.");
            return;
        };
        let provenance = PROVENANCES[self.akashi_provenance_idx.min(PROVENANCES.len() - 1)].0;
        let blackout = if self.akashi_attach_blackout {
            self.last_blackout_receipt.as_ref()
        } else {
            None
        };
        let summary = if self.akashi_summary.trim().is_empty() {
            format!(
                "Predicted failure boundaries ({}/{})",
                report.accurate_predictions,
                report.outcomes.len()
            )
        } else {
            self.akashi_summary.trim().to_owned()
        };
        match verify_from_perturbation(
            self.akashi_node_id.trim(),
            provenance,
            &report,
            blackout,
            summary,
        ) {
            Ok(entry) => self.commit_verification(entry),
            Err(err) => self.set_err(err),
        }
    }

    pub fn akashi_export_bundle(&mut self) {
        let node_id = self.akashi_node_id.trim();
        let Some(node) = self.worldline.state.nodes.get(node_id).cloned() else {
            self.set_err("Select an existing verified capability node in the Worldline.");
            return;
        };
        let verifications: Vec<VerificationEntry> = self
            .worldline
            .state
            .verifications
            .iter()
            .filter(|v| v.node_id == node_id)
            .cloned()
            .collect();
        let failures: Vec<FailureRecord> = self
            .worldline
            .state
            .failures
            .values()
            .filter(|f| f.target_id == node_id)
            .cloned()
            .collect();
        let contract = self
            .worldline
            .state
            .contracts
            .values()
            .find(|c| c.output == node_id)
            .cloned();
        let disclosed = self.worldline.state.unassisted_capabilities();
        let signer = if self.akashi_sign_bundle {
            self.active_identity.as_ref()
        } else {
            None
        };
        if self.akashi_sign_bundle && signer.is_none() {
            self.set_err("Unlock your Vault or load a session key to sign the bundle.");
            return;
        }
        let input = BundleInput {
            capability: node,
            contract,
            verifications,
            failures,
            perturbation_report: self.akashi_last_perturb.clone(),
            blackout_receipt: if self.akashi_attach_blackout {
                self.last_blackout_receipt.clone()
            } else {
                None
            },
            disclosed_capabilities: disclosed,
            scope_limits: self.akashi_bundle_scope.trim().to_owned(),
        };
        let out_path = PathBuf::from(self.akashi_bundle_path.trim());
        match build_bundle(input, signer) {
            Ok(bundle) => match save_bundle(&out_path, &bundle) {
                Ok(()) => self.set_ok(format!(
                    "Exported bundle {} to {}.",
                    &bundle.bundle_id[..12.min(bundle.bundle_id.len())],
                    out_path.display()
                )),
                Err(err) => self.set_err(format!("Could not save bundle: {err}")),
            },
            Err(err) => self.set_err(err),
        }
    }

    pub fn akashi_inspect_bundle(&mut self) {
        let path = PathBuf::from(self.akashi_bundle_path.trim());
        match load_bundle(&path, false) {
            Ok(bundle) => {
                let signed = bundle
                    .author_fingerprint
                    .as_deref()
                    .map(|fp| format!("signed by {fp}"))
                    .unwrap_or_else(|| "unsigned".into());
                self.akashi_last_inspected_bundle = Some(format!(
                    "Capability '{}' ({}) — {} verification(s), {} disclosed peer cap(s)",
                    bundle.capability.id,
                    signed,
                    bundle.verifications.len(),
                    bundle.disclosed_capabilities.len()
                ));
                self.set_ok("Bundle integrity verified.");
            }
            Err(err) => self.set_err(format!("Bundle verification failed: {err}")),
        }
    }

    pub fn akashi_import_peer_bundle(&mut self) {
        let path = PathBuf::from(self.akashi_bundle_path.trim());
        let bundle = match load_bundle(&path, true) {
            Ok(b) => b,
            Err(err) => {
                self.set_err(format!("Peer import requires a valid signed bundle: {err}"));
                return;
            }
        };
        let ops = match bundle.to_peer_import_ops() {
            Ok(ops) => ops,
            Err(err) => {
                self.set_err(err);
                return;
            }
        };
        let _ = match self.ensure_worldline_ready() {
            Ok(p) => p,
            Err(err) => {
                self.set_err(err);
                return;
            }
        };
        let cap_id = bundle.capability.id.clone();
        self.mutate_worldline(|wl, signer| {
            let cid = wl
                .commit(format!("Import peer capability {cap_id}"), ops, signer)
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "Imported peer capability '{cap_id}' as External ({}).",
                &cid[..12.min(cid.len())]
            ))
        });
    }

    // --- Vault & Proxy actions ---

    pub fn create_vault(&mut self) {
        let path = PathBuf::from(self.vault_path.trim());
        if path.as_os_str().is_empty() {
            self.set_err("Enter a vault file path.");
            return;
        }
        let pw_bytes = Zeroizing::new(self.vault_password.as_bytes().to_vec());
        let passphrase = Zeroizing::new(self.vault_passphrase.clone());
        match UnlockedVault::create_new(&path, &pw_bytes, &passphrase) {
            Ok((mnemonic, _)) => match UnlockedVault::open(&path, &pw_bytes) {
                Ok(vault) => {
                    self.active_identity = vault.identity(&passphrase).ok();
                    self.vault = Some(vault);
                    self.pending_backup_mnemonic = Some(mnemonic);
                    self.sync_vault_to_proxy();
                    self.vault_passphrase.zeroize();
                    self.set_ok(format!(
                        "Created and unlocked vault at {}. Back up your 12-word phrase.",
                        path.display()
                    ));
                }
                Err(err) => self.set_err(format!("Vault created, but open failed: {err}")),
            },
            Err(err) => self.set_err(format!("Could not create vault: {err}")),
        }
    }

    pub fn open_vault(&mut self) {
        let path = PathBuf::from(self.vault_path.trim());
        let pw_bytes = Zeroizing::new(self.vault_password.as_bytes().to_vec());
        let passphrase = Zeroizing::new(self.vault_passphrase.clone());
        match UnlockedVault::open(&path, &pw_bytes) {
            Ok(vault) => {
                let fp = vault.summary().fingerprint;
                self.active_identity = vault.identity(&passphrase).ok();
                self.vault = Some(vault);
                self.sync_vault_to_proxy();
                self.vault_passphrase.zeroize();
                self.set_ok(format!("Unlocked vault ({fp})."));
            }
            Err(err) => self.set_err(format!("Could not unlock vault: {err}")),
        }
    }

    pub fn lock_vault(&mut self) {
        self.vault = None;
        self.pending_backup_mnemonic = None;
        self.vault_password.zeroize();
        self.vault_passphrase.zeroize();
        self.cred_secret.zeroize();
        self.set_ok("Vault locked and cleared from memory.");
    }

    pub fn load_session_mnemonic(&mut self) {
        let phrase = Zeroizing::new(self.session_mnemonic_input.clone());
        let passphrase = Zeroizing::new(self.vault_passphrase.clone());
        self.session_mnemonic_input.zeroize();
        self.vault_passphrase.zeroize();
        match Identity::recover(&phrase, &passphrase) {
            Ok(id) => {
                let fp = id.fingerprint();
                self.active_identity = Some(id);
                self.set_ok(format!("Loaded signing identity ({fp})."));
            }
            Err(err) => self.set_err(format!("Invalid 12-word recovery phrase: {err}")),
        }
    }

    pub fn save_vault_credential(&mut self) {
        let pw_bytes = Zeroizing::new(self.vault_password.as_bytes().to_vec());
        if pw_bytes.is_empty() {
            self.set_err("Keep your vault password entered to save encrypted changes.");
            return;
        }
        let path = PathBuf::from(self.vault_path.trim());
        let scheme = AUTH_SCHEMES[self.cred_scheme_idx.min(AUTH_SCHEMES.len() - 1)].0;
        let url = if self.cred_url.trim().is_empty() {
            None
        } else {
            Some(self.cred_url.trim().to_owned())
        };
        let name = self.cred_name.trim().to_owned();
        let secret = Zeroizing::new(self.cred_secret.clone());

        let Some(vault) = &mut self.vault else {
            self.set_err("Unlock or create a vault first.");
            return;
        };
        if let Err(err) = vault.set_credential(&name, &secret, scheme, url) {
            self.set_err(format!("Invalid credential: {err}"));
            return;
        }
        if let Err(err) = vault.save(&path, &pw_bytes) {
            self.set_err(format!("Could not save vault to disk: {err}"));
            return;
        }
        self.cred_name.clear();
        self.cred_url.clear();
        self.cred_secret.zeroize();
        self.sync_vault_to_proxy();
        self.set_ok(format!("Saved credential '{name}' to encrypted vault."));
    }

    pub fn remove_vault_credential(&mut self, name: &str) {
        let pw_bytes = Zeroizing::new(self.vault_password.as_bytes().to_vec());
        if pw_bytes.is_empty() {
            self.set_err("Enter your vault password to persist credential removal.");
            return;
        }
        let path = PathBuf::from(self.vault_path.trim());
        let Some(vault) = &mut self.vault else {
            return;
        };
        if let Err(err) = vault.remove_credential(name) {
            self.set_err(format!("Could not remove credential: {err}"));
            return;
        }
        if let Err(err) = vault.save(&path, &pw_bytes) {
            self.set_err(format!("Could not save vault: {err}"));
            return;
        }
        self.set_ok(format!("Removed credential '{name}'."));
    }

    pub fn ensure_proxy_started(&mut self) -> bool {
        if self.proxy.is_some() {
            return true;
        }
        match ProxyServer::start(0) {
            Ok(server) => {
                server.register_provider("local-stub", UpstreamTarget::OfflineStub);
                self.proxy = Some(server);
                self.sync_vault_to_proxy();
                true
            }
            Err(err) => {
                self.set_err(format!("Could not start loopback AI proxy: {err}"));
                false
            }
        }
    }

    pub fn stop_proxy(&mut self) {
        if let Some(mut server) = self.proxy.take() {
            server.stop();
            self.last_minted_token = None;
            self.set_ok("Stopped loopback AI proxy.");
        }
    }

    pub fn sync_vault_to_proxy(&mut self) {
        let (Some(proxy), Some(vault)) = (&self.proxy, &self.vault) else {
            return;
        };
        proxy.register_protected_literals(vault.protected_literals());
        for summary in vault.list_credentials() {
            if let Some(base_url) = &summary.base_url {
                if base_url.starts_with("http://") {
                    if let Ok((secret, _)) = vault.resolve_credential(&summary.name) {
                        proxy.register_provider(
                            summary.name.clone(),
                            UpstreamTarget::Http {
                                base_url: base_url.clone(),
                                auth_scheme: summary.auth_scheme,
                                secret,
                            },
                        );
                    }
                }
            }
        }
    }

    pub fn current_impedance(&self) -> Option<ImpedanceMode> {
        self.proxy.as_ref().map(ProxyServer::impedance)
    }

    pub fn select_impedance(&mut self, target: ImpedanceMode) {
        if !self.ensure_proxy_started() {
            return;
        }
        let Some(proxy) = &self.proxy else {
            return;
        };
        let current = proxy.impedance();
        let in_blackout = proxy.status().active_blackout_label.is_some();
        if current == target && in_blackout == (target == ImpedanceMode::Blackout) {
            return;
        }

        if target == ImpedanceMode::Blackout {
            if !in_blackout {
                if let Err(err) = proxy.begin_blackout("desktop-blackout") {
                    self.set_err(format!("Could not start blackout window: {err}"));
                    return;
                }
            }
            let addr = proxy.base_url();
            self.set_ok(format!(
                "AI Proxy in Blackout mode ({addr}) — tracking zero-assistance window."
            ));
            return;
        }

        // Switching to Open or Socratic: close any attested blackout window first.
        if proxy.status().active_blackout_label.is_some() {
            match proxy.end_blackout(target, self.active_identity.as_ref()) {
                Ok(receipt) => {
                    let signed = receipt.signature_hex.is_some();
                    self.last_blackout_receipt = Some(receipt);
                    self.set_ok(format!(
                        "AI Proxy set to {} ({} blackout receipt ready for Akashi).",
                        target.as_str(),
                        if signed { "signed" } else { "unsigned" }
                    ));
                }
                Err(err) => self.set_err(format!("Could not exit blackout window: {err}")),
            }
        } else if let Err(err) = proxy.set_impedance(target) {
            self.set_err(err);
        } else {
            let addr = proxy.base_url();
            self.set_ok(format!("AI Proxy set to {} ({addr}).", target.as_str()));
        }
    }

    pub fn mint_proxy_token(&mut self) {
        if !self.ensure_proxy_started() {
            return;
        }
        let max_requests: u64 = match self.session_max_requests.trim().parse() {
            Ok(n) if n > 0 => n,
            _ => {
                self.set_err("Max requests must be a positive integer.");
                return;
            }
        };
        let Some(proxy) = &self.proxy else {
            return;
        };
        let budget = SessionBudget {
            max_requests,
            ..SessionBudget::default()
        };
        match proxy.grant_session(
            self.session_label_input.trim(),
            self.session_provider_input.trim(),
            budget,
        ) {
            Ok((token, info)) => {
                self.last_minted_token = Some(token);
                self.set_ok(format!(
                    "Minted capability token for session #{} ({}).",
                    info.id, info.provider
                ));
            }
            Err(err) => self.set_err(format!("Could not mint token: {err}")),
        }
    }

    pub fn revoke_proxy_session(&mut self, id: u64) {
        let Some(proxy) = &self.proxy else {
            return;
        };
        match proxy.revoke_session(id) {
            Ok(()) => self.set_ok(format!("Revoked proxy session #{id}.")),
            Err(err) => self.set_err(format!("Could not revoke session: {err}")),
        }
    }
}

fn resolve_project_path(raw: &str) -> String {
    let p = Path::new(raw);
    if p.is_absolute() {
        raw.to_owned()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(p).to_string_lossy().into_owned()
    } else {
        raw.to_owned()
    }
}

fn load_crux_snapshot(stamp: &FileStamp) -> CruxSnapshot {
    if !stamp.exists {
        return CruxSnapshot::default();
    }
    let path = Path::new(&stamp.path);
    let events = match henosis_crux::read(path) {
        Ok(events) => events,
        Err(err) => {
            return CruxSnapshot {
                exists: true,
                load_error: Some(err.to_string()),
                ..CruxSnapshot::default()
            };
        }
    };
    let ranked = henosis_crux::rank(&events).unwrap_or_default();
    let unfinished = henosis_crux::unfinished(&events).unwrap_or_default();
    let drift = detect_drift(path).ok();

    let mut rank_positions = BTreeMap::new();
    for (idx, item) in ranked.iter().enumerate() {
        rank_positions.insert(item.id, idx + 1);
    }

    let mut cards_map: BTreeMap<u64, ProposalCard> = BTreeMap::new();
    let mut command_results = Vec::new();

    for (idx, event) in events.iter().enumerate() {
        let event_id = (idx + 1) as u64;
        match event {
            CruxEvent::Proposed {
                goal,
                hypothesis,
                test,
            } => {
                cards_map.insert(
                    event_id,
                    ProposalCard {
                        id: event_id,
                        goal: goal.clone(),
                        hypothesis: hypothesis.clone(),
                        test: test.clone(),
                        closed: false,
                        latest_score: None,
                        rank_position: rank_positions.get(&event_id).copied(),
                        history: Vec::new(),
                    },
                );
            }
            CruxEvent::Observed { proposal, .. }
            | CruxEvent::ExperimentStarted { proposal, .. }
            | CruxEvent::ExperimentFailed { proposal, .. }
            | CruxEvent::AttemptReviewed { proposal, .. } => {
                if let Some(card) = cards_map.get_mut(proposal) {
                    card.history.push((event_id, event.clone()));
                }
            }
            CruxEvent::Assessed {
                proposal,
                information,
                failure,
                cost,
            } => {
                if let Some(card) = cards_map.get_mut(proposal) {
                    card.latest_score = Some((*information, *failure, *cost));
                    card.history.push((event_id, event.clone()));
                }
            }
            CruxEvent::StatusChanged {
                proposal, closed, ..
            } => {
                if let Some(card) = cards_map.get_mut(proposal) {
                    card.closed = *closed;
                    card.history.push((event_id, event.clone()));
                }
            }
            CruxEvent::CommandResult {
                proposal, evidence, ..
            } => {
                if let Some(card) = cards_map.get_mut(proposal) {
                    card.history.push((event_id, event.clone()));
                }
                command_results.push((event_id, *proposal, (**evidence).clone()));
            }
        }
    }

    CruxSnapshot {
        exists: true,
        proposals: cards_map.into_values().collect(),
        unfinished,
        command_results,
        drift,
        load_error: None,
    }
}

fn load_worldline_snapshot(stamp: &FileStamp) -> WorldlineSnapshot {
    if !stamp.exists {
        return WorldlineSnapshot::default();
    }
    let path = Path::new(&stamp.path);
    let wl = match Worldline::load(path) {
        Ok(wl) => wl,
        Err(err) => {
            return WorldlineSnapshot {
                exists: true,
                load_error: Some(err.to_string()),
                ..WorldlineSnapshot::default()
            };
        }
    };
    let _ = wl.verify_all(false);
    let state = wl.materialize_head().unwrap_or_default();
    let hypergraph = Some(state.hypergraph());
    let mut commits: Vec<Commit> = wl
        .log(None)
        .map(|list| list.into_iter().cloned().collect())
        .unwrap_or_default();
    commits.reverse();

    WorldlineSnapshot {
        exists: true,
        worldline: Some(wl),
        state,
        hypergraph,
        commits,
        load_error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crux_proposal_and_scoring_workflow() {
        let dir = tempfile::tempdir().unwrap();
        let mut ws = WorkspaceData {
            crux_path: dir.path().join("crux.jsonl").to_string_lossy().into_owned(),
            worldline_path: dir
                .path()
                .join("worldline.json")
                .to_string_lossy()
                .into_owned(),
            ..WorkspaceData::default()
        };
        ws.sync_files_if_changed();
        assert!(!ws.crux.exists);

        ws.crux_goal = "Reduce tail latency".into();
        ws.crux_hypothesis = "Lock contention dominates p99".into();
        ws.crux_test = "Benchmark shard lock vs single mutex".into();
        ws.create_proposal();
        assert!(!ws.status_is_error, "{}", ws.status_line);
        assert_eq!(ws.crux.proposals.len(), 1);

        ws.crux_info_score = 5;
        ws.crux_fail_score = 4;
        ws.crux_cost_score = 2;
        ws.record_assessment(1);
        assert_eq!(ws.crux.proposals[0].latest_score, Some((5, 4, 2)));
        assert_eq!(ws.crux.proposals[0].rank_position, Some(1));
    }

    #[test]
    fn worldline_and_akashi_written_verification_workflow() {
        let dir = tempfile::tempdir().unwrap();
        let mut ws = WorkspaceData {
            crux_path: dir.path().join("crux.jsonl").to_string_lossy().into_owned(),
            worldline_path: dir
                .path()
                .join("worldline.json")
                .to_string_lossy()
                .into_owned(),
            ..WorkspaceData::default()
        };
        ws.init_worldline();
        assert!(ws.worldline.exists);

        ws.akashi_node_id = "cap-mutex-proof".into();
        ws.akashi_operator_idx = 0; // Explain
        ws.akashi_provenance_idx = 0; // UnassistedHuman
        ws.akashi_written_text = "Detailed invariant derivation of lock-free handoff.".into();
        ws.akashi_verify_written();
        assert!(!ws.status_is_error, "{}", ws.status_line);
        assert!(ws
            .worldline
            .state
            .unassisted_capabilities()
            .contains("cap-mutex-proof"));
    }

    #[test]
    fn proxy_impedance_switch_emits_blackout_receipt() {
        let mut ws = WorkspaceData::default();
        ws.select_impedance(ImpedanceMode::Blackout);
        assert_eq!(ws.current_impedance(), Some(ImpedanceMode::Blackout));

        ws.select_impedance(ImpedanceMode::Socratic);
        assert_eq!(ws.current_impedance(), Some(ImpedanceMode::Socratic));
        assert!(ws.last_blackout_receipt.is_some());
        ws.stop_proxy();
    }
}
