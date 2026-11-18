#![deny(unsafe_code)]
//! Local loopback HTTP/1.1 AI gateway with ephemeral capability tokens,
//! three-state AI impedance control, outbound prompt DLP, per-session budgets,
//! hash-chained exposure quarantine telemetry, and signed blackout receipts.
//!
//! Honest security boundaries:
//! - Listens strictly on `127.0.0.1` so remote hosts cannot connect directly.
//! - Child processes launched via [`configure_launcher`] receive only an
//!   ephemeral `henosis-cap-*` bearer token, never a stored provider secret.
//!   Tokens are stored inside the proxy as SHA-256 digests and verified in
//!   constant time.
//! - TCP loopback tokens are **not** kernel-PID attested: another local process
//!   that reads a child's environment can reuse its session token until revoked
//!   or budget-exhausted.
//! - Blackout mode rejects all requests reaching this proxy and produces a
//!   hash-chained [`BlackoutReceipt`]; without an OS network namespace, it does
//!   not prevent a process from connecting directly to the internet.
//! - Direct upstream forwarding uses standard-library HTTP/1.1 over `http://`
//!   (suitable for local inference servers such as Ollama, vLLM, or llama.cpp,
//!   and local test gateways). `https://` URLs are rejected cleanly with `501`
//!   rather than silently downgrading to plaintext.

pub mod dlp;
pub mod impedance;

use dlp::{DlpCategory, DlpScanner};
use henosis_jail::LauncherSpec;
use henosis_vault::keyring::AuthScheme;
use henosis_vault::{
    hex, public_key_fingerprint, verify_domain_hex, Identity, DOMAIN_BLACKOUT_RECEIPT,
};
use impedance::{extract_exposure_summary, rewrite_socratic, ImpedanceMode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const TOKEN_PREFIX: &str = "henosis-cap-";
const MAX_HEADER_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_RESPONSE_BODY: usize = 2 * 1024 * 1024;
const MAX_EXPOSURE_LOG: usize = 4_096;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const GENESIS_CHAIN_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Upstream routing mode for a registered provider.
pub enum UpstreamTarget {
    /// Forward to an `http://host:port[/prefix]` server, replacing the phantom
    /// token with the provider's stored credential.
    Http {
        base_url: String,
        auth_scheme: AuthScheme,
        secret: Zeroizing<String>,
    },
    /// Synthetic local acknowledgment responder for offline policy testing and
    /// telemetry capture without contacting any upstream model server.
    OfflineStub,
}

impl fmt::Debug for UpstreamTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http {
                base_url,
                auth_scheme,
                ..
            } => f
                .debug_struct("Http")
                .field("base_url", base_url)
                .field("auth_scheme", auth_scheme)
                .finish_non_exhaustive(),
            Self::OfflineStub => f.write_str("OfflineStub"),
        }
    }
}

/// Per-session resource budget for an ephemeral capability token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBudget {
    pub max_requests: u64,
    pub max_prompt_bytes: u64,
}

impl Default for SessionBudget {
    fn default() -> Self {
        Self {
            max_requests: 256,
            max_prompt_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Public inspection view of an issued capability session (never includes the token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: u64,
    pub label: String,
    pub provider: String,
    pub budget: SessionBudget,
    pub used_requests: u64,
    pub used_prompt_bytes: u64,
    pub revoked: bool,
}

struct SessionRecord {
    token_sha256: [u8; 32],
    info: SessionInfo,
}

/// Proxy decision recorded for an intercepted request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProxyDecision {
    Forwarded,
    ForwardedSocratic,
    BlockedBlackout,
    BlockedAuth,
    BlockedRevoked,
    BlockedBudget,
    BlockedDlp { category: DlpCategory },
    BlockedSocraticFormat,
    UpstreamError { detail: String },
}

/// One hash-chained telemetry entry. Every model interaction recorded here is
/// strictly tagged as `unverified_exposure`, never demonstrated capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureRecord {
    pub seq: u64,
    pub unix_secs: u64,
    pub session_id: Option<u64>,
    pub session_label: Option<String>,
    pub provider: Option<String>,
    pub endpoint: String,
    pub model: Option<String>,
    pub topic_hints: Vec<String>,
    pub impedance: ImpedanceMode,
    pub decision: ProxyDecision,
    pub prompt_bytes: usize,
    pub prompt_sha256: String,
    pub epistemic_status: String,
    pub prev_chain_sha256: String,
    pub entry_sha256: String,
}

/// Active blackout window tracking zero-forwarding enforcement on this proxy.
#[derive(Debug, Clone)]
struct ActiveBlackout {
    window_id: u64,
    label: String,
    nonce_hex: String,
    start_seq: u64,
    started_unix_secs: u64,
    start_chain_sha256: String,
    blocked_attempts: u64,
    forwarded_requests: u64,
}

/// Verifiable record of a completed proxy blackout window.
/// Proves proxy-level enforcement for the signing key holder, not OS network isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlackoutReceipt {
    pub window_id: u64,
    pub label: String,
    pub nonce_hex: String,
    pub start_seq: u64,
    pub end_seq: u64,
    pub started_unix_secs: u64,
    pub ended_unix_secs: u64,
    pub blocked_attempts: u64,
    pub forwarded_requests: u64,
    pub start_chain_sha256: String,
    pub end_chain_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
}

#[derive(Serialize)]
struct CanonicalBlackout<'a> {
    window_id: u64,
    label: &'a str,
    nonce_hex: &'a str,
    start_seq: u64,
    end_seq: u64,
    started_unix_secs: u64,
    ended_unix_secs: u64,
    blocked_attempts: u64,
    forwarded_requests: u64,
    start_chain_sha256: &'a str,
    end_chain_sha256: &'a str,
    signer_pubkey_hex: &'a str,
}

impl BlackoutReceipt {
    /// Returns `true` when zero requests were forwarded through the proxy during
    /// the recorded blackout interval.
    pub fn is_clean(&self) -> bool {
        self.forwarded_requests == 0 && self.end_seq >= self.start_seq
    }

    /// Verify internal invariants and, if signed, the Ed25519 signature.
    pub fn verify(&self, require_signature: bool) -> Result<(), String> {
        if !self.is_clean() {
            return Err("blackout receipt recorded forwarded requests or invalid sequence".into());
        }
        if hex::decode_array::<16>(&self.nonce_hex).is_err()
            || hex::decode_array::<32>(&self.start_chain_sha256).is_err()
            || hex::decode_array::<32>(&self.end_chain_sha256).is_err()
        {
            return Err("blackout receipt contains malformed hex digests".into());
        }
        match (&self.signer_pubkey_hex, &self.signature_hex) {
            (Some(pk_hex), Some(sig_hex)) => {
                let pk = hex::decode_array::<32>(pk_hex)
                    .map_err(|_| "invalid receipt signer public key".to_owned())?;
                if let Some(fp) = &self.signer_fingerprint {
                    if public_key_fingerprint(&pk) != *fp {
                        return Err("receipt fingerprint does not match signer public key".into());
                    }
                }
                let payload = serde_json::to_vec(&CanonicalBlackout {
                    window_id: self.window_id,
                    label: &self.label,
                    nonce_hex: &self.nonce_hex,
                    start_seq: self.start_seq,
                    end_seq: self.end_seq,
                    started_unix_secs: self.started_unix_secs,
                    ended_unix_secs: self.ended_unix_secs,
                    blocked_attempts: self.blocked_attempts,
                    forwarded_requests: self.forwarded_requests,
                    start_chain_sha256: &self.start_chain_sha256,
                    end_chain_sha256: &self.end_chain_sha256,
                    signer_pubkey_hex: pk_hex,
                })
                .map_err(|err| err.to_string())?;
                verify_domain_hex(pk_hex, DOMAIN_BLACKOUT_RECEIPT, &payload, sig_hex)
                    .map_err(|err| err.to_string())
            }
            (None, None) if !require_signature => Ok(()),
            _ => Err("blackout receipt is missing a required Ed25519 signature".into()),
        }
    }
}

/// Snapshot of current proxy status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub listen_addr: String,
    pub impedance: ImpedanceMode,
    pub active_blackout_label: Option<String>,
    pub provider_names: Vec<String>,
    pub active_sessions: usize,
    pub total_events: u64,
    pub chain_head_sha256: String,
}

struct ProxyState {
    impedance: ImpedanceMode,
    dlp: DlpScanner,
    providers: BTreeMap<String, Arc<UpstreamTarget>>,
    next_session_id: u64,
    sessions: BTreeMap<u64, SessionRecord>,
    next_seq: u64,
    chain_head: String,
    exposures: Vec<ExposureRecord>,
    next_blackout_id: u64,
    active_blackout: Option<ActiveBlackout>,
}

impl Default for ProxyState {
    fn default() -> Self {
        Self {
            impedance: ImpedanceMode::Open,
            dlp: DlpScanner::new(),
            providers: BTreeMap::new(),
            next_session_id: 0,
            sessions: BTreeMap::new(),
            next_seq: 0,
            chain_head: GENESIS_CHAIN_HASH.to_owned(),
            exposures: Vec::new(),
            next_blackout_id: 0,
            active_blackout: None,
        }
    }
}

struct LogInput {
    session_id: Option<u64>,
    session_label: Option<String>,
    provider: Option<String>,
    endpoint: String,
    model: Option<String>,
    topic_hints: Vec<String>,
    impedance: ImpedanceMode,
    decision: ProxyDecision,
    prompt_bytes: usize,
    prompt_sha256: String,
}

impl ProxyState {
    fn record_event(&mut self, input: LogInput) {
        self.next_seq = self.next_seq.saturating_add(1);
        let unix_secs = now_unix_secs();
        let prev_chain_sha256 = self.chain_head.clone();
        let decision_json = serde_json::to_string(&input.decision).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(b"henosis.proxy.exposure.v1\0");
        hasher.update(prev_chain_sha256.as_bytes());
        hasher.update(self.next_seq.to_be_bytes());
        hasher.update(unix_secs.to_be_bytes());
        hasher.update(input.endpoint.as_bytes());
        hasher.update(b"\0");
        hasher.update(input.impedance.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(decision_json.as_bytes());
        hasher.update(b"\0");
        hasher.update(input.prompt_sha256.as_bytes());
        let entry_sha256 = hex::encode(&hasher.finalize());
        self.chain_head = entry_sha256.clone();

        if let Some(window) = &mut self.active_blackout {
            match input.decision {
                ProxyDecision::Forwarded | ProxyDecision::ForwardedSocratic => {
                    window.forwarded_requests = window.forwarded_requests.saturating_add(1);
                }
                ProxyDecision::BlockedBlackout => {
                    window.blocked_attempts = window.blocked_attempts.saturating_add(1);
                }
                _ => {}
            }
        }

        if self.exposures.len() >= MAX_EXPOSURE_LOG {
            self.exposures.remove(0);
        }
        self.exposures.push(ExposureRecord {
            seq: self.next_seq,
            unix_secs,
            session_id: input.session_id,
            session_label: input.session_label,
            provider: input.provider,
            endpoint: input.endpoint,
            model: input.model,
            topic_hints: input.topic_hints,
            impedance: input.impedance,
            decision: input.decision,
            prompt_bytes: input.prompt_bytes,
            prompt_sha256: input.prompt_sha256,
            epistemic_status: "unverified_exposure".into(),
            prev_chain_sha256,
            entry_sha256,
        });
    }

    fn match_session_mut(&mut self, presented_token: &str) -> Option<&mut SessionRecord> {
        if !presented_token.starts_with(TOKEN_PREFIX) {
            return None;
        }
        let presented_digest: [u8; 32] = Sha256::digest(presented_token.as_bytes()).into();
        let mut matched_id = None;
        // Scan all sessions in constant time per digest so lookup does not short-circuit.
        for (&id, record) in &self.sessions {
            if record.token_sha256.ct_eq(&presented_digest).unwrap_u8() == 1 {
                matched_id = Some(id);
            }
        }
        matched_id.and_then(|id| self.sessions.get_mut(&id))
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify hash-chain continuity across a slice of consecutive [`ExposureRecord`]s.
pub fn verify_exposure_chain(records: &[ExposureRecord]) -> Result<(), String> {
    for pair in records.windows(2) {
        let (prev, curr) = (&pair[0], &pair[1]);
        if curr.seq != prev.seq + 1 || curr.prev_chain_sha256 != prev.entry_sha256 {
            return Err(format!(
                "broken exposure hash chain between seq {} and {}",
                prev.seq, curr.seq
            ));
        }
    }
    Ok(())
}

/// Configure a [`LauncherSpec`] so the spawned child talks to `proxy_base_url`
/// using an ephemeral `henosis-cap-*` token rather than real provider keys.
pub fn configure_launcher(spec: &mut LauncherSpec, proxy_base_url: &str, capability_token: &str) {
    let v1 = format!("{}/v1", proxy_base_url.trim_end_matches('/'));
    spec.env("HENOSIS_PROXY_URL", proxy_base_url)
        .env("OPENAI_BASE_URL", &v1)
        .env("OPENAI_API_KEY", capability_token)
        .env("ANTHROPIC_BASE_URL", proxy_base_url)
        .env("ANTHROPIC_API_KEY", capability_token);
}

/// A running loopback AI proxy gateway. Stops cleanly when [`Self::stop`] is
/// called or when dropped.
pub struct ProxyServer {
    addr: SocketAddr,
    state: Arc<Mutex<ProxyState>>,
    shutdown: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl ProxyServer {
    /// Start listening on `127.0.0.1:port` (pass `0` for an OS-assigned port).
    pub fn start(port: u16) -> io::Result<Self> {
        Self::start_with_scanner(port, DlpScanner::new())
    }

    pub fn start_with_scanner(port: u16, dlp: DlpScanner) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(ProxyState {
            dlp,
            ..ProxyState::default()
        }));
        let shutdown = Arc::new(AtomicBool::new(false));
        let loop_state = Arc::clone(&state);
        let loop_shutdown = Arc::clone(&shutdown);
        let accept_thread = thread::Builder::new()
            .name("henosis-proxy-accept".into())
            .spawn(move || accept_loop(listener, loop_state, loop_shutdown))?;
        Ok(Self {
            addr,
            state,
            shutdown,
            accept_thread: Some(accept_thread),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Register an upstream provider and automatically add its secret (if any)
    /// to the outbound DLP scanner.
    pub fn register_provider(&self, name: impl Into<String>, target: UpstreamTarget) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let UpstreamTarget::Http { secret, .. } = &target {
            guard.dlp.register_secret(Zeroizing::new(secret.as_str().to_owned()));
        }
        guard.providers.insert(name.into(), Arc::new(target));
    }

    /// Register extra protected secret literals (e.g. from an unlocked vault)
    /// with the outbound DLP scanner.
    pub fn register_protected_literals(&self, secrets: Vec<Zeroizing<String>>) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.dlp.register_secrets(secrets);
    }

    /// Set the current AI Impedance mode. Refuses to leave an active blackout
    /// window directly; call [`Self::end_blackout`] to close a tracked window.
    pub fn set_impedance(&self, mode: ImpedanceMode) -> Result<(), String> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.active_blackout.is_some() && mode != ImpedanceMode::Blackout {
            return Err(
                "an attested blackout window is active; call end_blackout to exit blackout".into(),
            );
        }
        guard.impedance = mode;
        Ok(())
    }

    pub fn impedance(&self) -> ImpedanceMode {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).impedance
    }

    /// Enter an attested blackout window, forcing `ImpedanceMode::Blackout`
    /// until [`Self::end_blackout`] is called.
    pub fn begin_blackout(&self, label: impl Into<String>) -> io::Result<u64> {
        let label = label.into();
        if label.trim().is_empty() || label.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "blackout label must be 1..=128 non-whitespace bytes",
            ));
        }
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|err| io::Error::other(err.to_string()))?;
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.active_blackout.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a blackout window is already active",
            ));
        }
        guard.impedance = ImpedanceMode::Blackout;
        guard.next_blackout_id = guard.next_blackout_id.saturating_add(1);
        let window_id = guard.next_blackout_id;
        let start_seq = guard.next_seq;
        let start_chain_sha256 = guard.chain_head.clone();
        guard.active_blackout = Some(ActiveBlackout {
            window_id,
            label,
            nonce_hex: hex::encode(&nonce),
            start_seq,
            started_unix_secs: now_unix_secs(),
            start_chain_sha256,
            blocked_attempts: 0,
            forwarded_requests: 0,
        });
        Ok(window_id)
    }

    /// Close the active blackout window, switch to `resume_mode`, and emit a
    /// verifiable (optionally Ed25519-signed) [`BlackoutReceipt`].
    pub fn end_blackout(
        &self,
        resume_mode: ImpedanceMode,
        signer: Option<&Identity>,
    ) -> io::Result<BlackoutReceipt> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let window = guard.active_blackout.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no blackout window is active")
        })?;
        guard.impedance = resume_mode;
        let ended_unix_secs = now_unix_secs();
        let end_seq = guard.next_seq;
        let end_chain_sha256 = guard.chain_head.clone();
        drop(guard);

        let (signer_pubkey_hex, signer_fingerprint, signature_hex) = if let Some(id) = signer {
            let pk_hex = id.public_key_hex();
            let fp = id.fingerprint();
            let payload = serde_json::to_vec(&CanonicalBlackout {
                window_id: window.window_id,
                label: &window.label,
                nonce_hex: &window.nonce_hex,
                start_seq: window.start_seq,
                end_seq,
                started_unix_secs: window.started_unix_secs,
                ended_unix_secs,
                blocked_attempts: window.blocked_attempts,
                forwarded_requests: window.forwarded_requests,
                start_chain_sha256: &window.start_chain_sha256,
                end_chain_sha256: &end_chain_sha256,
                signer_pubkey_hex: &pk_hex,
            })
            .map_err(io::Error::other)?;
            let sig = id
                .sign_domain_hex(DOMAIN_BLACKOUT_RECEIPT, &payload)
                .map_err(io::Error::other)?;
            (Some(pk_hex), Some(fp), Some(sig))
        } else {
            (None, None, None)
        };

        Ok(BlackoutReceipt {
            window_id: window.window_id,
            label: window.label,
            nonce_hex: window.nonce_hex,
            start_seq: window.start_seq,
            end_seq,
            started_unix_secs: window.started_unix_secs,
            ended_unix_secs,
            blocked_attempts: window.blocked_attempts,
            forwarded_requests: window.forwarded_requests,
            start_chain_sha256: window.start_chain_sha256,
            end_chain_sha256,
            signer_pubkey_hex,
            signer_fingerprint,
            signature_hex,
        })
    }

    /// Mint a fresh ephemeral capability token (`henosis-cap-*`) scoped to a
    /// registered provider and budget. The raw token is returned once and only
    /// its SHA-256 digest is kept in proxy memory.
    pub fn grant_session(
        &self,
        label: impl Into<String>,
        provider: impl Into<String>,
        budget: SessionBudget,
    ) -> io::Result<(Zeroizing<String>, SessionInfo)> {
        let label = label.into();
        let provider = provider.into();
        if label.trim().is_empty() || label.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session label must be 1..=128 non-whitespace bytes",
            ));
        }
        if budget.max_requests == 0 || budget.max_prompt_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session budget limits must be positive",
            ));
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(raw.as_mut()).map_err(|err| io::Error::other(err.to_string()))?;
        let token = Zeroizing::new(format!("{TOKEN_PREFIX}{}", hex::encode(raw.as_ref())));
        let token_sha256: [u8; 32] = Sha256::digest(token.as_bytes()).into();

        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !guard.providers.contains_key(&provider) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown upstream provider '{provider}'"),
            ));
        }
        guard.next_session_id = guard.next_session_id.saturating_add(1);
        let id = guard.next_session_id;
        let info = SessionInfo {
            id,
            label,
            provider,
            budget,
            used_requests: 0,
            used_prompt_bytes: 0,
            revoked: false,
        };
        guard.sessions.insert(
            id,
            SessionRecord {
                token_sha256,
                info: info.clone(),
            },
        );
        Ok((token, info))
    }

    pub fn revoke_session(&self, session_id: u64) -> io::Result<()> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let record = guard
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown session ID"))?;
        record.info.revoked = true;
        Ok(())
    }

    pub fn sessions(&self) -> Vec<SessionInfo> {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.sessions.values().map(|r| r.info.clone()).collect()
    }

    pub fn exposures(&self) -> Vec<ExposureRecord> {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.exposures.clone()
    }

    pub fn status(&self) -> ProxyStatus {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        ProxyStatus {
            listen_addr: self.addr.to_string(),
            impedance: guard.impedance,
            active_blackout_label: guard.active_blackout.as_ref().map(|w| w.label.clone()),
            provider_names: guard.providers.keys().cloned().collect(),
            active_sessions: guard.sessions.values().filter(|s| !s.info.revoked).count(),
            total_events: guard.next_seq,
            chain_head_sha256: guard.chain_head.clone(),
        }
    }

    pub fn stop(&mut self) {
        if !self.shutdown.swap(true, Ordering::SeqCst) {
            let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        }
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: TcpListener, state: Arc<Mutex<ProxyState>>, shutdown: Arc<AtomicBool>) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while let Ok((stream, _peer)) = listener.accept() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        workers.retain(|h| !h.is_finished());
        let conn_state = Arc::clone(&state);
        if let Ok(handle) = thread::Builder::new()
            .name("henosis-proxy-conn".into())
            .spawn(move || {
                let _ = handle_connection(stream, conn_state);
            })
        {
            workers.push(handle);
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}

struct ParsedRequest {
    method: String,
    path: String,
    auth_token: Option<String>,
    content_type: Option<String>,
    anthropic_version: Option<String>,
    body: Vec<u8>,
}

fn read_bounded_line<R: BufRead>(reader: &mut R, max_len: usize) -> io::Result<String> {
    let mut buf = Vec::new();
    let n = reader
        .take((max_len + 1) as u64)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty request"));
    }
    if buf.len() > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP header line exceeds limit",
        ));
    }
    let text = String::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 HTTP header"))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn parse_request(stream: &TcpStream, max_body: usize) -> Result<ParsedRequest, (u16, String)> {
    let mut reader = BufReader::new(stream);
    let request_line = read_bounded_line(&mut reader, MAX_HEADER_LINE)
        .map_err(|err| (400, format!("malformed request line: {err}")))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| (400, "missing HTTP method".to_owned()))?
        .to_owned();
    let path = parts
        .next()
        .ok_or_else(|| (400, "missing request path".to_owned()))?
        .to_owned();
    let version = parts
        .next()
        .ok_or_else(|| (400, "missing HTTP version".to_owned()))?;
    if !path.starts_with('/') || (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return Err((400, "unsupported HTTP version or target".into()));
    }

    let mut content_len: usize = 0;
    let mut auth_token: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut anthropic_version: Option<String> = None;

    for _ in 0..MAX_HEADERS {
        let line = read_bounded_line(&mut reader, MAX_HEADER_LINE)
            .map_err(|err| (400, format!("invalid header: {err}")))?;
        if line.is_empty() {
            break;
        }
        let Some((raw_name, raw_val)) = line.split_once(':') else {
            return Err((400, "malformed header line".into()));
        };
        let name = raw_name.trim().to_ascii_lowercase();
        let val = raw_val.trim();
        match name.as_str() {
            "content-length" => {
                content_len = val
                    .parse::<usize>()
                    .map_err(|_| (400, "invalid Content-Length".to_owned()))?;
                if content_len > max_body {
                    return Err((413, format!("request body exceeds {max_body} bytes")));
                }
            }
            "transfer-encoding" => {
                return Err((411, "chunked request bodies are not supported; supply Content-Length".into()));
            }
            "authorization" => {
                if let Some(rest) = val.strip_prefix("Bearer ").or_else(|| val.strip_prefix("bearer ")) {
                    auth_token = Some(rest.trim().to_owned());
                }
            }
            "x-api-key" if auth_token.is_none() => {
                auth_token = Some(val.to_owned());
            }
            "content-type" => {
                content_type = Some(val.to_owned());
            }
            "anthropic-version" => {
                if !val.bytes().any(|b| b.is_ascii_control()) && val.len() <= 64 {
                    anthropic_version = Some(val.to_owned());
                }
            }
            _ => {}
        }
    }

    let mut body = vec![0u8; content_len];
    reader
        .read_exact(&mut body)
        .map_err(|err| (400, format!("incomplete request body: {err}")))?;

    Ok(ParsedRequest {
        method,
        path,
        auth_token,
        content_type,
        anthropic_version,
        body,
    })
}

fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nX-Henosis-Epistemic: unverified_exposure\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

fn write_error(stream: &mut TcpStream, status: u16, reason: &str, code: &str, msg: &str) -> io::Result<()> {
    let payload = serde_json::json!({
        "error": {
            "code": code,
            "message": msg,
        }
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    write_json_response(stream, status, reason, &bytes)
}

fn handle_connection(mut stream: TcpStream, state: Arc<Mutex<ProxyState>>) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let max_body = state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .dlp
        .max_body_bytes();
    let req = match parse_request(&stream, max_body) {
        Ok(req) => req,
        Err((status, msg)) => {
            return write_error(&mut stream, status, "Bad Request", "invalid_request", &msg);
        }
    };

    if req.method == "GET" && req.path == "/healthz" {
        let mode = state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .impedance
            .as_str();
        let body = serde_json::to_vec(&serde_json::json!({
            "status": "ok",
            "impedance": mode,
        }))
        .unwrap_or_default();
        return write_json_response(&mut stream, 200, "OK", &body);
    }

    if req.method != "POST" {
        return write_error(
            &mut stream,
            405,
            "Method Not Allowed",
            "method_not_allowed",
            "only POST inference requests and GET /healthz are accepted",
        );
    }

    let prompt_sha256 = hex::encode(&Sha256::digest(&req.body));
    let prompt_bytes = req.body.len();
    let (model, topic_hints) = extract_exposure_summary(&req.body);

    // Inspect impedance, authenticate session token, check revocation, DLP, and budget atomically.
    let dispatch = {
        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
        let impedance = guard.impedance;

        // 1. Blackout hard-blocks before everything else.
        if impedance == ImpedanceMode::Blackout {
            guard.record_event(LogInput {
                session_id: None,
                session_label: None,
                provider: None,
                endpoint: req.path.clone(),
                model,
                topic_hints,
                impedance,
                decision: ProxyDecision::BlockedBlackout,
                prompt_bytes,
                prompt_sha256,
            });
            return write_error(
                &mut stream,
                403,
                "Forbidden",
                "henosis_blackout",
                "Henosis proxy is in Blackout mode: generative AI traffic is blocked.",
            );
        }

        // 2. Constant-time phantom capability token check.
        let presented = req.auth_token.as_deref().unwrap_or("");
        let session_snapshot = guard.match_session_mut(presented).map(|s| s.info.clone());
        let Some(session_info) = session_snapshot else {
            guard.record_event(LogInput {
                session_id: None,
                session_label: None,
                provider: None,
                endpoint: req.path.clone(),
                model,
                topic_hints,
                impedance,
                decision: ProxyDecision::BlockedAuth,
                prompt_bytes,
                prompt_sha256,
            });
            return write_error(
                &mut stream,
                401,
                "Unauthorized",
                "invalid_capability_token",
                "missing or invalid Henosis capability token",
            );
        };

        if session_info.revoked {
            guard.record_event(LogInput {
                session_id: Some(session_info.id),
                session_label: Some(session_info.label),
                provider: Some(session_info.provider),
                endpoint: req.path.clone(),
                model,
                topic_hints,
                impedance,
                decision: ProxyDecision::BlockedRevoked,
                prompt_bytes,
                prompt_sha256,
            });
            return write_error(
                &mut stream,
                401,
                "Unauthorized",
                "revoked_capability_token",
                "capability token has been revoked",
            );
        }

        // 3. Outbound Prompt DLP & Secret Exfiltration Firewall.
        if let Err(violation) = guard.dlp.scan(&req.body) {
            guard.record_event(LogInput {
                session_id: Some(session_info.id),
                session_label: Some(session_info.label),
                provider: Some(session_info.provider),
                endpoint: req.path.clone(),
                model,
                topic_hints,
                impedance,
                decision: ProxyDecision::BlockedDlp {
                    category: violation.category,
                },
                prompt_bytes,
                prompt_sha256,
            });
            return write_error(
                &mut stream,
                403,
                "Forbidden",
                violation.category.as_str(),
                &violation.reason,
            );
        }

        // 4. Per-session request & byte circuit breaker.
        let next_reqs = session_info.used_requests.saturating_add(1);
        let next_bytes = session_info
            .used_prompt_bytes
            .saturating_add(prompt_bytes as u64);
        if next_reqs > session_info.budget.max_requests
            || next_bytes > session_info.budget.max_prompt_bytes
        {
            guard.record_event(LogInput {
                session_id: Some(session_info.id),
                session_label: Some(session_info.label),
                provider: Some(session_info.provider),
                endpoint: req.path.clone(),
                model,
                topic_hints,
                impedance,
                decision: ProxyDecision::BlockedBudget,
                prompt_bytes,
                prompt_sha256,
            });
            return write_error(
                &mut stream,
                429,
                "Too Many Requests",
                "session_budget_exceeded",
                "session request or prompt-byte circuit breaker tripped",
            );
        }

        // 5. Apply Socratic Impedance prompt rewriting if active.
        let (outbound_body, planned_decision) = if impedance == ImpedanceMode::Socratic {
            match rewrite_socratic(&req.path, &req.body) {
                Ok(rewritten) => (rewritten, ProxyDecision::ForwardedSocratic),
                Err(reason) => {
                    guard.record_event(LogInput {
                        session_id: Some(session_info.id),
                        session_label: Some(session_info.label),
                        provider: Some(session_info.provider),
                        endpoint: req.path.clone(),
                        model,
                        topic_hints,
                        impedance,
                        decision: ProxyDecision::BlockedSocraticFormat,
                        prompt_bytes,
                        prompt_sha256,
                    });
                    return write_error(
                        &mut stream,
                        422,
                        "Unprocessable Entity",
                        "socratic_rewrite_rejected",
                        &reason,
                    );
                }
            }
        } else {
            (req.body, ProxyDecision::Forwarded)
        };

        // Charge session quota and grab upstream handle before releasing lock.
        if let Some(rec) = guard.sessions.get_mut(&session_info.id) {
            rec.info.used_requests = next_reqs;
            rec.info.used_prompt_bytes = next_bytes;
        }
        let upstream = guard.providers.get(&session_info.provider).cloned();
        (
            upstream,
            session_info,
            impedance,
            outbound_body,
            planned_decision,
            model,
            topic_hints,
            prompt_sha256,
        )
    };

    let (
        Some(upstream),
        session_info,
        impedance,
        outbound_body,
        planned_decision,
        model,
        topic_hints,
        prompt_sha256,
    ) = dispatch
    else {
        return write_error(
            &mut stream,
            502,
            "Bad Gateway",
            "missing_provider",
            "upstream provider is not configured",
        );
    };

    let forward_result = forward_upstream(
        &upstream,
        &req.path,
        req.content_type.as_deref().unwrap_or("application/json"),
        req.anthropic_version.as_deref(),
        &outbound_body,
        impedance,
    );

    match forward_result {
        Ok((status, content_type, resp_body)) => {
            let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
            guard.record_event(LogInput {
                session_id: Some(session_info.id),
                session_label: Some(session_info.label),
                provider: Some(session_info.provider),
                endpoint: req.path,
                model,
                topic_hints,
                impedance,
                decision: planned_decision,
                prompt_bytes,
                prompt_sha256,
            });
            drop(guard);
            write!(
                stream,
                "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Henosis-Epistemic: unverified_exposure\r\nX-Henosis-Impedance: {}\r\n\r\n",
                resp_body.len(),
                impedance.as_str()
            )?;
            stream.write_all(&resp_body)?;
            stream.flush()
        }
        Err((status, detail)) => {
            let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
            guard.record_event(LogInput {
                session_id: Some(session_info.id),
                session_label: Some(session_info.label),
                provider: Some(session_info.provider),
                endpoint: req.path,
                model,
                topic_hints,
                impedance,
                decision: ProxyDecision::UpstreamError {
                    detail: detail.clone(),
                },
                prompt_bytes,
                prompt_sha256,
            });
            drop(guard);
            write_error(&mut stream, status, "Upstream Error", "upstream_error", &detail)
        }
    }
}

fn parse_http_url(base_url: &str) -> Result<(String, u16, String), (u16, String)> {
    if base_url.starts_with("https://") {
        return Err((
            501,
            "direct HTTPS upstream requires a TLS adapter; use a local http:// inference endpoint"
                .into(),
        ));
    }
    let rest = base_url
        .strip_prefix("http://")
        .ok_or_else(|| (502, "upstream URL must start with http://".to_owned()))?;
    let (authority, prefix) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{}", p.trim_end_matches('/'))),
        None => (rest, String::new()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| (502, "invalid upstream port".to_owned()))?;
            (h.to_owned(), port)
        }
        None => (authority.to_owned(), 80),
    };
    if host.is_empty() || host.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err((502, "invalid upstream host".into()));
    }
    let clean_prefix = if prefix == "/" { String::new() } else { prefix };
    Ok((host, port, clean_prefix))
}

fn forward_upstream(
    target: &UpstreamTarget,
    request_path: &str,
    content_type: &str,
    anthropic_version: Option<&str>,
    body: &[u8],
    impedance: ImpedanceMode,
) -> Result<(u16, String, Vec<u8>), (u16, String)> {
    match target {
        UpstreamTarget::OfflineStub => {
            let reply = serde_json::json!({
                "id": "henosis-offline-stub",
                "epistemic_status": "unverified_exposure",
                "impedance": impedance.as_str(),
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": if impedance == ImpedanceMode::Socratic {
                            "[offline-socratic] State your governing assumption and test failure boundary first."
                        } else {
                            "[offline-stub] Request logged to Henosis exposure quarantine."
                        }
                    }
                }]
            });
            let bytes = serde_json::to_vec(&reply).map_err(|err| (500, err.to_string()))?;
            Ok((200, "application/json".into(), bytes))
        }
        UpstreamTarget::Http {
            base_url,
            auth_scheme,
            secret,
        } => {
            let (host, port, prefix) = parse_http_url(base_url)?;
            let mut upstream = TcpStream::connect((host.as_str(), port))
                .map_err(|err| (502, format!("could not connect to upstream: {err}")))?;
            let _ = upstream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = upstream.set_write_timeout(Some(IO_TIMEOUT));

            let full_path = format!("{prefix}{request_path}");
            let safe_ct: String = content_type
                .chars()
                .filter(|c| !c.is_control())
                .take(128)
                .collect();
            let auth_header = match auth_scheme {
                AuthScheme::Bearer => format!("Authorization: Bearer {}\r\n", secret.as_str()),
                AuthScheme::XApiKey => format!("x-api-key: {}\r\n", secret.as_str()),
            };
            let version_header = anthropic_version
                .map(|v| format!("anthropic-version: {v}\r\n"))
                .unwrap_or_default();

            write!(
                upstream,
                "POST {full_path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: {safe_ct}\r\n{auth_header}{version_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .map_err(|err| (502, format!("upstream write failed: {err}")))?;
            upstream
                .write_all(body)
                .and_then(|()| upstream.flush())
                .map_err(|err| (502, format!("upstream body send failed: {err}")))?;

            let mut reader = BufReader::new(upstream);
            let status_line = read_bounded_line(&mut reader, MAX_HEADER_LINE)
                .map_err(|err| (502, format!("upstream status read failed: {err}")))?;
            let status = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or_else(|| (502, "malformed upstream HTTP status".to_owned()))?;

            let mut resp_ct = "application/json".to_owned();
            let mut resp_len: Option<usize> = None;
            for _ in 0..MAX_HEADERS {
                let line = read_bounded_line(&mut reader, MAX_HEADER_LINE)
                    .map_err(|err| (502, format!("upstream header read failed: {err}")))?;
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    let lower = k.trim().to_ascii_lowercase();
                    let val = v.trim();
                    if lower == "content-type" && !val.bytes().any(|b| b.is_ascii_control()) {
                        resp_ct = val.to_owned();
                    } else if lower == "content-length" {
                        let n = val
                            .parse::<usize>()
                            .map_err(|_| (502, "invalid upstream Content-Length".to_owned()))?;
                        if n > MAX_RESPONSE_BODY {
                            return Err((502, "upstream response exceeds 2 MiB limit".into()));
                        }
                        resp_len = Some(n);
                    }
                }
            }

            let mut resp_body = Vec::new();
            if let Some(len) = resp_len {
                resp_body.resize(len, 0);
                reader
                    .read_exact(&mut resp_body)
                    .map_err(|err| (502, format!("upstream truncated body: {err}")))?;
            } else {
                reader
                    .take((MAX_RESPONSE_BODY + 1) as u64)
                    .read_to_end(&mut resp_body)
                    .map_err(|err| (502, format!("upstream stream read failed: {err}")))?;
                if resp_body.len() > MAX_RESPONSE_BODY {
                    return Err((502, "upstream response exceeds 2 MiB limit".into()));
                }
            }
            Ok((status, resp_ct, resp_body))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn post(addr: SocketAddr, path: &str, token: Option<&str>, body: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let auth = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        let (head, payload) = raw.split_once("\r\n\r\n").unwrap();
        let status: u16 = head
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, payload.to_owned())
    }

    fn spawn_mock_upstream(expected_secret: &'static str) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::clone(&received);
        thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut conn, _)) = listener.accept() else {
                    break;
                };
                let req = parse_request(&conn, 65536).unwrap();
                assert_eq!(req.auth_token.as_deref(), Some(expected_secret));
                let body_str = String::from_utf8(req.body).unwrap();
                assert!(!body_str.contains("henosis-cap-"));
                store.lock().unwrap().push(body_str);
                let reply = br#"{"choices":[{"message":{"role":"assistant","content":"ok"}}]}"#;
                write!(
                    conn,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                )
                .unwrap();
                conn.write_all(reply).unwrap();
            }
        });
        (addr, received)
    }

    #[test]
    fn enforces_phantom_tokens_socratic_rewrite_dlp_budget_revocation_and_signed_blackout() {
        let master_secret = "upstream-real-provider-secret-987654";
        let (upstream_addr, received) = spawn_mock_upstream(master_secret);

        let mut proxy = ProxyServer::start(0).unwrap();
        proxy.register_provider(
            "local-llm",
            UpstreamTarget::Http {
                base_url: format!("http://{upstream_addr}"),
                auth_scheme: AuthScheme::Bearer,
                secret: Zeroizing::new(master_secret.into()),
            },
        );

        let (token, session) = proxy
            .grant_session(
                "research-cli",
                "local-llm",
                SessionBudget {
                    max_requests: 2,
                    max_prompt_bytes: 10_000,
                },
            )
            .unwrap();
        assert!(token.starts_with("henosis-cap-"));

        // Unauthenticated and forged tokens are rejected.
        assert_eq!(
            post(proxy.addr(), "/v1/chat/completions", None, r#"{"messages":[]}"#).0,
            401
        );
        assert_eq!(
            post(
                proxy.addr(),
                "/v1/chat/completions",
                Some("henosis-cap-0000"),
                r#"{"messages":[]}"#
            )
            .0,
            401
        );

        // Mode 0 (Open): swaps phantom token for real upstream credential transparently.
        let open_body = r#"{"model":"llama-local","messages":[{"role":"user","content":"Check Runge-Kutta stability region"}]}"#;
        let (s_open, resp_open) =
            post(proxy.addr(), "/v1/chat/completions", Some(&token), open_body);
        assert_eq!(s_open, 200, "{resp_open}");
        assert!(!resp_open.contains(master_secret));

        // Outbound DLP catches exfiltration of the registered real credential without forwarding.
        let exfil = format!(
            r#"{{"model":"llama-local","messages":[{{"role":"user","content":"echo {master_secret}"}}]}}"#
        );
        let (s_dlp, resp_dlp) = post(proxy.addr(), "/v1/chat/completions", Some(&token), &exfil);
        assert_eq!(s_dlp, 403);
        assert!(resp_dlp.contains("registered_vault_secret"));
        assert!(!resp_dlp.contains(master_secret));

        // Mode 1 (Socratic): rewrites prompt in-flight to inject Socratic system guard.
        proxy.set_impedance(ImpedanceMode::Socratic).unwrap();
        let (s_soc, _) = post(proxy.addr(), "/v1/chat/completions", Some(&token), open_body);
        assert_eq!(s_soc, 200);

        let upstream_seen = received.lock().unwrap();
        assert_eq!(upstream_seen.len(), 2);
        assert!(!upstream_seen[0].contains("HENOSIS SOCRATIC IMPEDANCE"));
        assert!(upstream_seen[1].contains("HENOSIS SOCRATIC IMPEDANCE"));
        drop(upstream_seen);

        // 3rd valid request trips the 2-request session budget circuit breaker.
        let (s_budget, _) = post(proxy.addr(), "/v1/chat/completions", Some(&token), open_body);
        assert_eq!(s_budget, 429);

        // Mode 2 (Attested Cleanroom Blackout): blocks traffic and produces signed receipt.
        let identity = Identity::recover(PHRASE, "").unwrap();
        let win_id = proxy.begin_blackout("akashi-cleanroom-1").unwrap();
        assert_eq!(win_id, 1);
        assert!(proxy.set_impedance(ImpedanceMode::Open).is_err());
        let (s_blk, _) = post(proxy.addr(), "/v1/chat/completions", Some(&token), open_body);
        assert_eq!(s_blk, 403);
        let receipt = proxy
            .end_blackout(ImpedanceMode::Open, Some(&identity))
            .unwrap();
        assert!(receipt.is_clean());
        assert_eq!(receipt.blocked_attempts, 1);
        assert_eq!(receipt.forwarded_requests, 0);
        assert!(receipt.verify(true).is_ok());

        // Tampered receipt fails strict Ed25519 verification.
        let mut tampered = receipt.clone();
        tampered.blocked_attempts = 0;
        assert!(tampered.verify(true).is_err());

        // Revocation permanently disables a session token.
        let (token2, s2) = proxy
            .grant_session("temp", "local-llm", SessionBudget::default())
            .unwrap();
        proxy.revoke_session(s2.id).unwrap();
        assert_eq!(
            post(proxy.addr(), "/v1/chat/completions", Some(&token2), open_body).0,
            401
        );
        assert_eq!(session.id, 1);

        // Every logged event forms an unbroken SHA-256 chain tagged as unverified exposure.
        let log = proxy.exposures();
        assert!(log.len() >= 7);
        verify_exposure_chain(&log).unwrap();
        assert!(log.iter().all(|e| e.epistemic_status == "unverified_exposure"));

        proxy.stop();
    }
}
