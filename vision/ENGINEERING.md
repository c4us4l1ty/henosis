# ENGINEERING.md — Building Henosis from First Principles

> **Mission Brief for the Core Engineering Team:**
> Henosis’ ambition is civilization-scale. **Its execution must be bottleneck-scale.**
>
> You are not building an EdTech wrapper, a markdown note-taker, or an Electron chatbot. You are building a **Sovereign Epistemic Hypervisor** in Rust: a local-first, cryptographically self-custodied operating environment that sits between a thinker, their external tools, their execution sandboxes, and their AI models to maximize **$\Delta \mathcal{F}$—the expansion of what a human being can independently execute and discover in reality.**

---

## 1. What Henosis Actually Is (Zero-Jargon Onboarding)

If you know nothing about Henosis, understand these four operational truths before touching the codebase:

1. **We Track Demonstrated Capability, Never "Content Consumed":** Most software tracks pages read, videos watched, or AI chats completed. Henosis treats all of that as *Unverified Exposure* (value = 0). A node in Henosis only flips to a verified **Capability** when the user constructs a working **Realization** (code, mathematical derivation, simulation, reproduced paper figure, empirical model, or critical text) that survives **Akashi**—our deterministic and adversarial verification engine.
2. **We Orchestrate Existing Tools via a Hypervisor Layer:** Users will use external open-source learning engines (`learnharness`, `deeptutor`, `open-academy`, `feynman`), terminal solvers, and web apps (like NotebookLM). We do not rewrite those tools. Henosis spawns and wraps them, injects API credentials transparently through a local proxy, intercepts their epistemic telemetry at the network/PTY layer, and gates their usage with verification checks.
3. **We Map the Capability Hypergraph and the Frontier ($\partial \mathcal{F}$):** Capabilities do not combine pairwise; they combine in multi-way conditional bundles called **Realization Contracts** $e = (P, A, R, O, V, \Sigma)$. Our core data structure is a typed **Directed Hypergraph** paired with a **Content-Addressed Merkle-DAG (The Worldline)** that versions the user’s intellectual state over time like Git versions source code.
4. **Sovereign Identity (12-Word Seed, Zero Cloud DB):** There is no "Sign in with Google." A user’s mind and strategic map are derived from a 12-word BIP-39 mnemonic. Every verified capability and artifact is cryptographically signed by keys derived from that seed.

---

## 2. Hard Engineering Constraints & Core Innovations: Resource Usage & Security

When a physicist, engineer, or founder uses Henosis, their machine is *already* under heavy load—running numerical simulations, compiling Rust/C++, running local LLMs, or hosting multiple child tools. **If Henosis consumes 1.5 GB of RAM like an Electron app or leaks an API key to a malicious Python research script, we have failed.**

### A. Resource Usage Architecture (The `< 45 MB` Baseline Mandate)

| Metric | Hard Ceiling | Architectural Mechanism |
| :--- | :--- | :--- |
| **Daemon + Native UI Idle RAM** | `< 45 MB` RSS | Native GPU UI (`gpui` / `iced`), zero Chromium baseline, `mmap` storage. |
| **Idle CPU Usage** | `0.0% – 0.1%` | Event-driven epoll/kqueue loop (`tokio`); zero polling loops. |
| **Hypergraph Query (100k nodes)** | `< 500 µs` | CSR (Compressed Sparse Row) incidence arrays + `rkyv` zero-copy archives. |
| **Sandbox Branch / Perturbation** | `< 2 ms`, `0 B` disk | Filesystem Copy-on-Write (`reflink` / `overlayfs`) worktrees. |
| **Cold Startup Time** | `< 80 ms` | Direct memory-mapped state hydration; lazy plugin initialization. |

#### Resource Innovation 1: Zero-Copy Memory-Mapped Hypergraph (`redb` + `rkyv` + CSR Matrices)
Never deserialize the Capability Hypergraph or the Worldline DAG into pointer-heavy heap structs (`Arc<Mutex<Node>>`). That destroys CPU L1/L2 cache locality and fragments the allocator.
* Store all persistent records in **`redb`** (a pure-Rust, ACID, zero-copy memory-mapped B-tree) serialized with **`rkyv`**. Reading a node or verification bundle requires **zero memory allocations** and **zero parsing**—it is a direct pointer cast over `mmap`-backed pages.
* Maintain the active topological index of the hypergraph $\mathcal{H} = (V, E)$ in contiguous **Compressed Sparse Row (CSR)** bit-packed incidence matrices in RAM. Computing a backward light-cone, bottleneck score $B(c_i)$, or topological skill decay propagation across 100,000 hyperedges executes via SIMD bitwise intersections in microseconds inside a few megabytes of memory.

#### Resource Innovation 2: Native GPU Shell + Cryogenic WebView Hibernation
* **No Electron:** The Henosis workspace shell is rendered directly on the GPU at 120fps using native Rust UI primitives (forking Zed’s **`gpui`** or **`iced` + `wgpu`**), with native mathematical typesetting powered by embedding the **`typst`** compiler crate directly in-process (eliminating 4 GB TeX Live installs and browser DOM overhead).
* **Cryogenic WebViews:** When the user opens an external web app (e.g., NotebookLM or a local web UI from `deeptutor`), Henosis spawns a disposable OS-native WebView (`wry`) in a child process. The moment the user switches back to the Realization Lab or closes the quarantine gate, Henosis extracts the DOM/network state differential, snapshots the session cookie jar, and **terminates or `SIGSTOP`s the WebView process**, reclaiming 100% of its RAM immediately.

#### Resource Innovation 3: Zero-Byte Copy-on-Write (CoW) Laboratory Cloning
When the **Akashi Verification Engine** runs 7 adversarial perturbations against a user’s simulation code, or when a user branches their Worldline to test two competing hypotheses, copying a 5 GB project directory will thrash the SSD and exhaust disk space.
* Henosis uses filesystem-level Copy-on-Write primitives (`ioctl_ficlonerange` / `clonefile(2)` on APFS, Btrfs, XFS, and ReFS, falling back to `overlayfs` mounts on ext4).
* Cloning an entire laboratory environment for an adversarial run takes **under 2 milliseconds and consumes zero additional bytes of disk space** until files actually diverge.

#### Resource Innovation 4: Backpressure-Driven Epistemic Compute Governor
Background synthesis jobs (scanning for cross-domain isomorphisms or recalculating global leverage estimates) must never contend with the user's foreground compiler or simulation.
* A background governor monitors OS load averages, thermal pressure, and child PTY process activity. Heavy graph analysis runs strictly on low-priority efficiency cores (`QoS::Background`) during user think-time pauses.

---

### B. Security Architecture (Zero-Trust Epistemic Enclave)

**The Threat Model:**
Henosis users regularly clone untrusted GitHub repositories (`learnharness`, arbitrary research paper codebases, PyPI/npm packages) and execute AI-generated code. If we pass `OPENAI_API_KEY` or `OPENROUTER_API_KEY` via a `.env` file or standard environment variable, **any malicious dependency in a child process can read `os.environ` and exfiltrate the user's master API keys and wallet seed in 3 lines of Python.**

We solve this with four systems-security innovations:

#### Security Innovation 1: The Phantom-Key Enclave & PID-Attested Unix Socket Proxy
Child applications (`learnharness`, `deeptutor`, terminal CLIs, web agents) **never receive real API keys.**
1. **Locked Memory Enclave:** Upon unlocking Henosis with the 12-word BIP-39 phrase, the derived master keys and external API credentials live inside pages locked in physical RAM via `mlock(2)` / `VirtualLock` (preventing OS swap-to-disk leaks), flagged with `madvise(MADV_DONTDUMP)` (excluding them from core dumps), and wrapped in `zeroize::Zeroizing` buffers.
2. **Phantom Capability Tokens:** When Henosis spawns a child app, it sets `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` to a local Henosis proxy listener and injects an ephemeral token: `henosis-cap-<random_nonce>`.
3. **Kernel-Level PID Attestation (`SO_PEERCRED` / `LOCAL_PEERPID`):** When the child app makes an LLM request to the local proxy, the kernel reveals the exact caller PID over the socket (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS, `GetNamedPipeClientProcessId` on Windows). Henosis verifies that:
   * The caller PID belongs to the authorized process tree spawned for that specific session.
   * The session’s current **AI Impedance Level** permits the call (if the user is in *Akashi Cleanroom Mode*, the proxy drops the connection at the socket layer).
   * Even if malware inside the child repo steals `henosis-cap-<nonce>` and sends it to an external hacker—or even to an unauthorized background process on the *same laptop*—the token is cryptographically dead because the kernel PID attestation fails.

#### Security Innovation 2: Exfiltration Firewall (Outbound Prompt DLP)
What if malicious code inside a reproduced research repo cannot steal the API key, so instead it reads `~/.ssh/id_rsa` or the user's Worldline database and stuffs the contents into an LLM prompt via the local proxy, hoping to read it back from an external webhook or shared log?
* The Local AI Proxy runs a sub-millisecond **Outbound DLP (Data Loss Prevention) & Entropy Scanner** on every intercepted prompt before attaching the real API key and forwarding upstream.
* It blocks requests containing high-entropy private key signatures, paths outside the project’s designated sandbox worktree, or unauthorized tool-call webhooks, and enforces a strict per-process token/dollar circuit breaker.

#### Security Innovation 3: Unprivileged Micro-Jails for Realization & Akashi Harnesses
Every Reproduction Lab, code execution task, and Akashi perturbation runs inside a zero-privilege OS micro-jail:
* **Linux:** Unprivileged User Namespaces + `Landlock` LSM (restricting filesystem visibility strictly to the CoW project worktree) + `seccomp-bpf` syscall filtering + isolated network namespace (loopback only to the Henosis Proxy; zero raw internet access during execution).
* **macOS:** Custom dynamically compiled Seatbelt profiles (`sandbox_init`) denying read/write outside the CoW worktree and blocking outbound sockets except the local proxy UNIX socket.
* **Portable Deterministic Solvers:** Fast mathematical/algorithmic grading harnesses compile to WebAssembly and execute inside an embedded **`wasmtime`** engine with fuel-metering (hard CPU instruction caps) and memory limits.

#### Security Innovation 4: Hardware-Anchored Cleanroom Attestation (Anti-Forgery Worldline)
To ensure that a signed capability proof ($E_{\text{human}}$) in the Worldline cannot be forged by pasting AI output or spoofing UI events:
* The **Akashi Attestation Key** (Ed25519) is gated inside the Sovereign Vault module. It will only sign an $E_{\text{human}}$ capability transition if presented with a cryptographic receipt from the Hypervisor proving that during the session window:
  1. The Local AI Proxy held an active **Blackout Lock** across all child sockets and WebViews.
  2. The OS clipboard bridge into the Cleanroom PTY/Editor was severed.
  3. The artifact passed the deterministic test harness inside a sealed micro-jail.

---

## 3. Open-Source Repositories to Fork, Embed, or Wrap (Your Head Start)

Do not build foundational commodities from scratch. Fork, vendor, or embed these specific repositories to compress 18 months of systems engineering into weeks:

### Core Rust Infrastructure (Fork or Vendor Directly)
1. **`c4us4l1ty/worldline` & `c4us4l1ty/odderon`**
   * **What to take:** The philosophical and structural blueprint for local-first deterministic state machines, BLAKE3 content-addressed Merkle-DAGs, encrypted sync envelopes, and BIP-39/Ed25519 sovereign identity management.
2. **`zed-industries/zed` (Specifically the `gpui` and `terminal` crates)**
   * **What to take:** `gpui` gives us a battle-tested, metal/vulkan-accelerated native Rust UI framework with minuscule memory overhead. Zed’s `terminal` crate (built atop **`alacritty/alacritty`'s `alacritty_terminal`**) gives us an instant, headless-capable PTY terminal emulator where we can intercept every command, compiler error, and keystroke cadence.
3. **`tensorzero/tensorzero` (or `katanemo/archgw`)**
   * **What to take:** Pure-Rust, ultra-low-latency unified LLM gateway primitives. Strip it down and wire it into our Sovereign Vault to create the **Henosis Local AI Proxy** supporting OpenRouter, Anthropic, OpenAI, and local Ollama/vLLM out of the box.
4. **`typst/typst`**
   * **What to take:** Embed `typst` as a native Rust library to compile and render mathematical derivations, proof reconstructions, and Research Reproduction Contracts at 120fps in milliseconds.
5. **`tauri-apps/wry`**
   * **What to take:** Cross-platform OS WebView binding. Use this *only* for the Cryogenic WebView viewport (to host NotebookLM, `arena.ai`, or external web UIs inside a child process with CDP/script injection hooks).
6. **`cberner/redb` + `rkyv/rkyv`**
   * **What to take:** Our zero-copy `mmap` storage engine for the Capability Hypergraph, Failure Atlas, and Worldline DAG.
7. **`bytecodealliance/wasmtime` & `landlock-lsm/rust-landlock`**
   * **What to take:** In-process WASI sandboxing and Linux kernel filesystem jailing for the Realization and Akashi execution harnesses.
8. **`n0-computer/iroh`**
   * **What to take:** Pure-Rust, hole-punching, BLAKE3-verified peer-to-peer QUIC transport (used in Block 6 for P2P Epistemic Syndicates).

### External Learning Ecosystems (Wrapped via the Hypervisor Adapter in Block 1)
Instead of rewriting their logic, write lightweight `LauncherSpec` adapters in Henosis that spawn these repos as managed child processes pointed at our Local AI Proxy:
* **`amosblomqvist/learnharness`**
* **`Jonathanvwersch/open-academy`**
* **`hkuds/deeptutor`**
* **`Companion-Inc/feynman`**

---

## 4. Cargo Workspace Architecture

```text
henosis/
├── Cargo.toml
└── crates/
    ├── henosis-vault/       # BIP-39 seed, HD keys, mlock enclave, Ed25519 signing
    ├── henosis-proxy/       # Local AI routing daemon, SO_PEERCRED auth, Impedance Controller, DLP
    ├── henosis-dag/         # BLAKE3 Worldline Merkle-DAG & CSR Capability Hypergraph (redb + rkyv)
    ├── henosis-jail/        # CoW worktrees (reflink), Landlock/Seatbelt sandboxes, PTY harness
    ├── henosis-akashi/      # 7 Proof Operators, Perturbation Injector, Blind Tribunal, Provenance
    ├── henosis-leverage/    # Bottleneck solver B(c_i), Lagrange shadow prices, Option Market J(a)
    ├── henosis-synthesis/   # Axiom Annihilator, Functorial Bridge isomorphism solver
    └── henosis-shell/       # Native GPU UI (gpui/iced), Typst canvas, Cryogenic WebView host
```

---

## 5. Block-by-Block Execution Plan (Every Block Is a Usable MVP with a UI)

We do not build backend libraries in the dark for six months. **Every block below compiles into a standalone, usable desktop binary with an immediate UI**, solving a hard bottleneck from Day 1 and stacking cleanly toward the singularity.

---

### BLOCK 1: The Sovereign Shell, Phantom-Key Vault & Epistemic Hypervisor
**The Bottleneck Solved:** You use `learnharness`, `deeptutor`, CLI coding agents, and NotebookLM, which requires configuring API keys in five places and scatters your intellectual activity across disconnected silos with zero unified tracking or AI resistance control.

#### Core Engineering Tasks:
1. **`henosis-vault`**: Implement 12-word BIP-39 mnemonic generation/recovery, Argon2id key stretching, `mlock` memory-pinned API key keyring (OpenRouter, Anthropic, OpenAI, Custom), and Ed25519 identity keypair derivation.
2. **`henosis-proxy`**: Build the local HTTP/SSE proxy daemon (`127.0.0.1:0` + UNIX domain socket) with PID-verified `henosis-cap-*` phantom tokens, outbound prompt DLP scanner, and the 3-state **AI Impedance Switch**:
   * *Mode 0 (Open)*: Pass-through.
   * *Mode 1 (Socratic Impedance)*: Rewrites system prompts on the fly across all child apps to forbid outputting complete solutions or final derivation steps.
   * *Mode 2 (Cleanroom Blackout)*: Hard-blocks generative AI traffic at the socket layer.
3. **`henosis-jail` (Process & WebView Adapters)**: Build the `AppHarness` supervisor that spawns external tools (`learnharness`, `deeptutor`, `open-academy`, `feynman`, or any user CLI) with auto-injected proxy environment variables, plus the **Cryogenic WebView** wrapper (`wry`) for NotebookLM with DOM/network activity hooks and automatic `SIGSTOP` hibernation on blur.

#### Block 1 Shippable UI (`henosis-shell`):
* **Vault Onboarding Screen:** Generate/import 12-word seed; add API keys once into the locked enclave.
* **The Hypervisor Split-Workspace:**
  * *Left Pane:* App Launcher & Active Process Tree (launch `learnharness`, `deeptutor`, NotebookLM, or an instrumented PTY terminal in one click with zero `.env` setup).
  * *Center Pane:* The active terminal, native scratchpad, or Cryogenic WebView viewport.
  * *Right Sidebar (Live Epistemic Radar):* Real-time stream of intercepted prompts, extracted concepts (tagged strictly as `UNVERIFIED EXPOSURE`), token/resource usage, and a physical hardware-style toggle for the **AI Impedance Controller**.
* **Exit Criteria:** Launch `learnharness` and a Python CLI inside Henosis without touching an API key; see their LLM calls intercepted live in the sidebar; toggle *Blackout Mode* and verify child apps are immediately cut off; verify Henosis daemon + shell uses `< 45 MB` RAM when the WebView is hibernated.

---

### BLOCK 2: The Worldline Merkle-DAG & Akashi Cleanroom (Proofs of Power)
**The Bottleneck Solved:** Consuming explanations in NotebookLM or `deeptutor` creates the illusion of competence. We must block unverified exposure from masquerading as capability and build the cryptographic ledger of verified human power.

#### Core Engineering Tasks:
1. **`henosis-dag` (Worldline Engine)**: Implement the BLAKE3 content-addressed branching Merkle-DAG in `redb` + `rkyv`. Every commit stores $W(t) = (K(t), C(t), A(t), E(t), H(t))$ signed by the user’s Ed25519 Worldline Key.
2. **The Epistemic Quarantine Gate**: Wire the Hypervisor so closing or ending a session in an external learning app/WebView places all extracted concepts into a `Quarantine Queue`.
3. **`henosis-akashi` (Verification VM v1)**:
   * Implement the **7 Proof Operators** (*Explain, Reconstruct, Implement, Criticize, Modify, Transfer, Predict Failure*).
   * Build the **Blind Tribunal Pipeline**: Strips all prior chat context, runs deterministic checks first (compiler/test suite/symbolic equation check), and only then passes the artifact to a fresh, zero-history *Adversarial Judge* prompt instructed to falsify the user's submission.
   * Implement strict **Provenance Tagging**: Records $E = (E_{\text{human}}, E_{\text{AI}}, E_{\text{joint}}, E_{\text{external}})$.

#### Block 2 Shippable UI:
* **The Quarantine Interrogation Modal:** When you close NotebookLM or `learnharness`, Henosis intercepts you: *"You spent 45m on [Topic]. It is currently Unverified Dust. Enter the Akashi Cleanroom now to convert it into a Capability, or discard to quarantine."*
* **The Akashi Cleanroom Workbench:**
  * Locks the proxy into *Blackout Mode* and isolates the clipboard.
  * Provides a live `typst` math/derivation canvas and an isolated CoW PTY coding editor to execute one or more Proof Operators from memory.
  * Displays the Blind Tribunal’s falsification feedback and, upon survival, signs the cryptographic capability commit.
* **The Worldline Branching Explorer:** A blazing-fast, interactive DAG visualizer where users can inspect their capability trajectory, branch their intellectual state when exploring rival hypotheses, and inspect the exact artifact and evidence hash behind every node.

---

### BLOCK 3: The Capability Hypergraph, Crux Razor & Reproduction Laboratory
**The Bottleneck Solved:** Real breakthroughs require executing complex multi-capability projects and reproducing/extending dense research papers without wasting months building the easy parts first while ignoring fatal bottlenecks.

#### Core Engineering Tasks:
1. **`henosis-dag` (CSR Capability Hypergraph)**: Implement the typed, attributed hypergraph $\mathcal{H} = (V, E)$ with **Realization Contracts** $e = (P, A, R, O, V, \Sigma)$ and strict epistemic status typing (`Established | Inferred | Hypothesized | Unknown`).
2. **Goal-Conditioned Source Compiler**: Ingests a PDF research paper, textbook chapter, or GitHub repository and compiles it into a structured **Reproduction Contract** (extracting central claims, governing equations, implicit assumptions, boundary conditions, required capabilities $P$, and target figures/benchmarks).
3. **The Crux Razor Engine**: Given a target project or Reproduction Contract, computes the backward light-cone against the user’s verified state $H$, identifies missing vs. weak capabilities, and calculates the **Crux**—the single operation or assumption maximizing $\frac{\text{Information Gain} \times P(\text{Fatal Failure})}{\text{Cost to Test}}$.
4. **`henosis-jail` (Adversarial Perturbation Harness & Failure Atlas)**: Uses CoW directory cloning + OS micro-jails (`Landlock`/Seatbelt/`wasmtime`) to inject controlled perturbations into the user's working code/simulation (altering timesteps, parameters, boundary conditions) and commits broken assumptions into the **Failure Atlas**.

#### Block 3 Shippable UI:
* **The Reproduction Lab & Crux Studio:** Drag-and-drop a research paper or declare an engineering target. The UI renders the compiled Reproduction Contract alongside the **Crux Razor Execution Graph**—locking out low-risk boilerplate tasks until you pass a rapid falsification test on the #1 Crux.
* **The Adversarial Perturbation Runner:** Once your implementation passes baseline tests, click *"Run Akashi Stress Test."* The UI spawns parallel CoW micro-jails with perturbed parameters and asks you to **Predict Failure** (Operator 07) before showing you where your solver or model explodes.
* **Interactive Hypergraph & Failure Atlas Explorer:** Fast GPU-rendered canvas showing your verified capabilities, conditional hyperedges, and the catalog of documented failure boundaries.
* **Agency Telemetry HUD:** Non-gamified diagnostic strip tracking latency from intention to first crux execution, epistemic thrashing rate, and solo-struggle endurance.

---

### BLOCK 4: The Leverage Engine, Constraint Cartographer & Option Market
**The Bottleneck Solved:** Deciding *what* to learn or build next. Without a decision-theoretic engine, high-agency minds still waste years on low-leverage problems or drown in spaced-repetition review debt.

#### Core Engineering Tasks:
1. **`henosis-leverage` (Bottleneck vs. Multiplier Solver)**:
   * Computes local bottleneck relief $B(c_i) = P(G \mid H + c_i) - P(G \mid H)$ over the CSR hypergraph.
   * Computes the strategic objective $J(a) = \Delta V_{\text{goal}}(a) + \lambda \Delta V_{\text{options}}(a) + \mu \Delta V_{\text{transfer}}(a) - \rho C(a)$ with explicit uncertainty bounds (representing competing payoff hypotheses rather than fake single-number scores).
2. **The Constraint Cartographer & Shadow Price Estimator ($\lambda_k$)**: Maps frontier walls $\partial \mathcal{F}$ by tracking the **Asymptotic Cost Gap** ($\frac{\text{Current Cost}}{\text{Physical/Theoretical Minimum}}$) and **Workaround Density** (how many failures and patches in imported literature/repos pile up against constraint $k$).
3. **Topological Skill Half-Life Propagator ($R_c(t)$)**: Tracks multi-dimensional retention decay across five axes (*Recall, Derive, Apply-Familiar, Apply-Unfamiliar, Implement*). Whenever a high-level Realization Contract succeeds in Block 3, retention replenishment cascades backward down all prerequisite hyperedges $P$ automatically—eliminating redundant reviews for actively composed skills.

#### Block 4 Shippable UI:
* **The Strategic Leverage & Option Market Cockpit:**
  * Displays your active frontiers $G$ alongside ranked candidate interventions $a$—explicitly distinguishing *Local Bottleneck Fixes* from *High-Option-Value Multipliers*, and flagging low-yield study paths for **Immediate Abandonment**.
  * **The Asymptotic Gap (Idiot Index) Inspector:** Interactive breakdown of any target problem into Level 0 physical limits vs. current implementation cost to highlight where massive shadow prices ($\lambda_k$) are hiding.
* **Topological Health & Decay Radar:** Highlights only "orphaned" foundational capabilities whose decay $R_c(t)$ threatens a load-bearing branch of your graph, scheduling a single surgical Akashi reconstruction challenge instead of 200 flashcards.

---

### BLOCK 5: The Synthesis Engine (Axiom Annihilator & Functorial Bridge)
**The Bottleneck Solved:** Moving from *acquiring existing human capabilities* (Mode 1) to *inventing new capabilities and discovering breakthroughs* (Mode 2) by systematically deleting false dogmas and bridging structurally isomorphic domains.

#### Core Engineering Tasks:
1. **`henosis-synthesis` (The Axiom Annihilator)**:
   * Given a high-$\lambda_k$ Constraint Wall on $\partial \mathcal{F}$, extracts the minimal dependency tree of axioms $\{\alpha_1, \dots, \alpha_m\}$ required for the impossibility boundary to hold.
   * Classifies each axiom into **Level 0 (Iron Law)**, **Level 1 (Empirical Regime)**, or **Level 2 (Historical Dogma / Convention)**.
   * Runs the **Lobachevsky Operator**: Deletes one Level 1 or Level 2 axiom at a time, formulates the resulting counterfeit/non-Euclidean state space, and computes the cheapest empirical or formal test to falsify the axiom.
2. **The Functorial Bridge (Structural Isomorphism Solver)**:
   * Encodes verified capability modules and open problems into domain-agnostic **Structural Signatures** (conservation laws, symmetry groups, state-space differential equations, feedback topologies, queueing/min-cut graphs, game-theoretic payoff matrices).
   * Searches for structural homeomorphisms across zero-citation-overlap domains and forces every candidate match through the **Three-Part Transfer Gate**:
     $$\text{Structural Correspondence} + \text{Preserved Operations} + \text{Explicit Failure Boundary}$$
   * Includes the **Rejection Filter** to kill trivial or unfalsifiable analogies before they reach the UI.

#### Block 5 Shippable UI:
* **The Axiom Annihilation Lab:** Visualizes the impossibility proof holding back your target domain as a structural dependency tree; lets you sever a Level 1/2 axiom node, inspect the unlocked counterfactual region $\Delta \mathcal{F}$, and auto-generates a 1-day falsification protocol in the Realization Engine.
* **The Functorial Bridge Workbench:** Side-by-side structural translator mapping an unsolved problem in Domain $A$ onto a solved mechanism in Domain $B$, highlighting exact variable mappings, conserved invariants, and the red-zone regime where the isomorphism shatters.

---

### BLOCK 6: P2P Epistemic Syndicates & Civilizational Capability Protocol
**The Bottleneck Solved:** Connecting sovereign minds into a decentralized division of intellectual labor—allowing peers to stress-test each other's discoveries, exchange verified capability modules, and compute collective reach without a central corporate server.

#### Core Engineering Tasks:
1. **Cryptographic Capability Bundles (`.hcap`)**: Package any verified Method, Realization Contract, reproduction suite, Failure Atlas log, and signed Akashi Attestation receipt into a portable, deterministic, content-addressed bundle.
2. **Encrypted P2P Transport (`iroh`)**: Direct peer-to-peer QUIC sync and syndicate rooms authenticated via Ed25519 keys derived from each user's 12-word seed, supporting multi-device personal Worldline sync (CRDT/deterministic DAG merge) and selective zero-knowledge/full-provenance capability disclosure.
3. **Compositional Leverage Solver**: Given two or more peers’ exported capability hypergraphs ($H_A, H_B$), computes:
   $$\Delta \mathcal{F}_{\text{syn}}(H_A, H_B) = \mathcal{F}(H_A \cup H_B) - \bigl(\mathcal{F}(H_A) \cup \mathcal{F}(H_B)\bigr)$$
   identifying high-leverage Realization Contracts that neither peer can execute alone but both can execute together.

#### Block 6 Shippable UI:
* **The P2P Syndicate & Adversarial Peer-Review Arena:** Publish a redacted or full `.hcap` artifact to your syndicate; peers pull it into their local CoW micro-jail and attempt to break it using Operators 04 (*Criticize*) and 07 (*Predict Failure*). Validated breaks automatically append to the shared Failure Atlas and award verified criticism provenance to the breaker.
* **The Co-Founder / Syndicate Synergy Matrix:** Visual overlay of two or more minds’ hypergraphs showing instant compositional unlocks, redundant overlaps, and collective blind spots against a chosen civilizational frontier.

---

## 6. First Day Engineering Checklist (Getting Started on Block 1)

1. Initialize the Cargo workspace with `rust-toolchain.toml` pinned to stable Rust, enforcing `#![deny(unsafe_code)]` across all crates except the explicitly audited OS syscall wrappers in `henosis-vault` (`mlock`) and `henosis-jail` (`SO_PEERCRED`, `Landlock`, `reflink`).
2. Stand up `henosis-vault` + `henosis-proxy` first and write an integration test that spawns a mock Python child script attempting to read `os.environ` and exfiltrate a dummy secret—verify the Phantom-Key PID check and Outbound DLP Firewall catch and kill it in `< 1 ms`.
3. Wire `henosis-shell` using `gpui` (or `iced`) + `alacritty_terminal`, embed the proxy status bar, and wrap `learnharness` as Target App #1.
4. Measure baseline RSS memory on Linux/macOS/Windows on every PR in CI. **Any PR that pushes idle RSS above `45 MB` or breaks deterministic replay of the Worldline DAG fails CI automatically.**
