# Henosis

Henosis is an early-stage, local-first Rust project for building demonstrated
capability. The product vision and staged engineering plan live in [`vision/`](vision/).

## Current state

This repository contains an early Block 1 process adapter: an interactive
process workspace and a reusable `LauncherSpec`, plus an experimental crux journal. The launcher
starts an executable with an **empty environment**, so credentials in the parent
environment are not automatically passed to it. Arguments are passed directly,
not interpreted by a shell.

```sh
cargo test --workspace
cargo run -p henosis-shell # interactive workspace
cargo run -p henosis-shell -- /bin/echo 'Hello, Henosis'
```

In the workspace, use `launch /absolute/path/to/program "argument with spaces"`,
`list`, `stop ID`, and `exit`. Background children have no terminal input;
their output shares the workspace terminal. Exit attempts to stop and reap direct
children, but does **not** terminate descendants. Processes that escape or outlive
their parent are not supervised. One-shot invocation remains available for
interactive terminal programs.

Use an absolute path to the executable. Programs that rely on `PATH`, `HOME`, or
other environment variables may not work from the CLI yet. Library callers can
explicitly add non-secret variables with `LauncherSpec::env`.

An experimental `henosis-vault` library now provides 12-word BIP-39 generation,
recovery, and a deterministic Henosis-specific Ed25519 identity. It is not wired
into the workspace UI. The derivation uses HKDF-SHA256 with salt
`henosis.identity.v1` and info `ed25519.signing-key`, and is not a BIP-32/SLIP-10
wallet. A BIP-39 passphrase is optional but must be retained exactly for recovery.
An experimental library-only envelope can encrypt bounded bytes with Argon2id
and XChaCha20-Poly1305; its versioned header is authenticated. Create-only file
storage writes the encrypted envelope to a temporary file and publishes it without
overwriting existing files. It requires a trusted directory, has no update or
rollback detection, and is not integrated with the shell. Windows permissions
depend on the directory ACL, and directory durability is not guaranteed. Do not use these
early, unaudited primitives with existing wallets, production secrets, or funds:
there is no memory locking, trusted display, or audited secret handling.
Signatures alone do not establish human authorship or verified capability.

**Security limitation:** this is a process launcher, not a jail. A child can
still read accessible files, inspect processes, and use the network. Do not run
untrusted software with it or assume it protects secrets. There is no secure vault,
proxy, PID attestation, DLP, cleanroom, or capability verification
yet. No performance or isolation claims have been validated. These remain future
work, not features implied by the crate names or vision documents.

## Native desktop app (Rust)

The experimental `henosis-desktop` app uses **egui/eframe**, not a browser or
Python. It connects to one persistent `henosis-shell` process so launched
children and session state remain in the existing Rust supervisor.

```sh
cargo build --locked -p henosis-shell -p henosis-desktop
cargo run --locked -p henosis-desktop
# Or run target/debug/henosis-desktop directly (.exe on Windows).
```

A graphical desktop/display and the usual native graphics libraries are required.
On Debian/Ubuntu, install `build-essential pkg-config libxkbcommon-dev
libxkbcommon-x11-0 libgl1-mesa-dev` before building. Windows and macOS use their native windows;
Linux supports X11/Wayland. Headless servers cannot show the app.

The **Desktop** GitHub Actions workflow compiles on Linux, macOS, and Windows,
checks desktop formatting/lints/tests, tests the persistent Rust connection, and
smoke-tests a Linux window under Xvfb. Its `henosis-desktop-<OS>` artifacts contain
both debug binaries: extract them together and launch `henosis-desktop`.
These are development builds, not signed installers or standalone app bundles;
Linux still needs the native runtime libraries above.

1. On launch, the app automatically connects to a sibling `henosis-shell` binary
   when present; open **Settings** to change the shell path, reconnect, or edit
   active file paths (`crux.jsonl`, `worldline.json`, `vault.hnv`). Only choose a
   trusted Henosis binary.
2. **Crux** displays interactive proposal cards with plain-English subtitles,
   inline forms to propose, observe, score, run background experiments, close or
   reopen proposals, review unfinished attempts, and detect artifact drift.
3. **Worldline** inspects and edits capability nodes, realization contracts
   (with interactive backward light-cone views), quarantined exposures, failure
   boundaries, branches, and signed/unsigned commit history.
4. **Akashi** verifies capabilities via recorded command results, written proof
   artifacts, or isolated perturbation suites, and exports/imports `.hcap`
   bundles.
5. **Vault & Proxy** manages encrypted `.hnv` vaults and provider credentials
   using masked password/secret inputs (`Zeroizing<String>`), and controls the
   local `127.0.0.1` AI Proxy (`Open` / `Socratic` / `Blackout` modes, ephemeral
   capability tokens, and one-click quarantine of intercepted prompts).
6. **Processes** launches absolute executable paths (optionally as Unix process
   groups via `launch-group`) with status cards and one-click **Stop** / **Stop
   Group** controls, while the collapsible **Console** drawer at the bottom
   exposes raw shell commands and bounded (~200 KB) output logs. Do not enter
   secrets, passwords, or mnemonics into the raw console drawer.

Closing the window requests EOF after queued commands and waits for the backend
to stop/reap direct children. A long-running command can delay closing. The GUI
never force-kills the supervisor; descendants can still outlive it. An unsuccessful
backend exit keeps the window open so cleanup diagnostics can be inspected. Crashes or
forcibly terminating the GUI are not graceful shutdown. Like the CLI, **this is
not a sandbox** and does not isolate files, processes, credentials, or network
access. The GUI does not change the launcher's empty-child-environment policy.

## Experimental crux journal

The interactive workspace can record a goal, a suspected bottleneck, a test,
and subsequent observations in a local JSON-lines file:

```text
propose ./crux.jsonl "Improve the prototype" "Heat loss is the bottleneck" "Measure heat loss under load"
observe ./crux.jsonl 1 "Loss was lower than expected"
journal ./crux.jsonl
```

Quote fields containing spaces. IDs are one-based event positions, so an
observation refers to the ID of a proposal (not another observation). The file
is created by `propose` if missing; its parent directory must already exist.
Reading a missing journal reports an error instead of showing an empty history. Each append is
synced to disk, and malformed or incomplete journals are rejected rather than
silently discarded. Unknown event types or fields are rejected rather than
silently misinterpreted; newer journal formats may require a newer Henosis.
This is a plaintext journal: do not put secrets in it. Cooperating Henosis
readers and writers use advisory file locks to serialize access; other programs
may ignore the locks, and filesystems may not support them reliably. Newly created
files use owner-only permissions on Unix; existing permissions are unchanged.
It is not encrypted, signed, tamper-evident, or protected against rollback, and
partial writes or storage failures can require manual repair. An append error may
be reported after some or all of the event was written (including on sync failure);
inspect the journal before retrying to avoid duplicating an event. Initial file
creation is not guaranteed durable across a crash because its directory is not
synced. The directory must
not be modified concurrently, including replacing or unlinking the journal path. These are user
assertions, not verification, automated crux selection, or proof of capability.

To compare proposed tests, record subjective estimates and view the ranking:

```text
assess ./crux.jsonl 1 5 4 2
rank ./crux.jsonl
```

The three integer estimates are **information**, **fatal-failure concern**, and
**cost**, each from 1 (low) to 5 (high). The ranking sorts by
`information × failure / cost`, highest first; ties go to the earlier proposal.
This is a simple heuristic applied to ordinal estimates, not a calibrated
probability, measurement of information gain, or proof of the best experiment.
The latest assessment of each proposal is used; unassessed proposals are omitted.
Observations do not automatically close or change a proposal's rank: reassess it
as your understanding changes or explicitly close it. The full history remains visible with `journal`.
Older journals containing only proposals and observations remain readable; older
versions of Henosis cannot read the new assessment records.

Journals are limited to 8 MiB and must be regular files in a trusted directory.
On Unix, opening a FIFO is nonblocking and rejected. Symbolic links are followed;
this journal does not defend against hostile changes to its directory or files.

Use `show ./crux.jsonl 1` to inspect one proposal and its assessment and
observation history in order. Journal text is escaped when printed if it
contains terminal control characters.

When a test is complete or no longer useful, remove it from the active ranking
without deleting its history:

```text
close ./crux.jsonl 1 "Experiment complete"
reopen ./crux.jsonl 1 "New evidence merits another test"
```

Proposals start open. The latest status change determines whether a proposal
appears in `rank`; reopening retains its latest assessment. Status changes are
user-reported, may be repeated, and do not verify the result. Observations and
assessments can still be recorded for closed proposals. Older versions cannot
read status-change records.

### Back up a journal

```text
backup ./crux.jsonl ./crux-backup.jsonl
```

This validates the journal under a shared lock and creates a point-in-time,
byte-for-byte plaintext copy. Later events are not included. The destination
must not exist, and both directories must be trusted; this operation will not
replace an existing file. The temporary backup is synced before publication,
but directory durability is not guaranteed and a crash may leave a temporary
file. Backup permissions are owner-only on Unix and depend on directory ACLs on
Windows. Backups are not encrypted or tamper-evident. Store copies securely
and separately, and verify that they can be read before relying on them.
To restore, stop all writers and copy a verified backup to a **new** journal
path; do not replace or unlink a journal while any workspace has it open.

### Run a trusted experiment

A runnable, end-to-end example lives in [`examples/double-number`](examples/double-number/).

Create a proposal, then run a command and attach its result:

```text
propose ./crux.jsonl "Check the build" "Tests catch regressions" "Run the test suite"
run ./crux.jsonl 1 /absolute/project/path target/output.bin 0 /absolute/path/to/program argument
show ./crux.jsonl 1
```

The fields after the proposal ID are the absolute project directory, artifact
path relative to it, expected exit code, absolute executable, and arguments.
Arguments are passed directly; no shell is invoked unless explicitly requested.
The child receives an empty environment and no terminal input. This runs **trusted
software only**, not a sandbox. It can read files, use the network, and launch
descendants. On Unix, experiments run in a separate process group; on the
30-second timeout, Henosis attempts to send SIGKILL to that group and kills and
reaps the direct child. A successful group signal is not proof that every
descendant stopped: processes can leave the group. On Windows, timeout still
kills only the direct child. Normal completion, setup errors, workspace crashes,
and background `launch`/`stop` do not provide group cleanup. Descendants may
continue on every platform. Output is drained but only the first 16 KiB per stream is retained. Invalid
UTF-8 is replaced for display and storage, with a lossiness flag; older results
may not include that flag.
If descendants keep pipes open, capture stops waiting after one second and marks
output incomplete; reader threads may persist until the pipes close. Results
record whether timeout cleanup was attempted and any Unix group-signal error;
if direct-child termination or waiting fails, a runner error is recorded instead.
Older results do not have cleanup details, and older versions cannot read new
results containing them.

Henosis observes the artifact immediately before spawning the command and again
after it exits. Each hash covers at most 64 MiB of one regular file. The result
reports APPEARED (not found before, readable afterward), CHANGED or UNCHANGED
(comparing hashes), or UNAVAILABLE if comparison is impossible. Missing,
unreadable, non-regular and oversized files can prevent comparison. Older results
have no pre-run observation and report UNAVAILABLE. Older Henosis versions cannot
read results containing the new observation.

These are observations, not proof that the command created or changed the file:
other processes can modify it, symlinks are followed, reads can race with changes,
and descendants may continue running. Even UNCHANGED cannot rule out temporary
changes. Exit-code matches and hashes are not proof of correctness, human
authorship, unassisted work, isolation, or verified capability. Output, arguments,
paths and errors are stored in plaintext; do not include secrets.
If recording fails after execution, inspect the journal and project before retrying.

Before execution, `run` records an attempt and its command details in the
journal. A result or runner error is then appended and linked to that attempt.
Use `pending ./crux.jsonl` to find attempts without a recorded outcome, and
`show ./crux.jsonl ID` to inspect the proposal history. An unfinished attempt
may be running, may have run, or may never have started: inspect the project
and journal before retrying. A runner error also does not prove the command
had no effects. Storage failures, process termination, or power loss can still
leave incomplete or corrupt journals; this is not transactional execution.
Older command-result records without attempt IDs remain readable. Older Henosis
versions cannot read the new attempt events. Pre-run artifact observations are
stored only with a completed command result: an interrupted attempt or runner
error has no persisted before-and-after comparison.

### Compare an artifact with a recorded result

Use `journal FILE` or `show FILE PROPOSAL_ID` to find a **command result's
event ID**, then run:

```text
compare ./crux.jsonl RESULT_ID
```

This reads the current artifact at the result's recorded project and relative
path, computes SHA-256, and displays whether it matches the recorded digest. It
does not rerun the command or add a journal event. A missing artifact, absent or
malformed recorded hash, or file larger than 64 MiB produces an error, not a
match. The project must be trusted; symlinks are followed, the file can change
while being read, and the journal can be edited. A match is not proof of who
created the file, correctness, cleanroom conditions, or verified capability.

After inspecting an unfinished attempt, `review FILE ATTEMPT_ID "your note"`
records a user-authored recovery note in the proposal history. `pending` marks
reviewed attempts but continues to list them until a command result or runner
error is recorded. A note does not stop the process, establish an outcome, or
make a retry safe; the command might still be running. Later command results
remain valid. Notes are plaintext, and older Henosis versions cannot read them.

#### Explicit non-secret environment variables

`run` still clears the child's entire environment. If a trusted program needs
specific **non-secret** values from the environment Henosis was started with,
select their names explicitly:

```text
runenv ./crux.jsonl 1 /absolute/project result.txt 0 LANG,TZ /absolute/program argument
```

Names are comma-separated, unique uppercase ASCII identifiers (up to 32); each
must already exist in Henosis's parent environment. Missing or invalid names
prevent the command from starting. The journal records the selected **names**,
not their values; this limits reproducibility if the values later change.
This is not a secret-management feature: the child and descendants can read,
write, print, or transmit values, and captured output is stored in plaintext.
Never pass credentials, tokens or other secrets. Empty environment does not
sandbox the program or prevent it from accessing files and the network. Older
journal records without environment names remain readable; older Henosis versions
cannot read records with the new field.
