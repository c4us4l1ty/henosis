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
proxy, PID attestation, DLP, cleanroom, desktop UI, or capability verification
yet. No performance or isolation claims have been validated. These remain future
work, not features implied by the crate names or vision documents.

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
is created if missing; its parent directory must already exist. Each append is
synced to disk, and malformed or incomplete journals are rejected rather than
silently discarded. This is a **single-writer**, plaintext journal: do not use
multiple workspaces on the same file, and do not put secrets in it. Newly created
files use owner-only permissions on Unix; existing permissions are unchanged.
It is not encrypted, signed, tamper-evident, or protected against rollback, and
partial writes or storage failures can require manual repair. These are user
assertions, not verification, automated crux selection, or proof of capability.
