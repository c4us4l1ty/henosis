# Henosis

Henosis is an early-stage, local-first Rust project for building demonstrated
capability. The product vision and staged engineering plan live in [`vision/`](vision/).

## Current state

This repository currently contains only the first piece of the Block 1 process
adapter: an interactive process workspace and a reusable `LauncherSpec`. The launcher
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

**Security limitation:** this is a process launcher, not a jail. A child can
still read accessible files, inspect processes, and use the network. Do not run
untrusted software with it or assume it protects secrets. There is no vault,
proxy, PID attestation, DLP, cleanroom, desktop UI, or capability verification
yet. No performance or isolation claims have been validated. These remain future
work, not features implied by the crate names or vision documents.
