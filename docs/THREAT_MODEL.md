# Threat model: trusted experiment runner and future credential proxy

## Scope and trust assumptions

The current runner executes a user-selected executable in a user-selected local
project. It is intended only for code and files the user trusts, in directories
other users and processes cannot modify. The user, OS, journal directory, binary,
project, and artifact are assumed trustworthy. There is no adversarial isolation.
An empty child environment reduces accidental inheritance; it is **not** a
security boundary. The process can access readable files, the network, processes,
and credentials available through OS facilities, and may launch descendants.

The journal, backup, captured stdout/stderr, executable paths, arguments, and
artifact names are plaintext. Never put credentials in these fields or output.
The file lock is advisory and directory replacement or non-cooperating writers
are out of scope. A hash records bytes read after the command; it does not prove
who produced them, their creation time, completeness, or correctness. The
artifact can be modified concurrently, may predate the run, and symlinks are
followed. Output can be truncated, incomplete, or written by descendants.

## Misuse and failure cases

- A command or dependency reads local secrets or exfiltrates them over the network.
- A process hangs or spawns descendants. Unix experiment timeout sends a
  best-effort group SIGKILL and terminates the direct child; escaped descendants
  can survive, and a successful signal does not prove all stopped. On Windows,
  only the direct child is terminated. Normal exit and setup failures do not
  clean up descendants. Inherited output pipes can keep reader threads alive.
- Crash, full disk, partial writes, or sync failure can lose or partially record
  an event; a failed append may have written data. Inspect before retrying.
- Output contains secrets or terminal control sequences. Display escapes control
  characters, but storage remains plaintext and child output may contain secrets.
- A user or process alters a journal or artifact. There is no authenticity,
  rollback protection, trusted timestamp, or immutable chain of custody.
- A passing exit code or recorded hash is mistaken for verified capability.
  The UI must label results as observations, not human or cleanroom proof.

## Before a credential-injecting proxy

Do not pass real API keys to experimental runners. Define supported platforms,
attacker capabilities (including same-user malware and process-tree escape),
credential lifecycle, user consent, per-session authorization and revocation,
request limits, logging/redaction, and failure behavior. Prototype and test the
actual OS-enforced boundary before claiming a token is bound to a process or
that blackout blocks all network access. TCP does not inherently provide reliable
caller PID identity; any local-socket attestation must be evaluated for the target
OS and proxy architecture. Prompt scanning cannot guarantee exfiltration prevention.
Independent security review and adversarial tests are prerequisites for handling
real credentials; none of those protections exist today.

The shell records an attempt before starting a command and links a later result
or runner error. An unfinished attempt may or may not have executed. A runner
error does not prove the command had no effects. These records improve recovery
visibility but are not an atomic transaction with external process execution.

Artifact comparison re-reads the path recorded in the journal. A matching hash
is only a comparison to that unauthenticated record; it is not an independent
attestation. Symlink substitution and concurrent modification are out of scope.

User recovery notes are assertions, not process results. Reviewing an attempt
does not stop it, establish whether it ran, or make retrying safe. Unfinished
attempts remain visible even after a review.

An explicit environment allowlist reduces accidental inheritance, not access to
local secrets. Values selected for `runenv` are not directly serialized, but can
appear in output, files, network traffic, process inspection, or crash data.
Only select non-secret values; never treat name filtering as secret detection.

Pre-run and post-run artifact observations are non-atomic reads of a mutable
path. A comparison describes only the bytes observed, not authorship, a complete
change history, or an integrity guarantee; concurrent processes, symlink changes,
and surviving descendants can affect either observation. Not-found includes
paths that cannot resolve (such as a dangling symlink), not proof of creation.
Older results have no pre-run observation.
