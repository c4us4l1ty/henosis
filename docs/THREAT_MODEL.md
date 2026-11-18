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
- A process hangs or spawns descendants. Timeout kills only the direct child;
  inherited output pipes can keep reader threads alive after the run returns.
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
