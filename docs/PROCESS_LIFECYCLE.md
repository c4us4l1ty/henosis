# Process lifecycle: investigation and proposed next step

## Current behavior

Henosis runs trusted software, not a sandbox. The evidence runner kills and
reaps the **direct child** on timeout; its descendants may survive and may keep
output pipes open. After a bounded drain wait, output is marked incomplete, but
reader threads can remain until the pipes close. The background supervisor also
stops only direct children. If Henosis is killed or crashes, its normal cleanup
cannot be relied upon. Review of an unfinished attempt does not stop processes.

## Candidate design (not implemented)

Make process-tree cleanup an explicit, best-effort execution policy. Decide
whether descendants should be terminated after a successful direct-child exit
as well as on timeout, stop, and normal workspace shutdown; changing this could
break commands that intentionally leave services running. Keep direct-child
status, timeout, cleanup attempted/failed, and incomplete output distinct in
evidence. An inability to establish the requested containment must be visible,
not silently presented as successful tree cleanup.

* **Unix:** start the child in a dedicated process group before execution, and
  signal that group while managing the direct child's wait/reap. A group is not
  containment: descendants may move groups or sessions, and parent termination
  does not automatically kill the group. Avoid signaling a recycled numeric
  process-group ID after the group has disappeared; lifecycle, reaping, and
  concurrency need careful design. Unix group APIs and portable signaling need a
  reviewed safe wrapper compatible with the workspace's `deny(unsafe_code)`.
* **Windows:** investigate a Job Object configured for kill-on-close, using a
  reviewed safe wrapper. Avoid a spawn-then-assign gap where the child can
  create descendants before assignment; assess suspended creation/assignment,
  nested-job restrictions, breakaway settings, and handle inheritance. Assignment
  failure must have a defined fail-closed or explicitly downgraded outcome.
  Kill-on-close behavior depends on ownership and handle lifetime, and is not a
  sandbox or a guarantee against every escape.

Prototype each platform independently before promising equivalent behavior.
Consider separate policies for interactive/background launches and experiments.
Bound teardown and output draining; surface failures rather than claiming every
process was terminated. Do not call platform-specific APIs through unsafe code
in these crates without an explicit, separately reviewed change to that policy.

## Validation before shipping

Use controlled fixture processes and marker/handshake files rather than timing
alone. Exercise child and grandchild termination on timeout and explicit stop,
normal completion policy, already-exited processes, spawn/assignment failures,
stdout inherited by a grandchild, repeated cleanup, and shell crash/kill. Run
on Linux, macOS and Windows, including constrained CI environments; ensure each
test has independent cleanup and cannot kill unrelated processes. Test and
document known escapes rather than asserting universal process-tree control.
An independent security review is needed before treating any mechanism as a
security boundary.
