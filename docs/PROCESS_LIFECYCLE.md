# Process lifecycle: investigation and proposed next step

## Current behavior

Henosis runs trusted software, not a sandbox. On Unix, an experiment starts in a
new process group. On timeout only, Henosis attempts SIGKILL on the group before
reaping the leader, then separately kills and reaps the direct child. The result
records a group signal error separately; success means only that the OS accepted
the signal, not that all descendants stopped. If killing or waiting on the direct
child fails, the runner reports an error including the cleanup attempt instead of
claiming a completed result. On Windows, timeout still handles only the direct
child. Old records do not contain cleanup details.

Group cleanup is not attempted after normal child exit or reader setup failure.
Descendants can leave the group, and inherited pipes can hold reader threads open
past the bounded drain wait. The background supervisor still stops only direct
children. If Henosis crashes or is killed, normal cleanup cannot be relied upon.
Review of an unfinished attempt does not stop processes.

## Future work (not implemented)

Decide whether descendants should be terminated after a successful direct-child
exit, on setup failure, explicit stop, and workspace shutdown; changing this can
break commands that intentionally leave services running. Never signal a group
ID after its leader is reaped: IDs may be recycled. Account for processes that
move groups or sessions, and surface teardown failures. Group signaling is not
containment and should not be marketed as a sandbox.

On Windows, investigate a Job Object configured for kill-on-close, using a
reviewed safe wrapper. Avoid a spawn-then-assign gap where the child can create
descendants before assignment; assess suspended creation/assignment, nested-job
restrictions, breakaway settings, and handle inheritance. Assignment failure
must have a defined fail-closed or explicitly downgraded outcome. Kill-on-close
behavior depends on ownership and handle lifetime, and is not a sandbox or a
guarantee against every escape. Consider separate policies for background
launches and experiments. Preserve the workspace's `deny(unsafe_code)` policy.

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
