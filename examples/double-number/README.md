# Double a number: evidence walkthrough

This intentionally small, trusted Rust program reads `input.txt`, doubles the
integer, and writes `result.txt`. Work in a copy, not the repository directory.
Compile it with `rustc main.rs -o double-number` (on Windows use
`double-number.exe`). In Henosis's workspace, substitute the **absolute paths**
of the copy and executable, and quote paths containing spaces:

```text
propose journal.jsonl "Double a number" "The program doubles its input" "Run the program"
run journal.jsonl 1 /absolute/project result.txt 0 /absolute/project/double-number
show journal.jsonl 1
compare journal.jsonl 3
```

The proposal is event 1, the attempt is event 2, and the result is event 3 in a
new journal. Edit `result.txt` and run `compare journal.jsonl 3` again to see
`DIFFERENT`. These IDs are not fixed in an existing journal. A hash match only
compares bytes; it does not verify correctness or authorship. The journal is
plaintext and the executable is not sandboxed. Never run untrusted programs.

The optional `--pause` argument waits up to ten seconds after creating
`started.marker`, then continues when `release.marker` appears. It demonstrates
an interrupted workspace: stopping Henosis does **not** stop all descendants.
Create the release marker or wait for the sample to time out, inspect the
project, and use `pending journal.jsonl` to see the unresolved attempt. You can
record your inspection with `review journal.jsonl ATTEMPT_ID "inspected"`.
That note is not a result: the attempt stays pending and the child may still
run. Never assume an unfinished attempt was not executed.
