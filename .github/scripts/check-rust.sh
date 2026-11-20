#!/usr/bin/env bash
# Mirror compiler diagnostics into check annotations (also readable via gh api).
set +e
export CARGO_TERM_COLOR=never
cargo "$@" > cargo-check.log 2>&1
result=$?
cat cargo-check.log
python3 - <<'PY'
from pathlib import Path
import re
lines = Path("cargo-check.log").read_text(errors="replace").splitlines()
if any(line.startswith("Diff in ") for line in lines):
    full = "\n".join(lines)
    for start in range(0, min(len(full), 31500), 3500):
        chunk = full[start:start+3500]
        print("::error::" + chunk.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D"))
else:
    for i, line in enumerate(lines):
        if re.match(r"^(error(\[|:)|warning:|test .*FAILED|---- .* stdout ----)", line):
            text = "\n".join(lines[max(0, i-2):i+24])
            level = "warning" if line.startswith("warning:") else "error"
            print(f"::{level}::" + text.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D"))
PY
exit "$result"
