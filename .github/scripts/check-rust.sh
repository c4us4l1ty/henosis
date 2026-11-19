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
for i, line in enumerate(lines):
    if re.match(r"^(error(\[|:)|warning:|test .*FAILED|---- .* stdout ----)", line):
        text = "\n".join(lines[max(0, i-2):i+24])
        print("::error::" + text.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D"))
PY
exit "$result"
