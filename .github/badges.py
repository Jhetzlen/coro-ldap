"""Writes a shields.io endpoint file for the README's badges.

    python3 .github/badges.py tests LABEL CTEST_LOG OUT_FILE
    python3 .github/badges.py coverage LLVM_COV_SUMMARY_JSON OUT_FILE

tests: LABEL (e.g. "linux tests") and the passed and failed counts from
ctest's output. coverage: the line coverage from `llvm-cov export
-summary-only`. Prints a Markdown line for the job summary.
"""

import json
import pathlib
import re
import sys


def tests(label, log_path):
    log = pathlib.Path(log_path).read_text(errors="replace") if pathlib.Path(log_path).exists() else ""
    # "100% tests passed out of 914" or "99% tests passed, 2 tests failed out of 914".
    m = re.search(r"\d+% tests passed(?:, (\d+) tests? failed)? out of (\d+)", log)
    if not m:
        return label, "no result", "lightgrey"
    failed, total = int(m.group(1) or 0), int(m.group(2))
    skipped = len(re.findall(r"^\s*\d+ - .* \((?:Skipped|Disabled)\)\s*$", log, re.M))
    passed = total - failed - skipped
    message = f"{passed} passed" + (f", {failed} failed" if failed else "")
    return label, message, "red" if failed else "brightgreen"


def coverage(summary_path):
    summary = pathlib.Path(summary_path)
    if not summary.exists():
        return "coverage", "unknown", "lightgrey"
    percent = json.loads(summary.read_text())["data"][0]["totals"]["lines"]["percent"]
    color = next(c for limit, c in [(90, "brightgreen"), (80, "green"), (70, "yellowgreen"), (60, "yellow"),
                                    (50, "orange"), (0, "red")] if percent >= limit)
    return "coverage", f"{percent:.1f}%", color


kind, args = sys.argv[1], sys.argv[2:]
if kind == "tests":
    label, message, color = tests(args[0], args[1])
    out = args[2]
elif kind == "coverage":
    label, message, color = coverage(args[0])
    out = args[1]
else:
    sys.exit(f"unknown badge kind {kind!r}")
path = pathlib.Path(out)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps({"schemaVersion": 1, "label": label, "message": message, "color": color}) + "\n")
print(f"{label}: {message}\n")
