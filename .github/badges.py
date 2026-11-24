"""Writes the shields.io endpoint files tests.json and coverage.json.

    python3 .github/badges.py CTEST_LOG LLVM_COV_SUMMARY_JSON OUT_DIR

CTEST_LOG is ctest's output (run_coverage.sh's), LLVM_COV_SUMMARY_JSON
`llvm-cov export -summary-only`. Prints a Markdown summary.
"""

import json
import pathlib
import re
import sys

log_path, summary_path, out_dir = sys.argv[1:4]
log = pathlib.Path(log_path).read_text(errors="replace")

# "100% tests passed out of 914" or "99% tests passed, 2 tests failed out of 914".
m = re.search(r"\d+% tests passed(?:, (\d+) tests? failed)? out of (\d+)", log)
if m:
    failed, total = int(m.group(1) or 0), int(m.group(2))
    skipped = len(re.findall(r"^\s*\d+ - .* \((?:Skipped|Disabled)\)\s*$", log, re.M))
    passed = total - failed - skipped
    message = f"{passed} passed" + (f", {failed} failed" if failed else "")
    color = "red" if failed else "brightgreen"
else:
    message, color = "no result", "lightgrey"

summary = pathlib.Path(summary_path)
if summary.exists():
    percent = json.loads(summary.read_text())["data"][0]["totals"]["lines"]["percent"]
    coverage = f"{percent:.1f}%"
    coverage_color = next(c for limit, c in [(90, "brightgreen"), (80, "green"), (70, "yellowgreen"),
                                             (60, "yellow"), (50, "orange"), (0, "red")] if percent >= limit)
else:
    coverage, coverage_color = "unknown", "lightgrey"

out = pathlib.Path(out_dir)
out.mkdir(parents=True, exist_ok=True)
for name, label, msg, col in [("tests", "tests", message, color), ("coverage", "coverage", coverage, coverage_color)]:
    (out / f"{name}.json").write_text(json.dumps({"schemaVersion": 1, "label": label, "message": msg, "color": col}) + "\n")
print(f"tests: {message}\n\nline coverage of src/ and include/: {coverage}")
