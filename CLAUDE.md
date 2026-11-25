# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:46cd31e7 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB and stay local: there is no `bd dolt push` and no `refs/dolt/data` on the git remote, `.beads/` is git-ignored, and `.beads/issues.jsonl` is not committed.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits or git pushes unless explicitly asked. Never sync, push, or commit beads data. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->


## Build & Test

Build dir `build/main`, configured from the repo root (Ninja, Debug, GCC):

```bash
cmake -B build/main -G Ninja -DCMAKE_BUILD_TYPE=Debug -DJHETZ_LDAP_SANITIZE=ON
cmake --build build/main -j
ctest --test-dir build/main -j12        # serial ctest is ~4x slower (fuzz replays); let the build finish first
# Test binaries in build/main/tests: jhetz_ldap_tests (codec), jhetz_ldap_client_tests (in-process network, `net.` prefix)

# Integration tests against a throwaway OpenLDAP slapd in Docker (Debian's 2.6.10; skipped without docker;
# run_slapd.sh alone uses a local slapd). With GSSAPI: run_kdc.sh run_openldap.sh ... --test-dir build/gssapi
tests/integration/run_openldap.sh ctest --test-dir build/main -L integration --output-on-failure

# clang-tidy 23 (.clang-tidy; build/tidy is a Clang build dir, see docs/DEVELOPMENT.md "clang-tidy"):
run-clang-tidy -p build/tidy -j6 -quiet -source-filter '.*/coro-ldap/(src|tests|examples)/.*'

# Formatting: clang-format 23, same as CI
/usr/bin/clang-format -i <files>
```

Fuzzers (`build/fuzz`, Clang, `-DJHETZ_LDAP_BUILD_FUZZERS=ON`) and coverage are described in docs/DEVELOPMENT.md.

## Architecture Overview

coro-ldap is a C++23 LDAP client library with three CMake targets (the C++ namespace is `jhetz::ldap` for all of them):

- **`jhetz::ldap_core`**: the codec, whose only dependency is ICU (UTF-8 decoding, character properties): BER, LDAP messages and controls, DN, filter, URL, schema, matching rules (RFC 4517 with LDAPprep, RFC 4518), and the entry-to-struct mapping.
- **`jhetz::ldap`**: the client: the async `ldap::connection` on Corosio/Capy coroutines, with multiplexed operations, OpenSSL TLS (ldaps://, StartTLS), ldapi://, and SASL (EXTERNAL, SCRAM-SHA-256, optional GSSAPI), using ICU for SASLprep.
- **`jhetz::ldap_ad`**: the Active Directory helpers over the client's public API (`include/jhetz/ldap/ad/`, `src/ad/`).
- **`ldap::sync::connection`** (`sync.hpp`, in `jhetz::ldap`): a blocking facade over the async connection.

Layout: `include/jhetz/ldap/` for the public headers (`net/` for the transport), `src/` for the implementation (`src/connection/` for the connection modules, `src/net/` for transport and TLS), `tests/` for all test code (`tests/unit/` for the Catch2 unit tests, `tests/net/` for in-process network tests, `tests/integration/` for slapd, `tests/fuzz/` for the fuzz targets, `tests/support/` for the server-side codec used by the tests and fuzzers (not installed), `tests/install/` and `tests/coverage/`), `examples/`, `packaging/` for the vcpkg ports and Conan recipes, and `versions/` for the vcpkg registry versions. The design notes are in `docs/DESIGN.md`.

## Conventions & Patterns

The `bd prime` memories have the details. In short:

- Don't add new macros. Use functions, templates and constexpr instead (Catch2's macros are fine).
- Text handling is full UTF-8 everywhere. Never ship an ASCII-only restriction; implement the RFC preparation instead.
- ICU is the Unicode dependency.
- Don't use `std::optional<T&>`; lookups return pointers (null means not found).
- Linux is the tested platform. Windows is CI-verified for the build and unit tests (`.github/workflows/windows.yml`: MSVC 19.52 Debug, vcpkg ICU/OpenSSL). There is no local Windows toolchain: keep `_WIN32` branches compiling, check them locally with a mingw-w64 syntax check, let Windows CI confirm, and see docs/DEVELOPMENT.md "Windows". No macOS.
- `examples/` holds bare one-action files of about 15-30 lines, with no helpers.
- Format with `/usr/bin/clang-format` (v23).
- Don't touch CI (`.github/workflows`, `gh run`) unless asked.

## Non-Interactive Shell Commands

Shell commands like `cp`, `mv` and `rm` may be aliased to interactive mode (`-i`), so an agent can hang waiting for y/n input. Always use the non-interactive forms:

```bash
cp -f source dest       # NOT: cp source dest
mv -f source dest       # NOT: mv source dest
rm -f file              # NOT: rm file
rm -rf directory        # NOT: rm -r directory
cp -rf source dest      # NOT: cp -r source dest
```

Other commands that may prompt: `scp` and `ssh` (use `-o BatchMode=yes`), `apt-get` (use `-y`), `brew` (set `HOMEBREW_NO_AUTO_UPDATE=1`).
