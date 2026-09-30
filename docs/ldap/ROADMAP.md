# LDAP client: roadmap and tickets

Work left after steps 1–4b (merged). Each ticket is a GitHub issue written so
an agent can pick it up cold: goal, what to read first (`DESIGN.md` sections),
scope, acceptance criteria and dependencies. Read `DESIGN.md` and
`ldap/README.md` before starting any of them.

## Done

| Step | What | PR |
|---|---|---|
| 1–2 | Skeleton, errors, BER codec | #2 |
| 3 | Message model, filters, DN / attribute / entry | #3 |
| 4 | URLs, transports (TCP / TLS / Unix), connect, message I/O | #4 |
| 4b | Typed filter tree, `std::pmr` throughout, decode benchmark | #5 |

## Next

| Ticket | What | Depends on |
|---|---|---|
| #15 | `ldap::cond` error conditions (best before #6) | — |
| #6 | 5a: connection with sequential bind / search / unbind | — |
| #7 | 5b: multiplexing, cancellation, abandon | #6 |
| #8 | 6: remaining operations, typed controls, paged search, referrals | #6 |
| #9 | Typed struct mapping (descriptors, `search_as`, `modify`, `add`) | decode part: none; ops: #6, #8 |
| #10 | 7: StartTLS | #6 (#7) |
| #11 | 8: SASL bind (EXTERNAL) | #6 |
| #12 | 9: blocking facade, `ldapsearch` CLI, optional pool | #7, #8 (#11) |
| #13 | Runtime schema validation | #9, #6 |
| #14 | 10: integration tests against OpenLDAP slapd in CI | #6 → grows with #8, #10, #11 |

Suggested order: #15 → #6 → #7 and #8 (in parallel) → #9 → #10 / #11 → #12 →
#13, with #14 started right after #6 and extended as features land.

## Follow-ups

| Ticket | What |
|---|---|
| #16 | Report Corosio issues upstream (TLS verification default, CA bundles, host-check flags, resolve shutdown) |
| #17 | API polish: extensible-match builder, filter view naming, wire constructors |
| #18 | Networking: Happy Eyeballs, TLS close_notify, IPv6 and non-Linux CI |
| #19 | Decode performance: default-heap regression, message size limits |
| #20 | Clean up the legacy Asio code at the repo root |

## Definition of done (every ticket)

- GCC 13 Debug with `-DJHETZ_LDAP_SANITIZE=ON -DJHETZ_LDAP_WERROR=ON`: 0
  warnings, `UBSAN_OPTIONS=halt_on_error=1 ctest` green; network tests pass
  under `--repeat until-fail:10 -j8`.
- New parsers of untrusted input get a fuzz target, seeds and a GCC replay
  test.
- `clang-format --dry-run --Werror` clean, CI green, `DESIGN.md` updated,
  independent review done.
