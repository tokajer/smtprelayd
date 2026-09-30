# PROGRESS.md

Handover document. Update at the end of every working session.
Keep it short — this file is pasted into every new chat. Session logs,
closed defects and finished restructurings go to `docs/dev/HISTORY.md`.

## Current state

**All phases (0–5) are complete** as of 2026-09-29. The relay runs in the
live deployment: the Microsoft 365 route delivers with both `file:` and
`dpapi:` client secrets. Packaging is verified on hardware for the `.msi`,
the Burn `setup.exe`, `.rpm` and `.deb` (install, upgrade in every
combination, uninstall with and without purging the data directory).

**Last session**: 2026-09-30 — Second architectural review, findings acted
on (branch `new-features`, not yet committed). Structure and observable
changes are recorded in the `MEMORY.md` §3 amendment of the same date. In
short:

- `internal/ostrust` split out of `config` (trust checks, ACL, DPAPI).
- The TLS key pair is loaded once in `serve()`; expiry deadlines are computed
  once from the served certificate.
- `store.Class` and one class-to-status table; `RetentionSweep` takes a
  context, which closes the item deferred on 2026-09-29.
- `spool.Release` and `spool.Fail` no longer strand a message when the
  metadata write fails.
- `listener.withdraw` records the removal; `bounce.Notifier.Flush` runs at
  shutdown.
- `listener.Journal` and `selfmail.Journal` interfaces, `delivery.Manager.now`.
- `config.ClientBounce`, shared rewrite constants and `config.ParseReplyTo`.

Verified: gofmt, `go vet` and `go build` clean on linux and windows,
`go test -race ./...` green, banned imports clean. `govulncheck` and `gosec`
were not run in this session (neither is installed on the machine used).

Considered and left alone, with the reason:

- `spool.Remove` still drops the index entry before unlinking: for a delivered
  message the alternatives are an immediate redelivery or a lease that never
  clears.
- `Store` methods other than `RetentionSweep` take no context.
- `spool.Open` still derives the `spool/` layout from the data directory.
- Components still hold the whole `*config.Config`; narrow one when it is next
  touched.
- The multi-route commit failure that reaches `listener.withdraw` has a unit
  test on `withdraw` only; driving it end to end needs a spool quota finer
  than 1 GiB or a failure seam in `spool.Commit`.

**Nothing else is open.** Every remaining item is a deferred feature the operator
chose not to pursue yet, each of which would be its own phase. The scoping
for each is in `docs/dev/HISTORY.md`; grep for the quoted term.

- Token login for the dashboard, which would allow it off loopback
  ("token login")
- Ingesting downstream bounces from the relay mailbox via Graph
  ("Mail.Read")
- Sovereign cloud authorities ("Sovereign cloud")
- A MIME nesting depth bound, relevant only once MIME is parsed
  ("MIME nesting")

## Open defects

None as of 2026-09-29. Closed defects and their reasoning are in
`docs/dev/HISTORY.md`.

## Phases

| Phase | Scope | State |
|---|---|---|
| 0 | Scaffolding | ✅ |
| 1 | Minimum viable relay | ✅ |
| 2 | Microsoft 365 (XOAUTH2) | ✅ |
| 3 | Client policy, sender rewriting, recipient routing | ✅ |
| 4 | Observability: history, metrics, dashboard, API, bounce digest | ✅ |
| 5 | Productionisation: packaging, service wrappers, CI, release | ✅ |

The ticked checklists, the answered open questions and the decision log are
in `docs/dev/HISTORY.md`. A new phase gets its checklist here.
