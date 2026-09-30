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

**Last session**: 2026-09-30 — Third architectural review, every finding
acted on (branch `new-features`, not yet committed). Structure, the
`requeued` journal class decision and the observable changes are in the
`MEMORY.md` §3 "second pass" amendment of the same date. In short:

- `internal/queueid` leaf; the store and every journal interface take
  `queueid.ID`.
- Implicit-TLS handshake deadline, admission before the handshake, 5 s bound
  on pre-handshake refusals (security fix).
- `delivery.Manager.fail` owns the journal row; shutdown is not an attempt;
  `Spool.Commit` wakes the dispatcher (debounced); a short batch ends a pass.
- `listener.Queue` interface; `withdraw` uses `Discard` and is tested end to
  end, closing the item left open in the previous session.
- `requeued` class, written under the spool lease.
- `store.CommonFilter` + `httpx.ParseCommonFilter`; `store.ValidStatus`.
- `internal/housekeeping` and `expiry.Watcher` moved out of `delivery` and
  `bounce`; configuration page rendered by reflection.

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
- `Spool` reads the wall clock directly; add a `now` field when a test first
  needs one.
- `spool.Claim`, `Notifier.Pending` and `FindAuditByQueueID` are used only by
  tests, but by tests in other packages, so they cannot move to
  `export_test.go`.
- `rewrite.Compile` still re-validates what `config.Validate` checks: defence
  in depth on the highest-risk code, deliberately.
- Comments that narrate dated history are trimmed only where a change touched
  them; a tree-wide sweep into `docs/dev/HISTORY.md` was not done.
- The status sort in `store/query.go` still spells class names in its `CASE`
  literal; binding them would mean a second argument list for `ORDER BY`.

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
