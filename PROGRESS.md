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

**Last session**: 2026-09-29 — Architectural review, every finding acted
on (branch `new-features`, not yet committed). The structure is recorded in
the `MEMORY.md` §3 amendment of the same date. In short:

- `internal/mailaddr` split out of `config`; `MatchToken` moved to `httpx`.
- `delivery.Housekeeper` runs the sweeps and the quota warning apart from
  dispatch.
- OAuth2 token sources are built in `serve()`.
- `config.Normalize` is the single home of defaults.
- `metrics.Registry` is nil-safe.
- `store.Open` takes the database path.
- Constructor arguments now run in the order cfg, sp, st, reg, …, log.

Intended observable changes, all recorded in `MEMORY.md`:

- A zero or negative `data_timeout_sec` now means 300 s, not 60 s.
- The dashboard Configuration page shows normalized values.
- Selfmail journal failures are counted.
- The startup "client secret expires soon/has expired" lines are replaced by
  the `ExpiryWatcher`'s daily "expiry deadline approaching/has passed" lines.
  These are logged even without `bounce.notify`, where the watcher used to
  log a false "expiry warning sent".

Verified: gofmt, `go vet` and `go build` clean on linux and windows,
`go test -race ./...` green, banned imports and `govulncheck` clean. `gosec`
reports the same four pre-existing G104 findings as `HEAD`.

Deferred: `store.RetentionSweep` takes no context, so a shutdown during a
sweep of a very large history (about 15 s at 1M rows) waits for it. This is
pre-existing, not caused by this change, and matters only for the Windows SCM
stop timeout.

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
