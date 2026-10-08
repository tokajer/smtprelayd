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

**Last session**: 2026-10-08 — Fifth architectural review, top five acted
on (branch `new-features`, not yet committed):

- `store.FindMessageByID` reads status, `attempt_count` and `last_smtp_*`
  from the summary columns like the list queries (shared `summaryScan`), so
  detail and list agree after a requeue; `deriveStatus` is gone. API.md
  states that a requeue is not counted in `attempt_count`.
- One `insertAttemptSQL` constant for `RecordAttempt` and `RecordRequeue`.
- `web.New` takes consumer-side `web.Store`/`web.Queue` interfaces.
- New tests: smarthost AUTH over implicit TLS (535 stays `AuthError`,
  XOAUTH2 challenge decoded), `housekeeping.pass` end to end.
- Bounce digest crash durability: accepted, recorded in `MEMORY.md` §8.

Verified: gofmt, `go vet` and build on linux and windows, `go test -race
./...`, banned imports. gosec and govulncheck were not installed locally —
run them before merging. Deferred: `store.migrate` backfills summaries only
when a column was missing, so a migration interrupted after its ALTERs
leaves `last_class` NULL for messages with attempts (they read `queued` in
both views); a startup repair `WHERE last_class IS NULL AND EXISTS
(attempts)` would close it. Other review findings (metrics as a leaf
package, comment sweep, failed-sweep ignoring leases) are in the same
"left alone" spirit as below.

**Previous session**: 2026-09-30 — Fourth architectural review, every finding
acted on (since committed). Structure and the
observable changes are in the `MEMORY.md` §3 "third pass" amendment and the
§4 "Corrected 2026-09-30" note of the same date. In short:

- **Security fix**: the accept loop's global-cap refusal on an implicit-TLS
  listener closes without writing instead of running the TLS handshake on an
  unbounded plaintext write — a silent peer at the cap could stall the whole
  accept loop indefinitely. `session.refuse` gives every pre-session 421 the
  same `refusalTimeout`-bounded write in both directions.
- `internal/loopback` leaf holding `Host`/`HostHeader`, out of
  `internal/config`; `httpx` and `internal/metrics` call it instead.
- `internal/api/views.go`: `messageView`/`attemptView`/`bounceView` now own
  the JSON wire contract; `store.Message`, `store.Attempt` and
  `store.BounceSummary` carry no JSON tags any more.
- `delivery.Manager` replaced three parallel per-route maps with
  `map[string]*routeState` (config, compiled TLS, slots, tokens);
  `delivery.New` compiles every route's TLS config up front and now returns
  an error; `smarthost.Deliver` takes a pre-built `*tls.Config` instead of
  building its own (`smarthost.TLSConfig`, exported).
- One `selfmail.Mailer` built in `cmd/smtprelayd`'s composition root, handed
  to the bounce notifier and every canary runner; neither builds its own any
  more.
- `attempt_num` is assigned by the store, in the `INSERT` itself, for every
  row type (attempt, removal, requeue): one monotonic sequence per message,
  so numbering continues after a requeue instead of restarting at 1.
  Computing it in the `INSERT` keeps the transaction's first statement a
  write; a `SELECT` first got `SQLITE_BUSY` under concurrent writers.
- `smarthost.Deliver` refuses a TLS route handed a nil `*tls.Config`
  rather than dialling with defaults that would drop `ca_pin` and `min_tls`.
- `queueaction.Actor` counts a failed journal write into
  `metrics.Registry.JournalWriteFailure`, the way delivery and the listener
  already did.
- `delivery.Manager.fail` still reports a permanent failure through the
  bounce digest even when the move to `spool/failed` itself fails — the
  journal write already calls it permanent.
- `internal/spool`: path building, fsync-and-close and shared lease/read
  helpers were consolidated to remove duplication between `Fail`/`Discard`
  and between `Requeue`/`Discard`.
- `internal/api` and `internal/bounce` took consumer-side interfaces
  (`api.Store`, `bounce.MessageLookup`); `cmd/smtprelayd/main.go` parses
  `service.timezone` once and hands the `*time.Location` to `openLog` and
  `web.New`.

Verified 2026-10-01: gofmt, `go vet` and `go build` clean on linux and
windows, `go test -race ./...` green (uncached), banned imports clean,
gosec v2.28.0 `-severity=medium` 0 issues, govulncheck no vulnerabilities.
The implicit-TLS regression test fails against the previous `accept`.

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
- Comment volume (51 history-narrating comments) — still deferred to a
  tree-wide sweep.
- The journal-failure rule is still counted at each call site (delivery,
  listener, selfmail, queueaction) rather than by a wrapper; the fake-journal
  tests assert the count at the caller.

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
