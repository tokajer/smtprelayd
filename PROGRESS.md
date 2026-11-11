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

**Last session**: 2026-11-11 (second) — Six of the open defects closed:

- Spool I/O goes through one `os.Root` on `<data_dir>/spool`
  (`Spool.Close` is new; every test now closes its spool, because on
  Windows an open root blocks `t.TempDir` cleanup). `os.Root` follows a
  symlink inside the root even with `O_NOFOLLOW`, so reads go through
  `openRegular` (Lstat, open with `O_NONBLOCK`, `os.SameFile`).
- Spool metadata is validated on read and on write (`decodeMeta`, 1 MiB
  bound, `mailaddr.CheckEnvelope` moved out of the listener unchanged);
  `writeMeta` validates the marshalled bytes, so write and read cannot
  disagree. A parseable but invalid pair is quarantined to `spool/failed`
  all-or-nothing and logged at startup (`Spool.Quarantined`).
- Seven fuzz targets, `scripts/fuzz.sh`, a "Fuzz" step in CI and `make ci`.
- Core dumps off on Linux: `LimitCORE=0` in the unit, `RLIMIT_CORE` zeroed
  first thing in `serve` (startup error if that fails).
- `X-Original-From` and the spool-mode repair kept as they are; SECURITY.md
  reworded, decisions in `MEMORY.md` §9.
- Verified: `make ci` exit 0 on go1.27.4 (all steps incl. gosec,
  staticcheck, govulncheck, fuzz 10 s per target). The Windows test job
  was not run locally; the Root share-mode and cleanup reasoning rests on
  the Go source and needs that CI run.

**Previous session**: 2026-11-11 — Security review (repository-wide, no
HIGH/MEDIUM finding at confidence 8+). Two rewrite gaps fixed:

- `MAIL FROM:<>` no longer skips the header policy: under `force` and
  `if_unauthorized` the null reverse path stays null on the envelope but
  `From`, `X-Original-From` and `reply_to` apply (`rewrite.Apply`).
- `header_from = "keep"` no longer accepts a mailbox list whose last entry
  aligns: `addrOfMailbox` refuses lists, groups, comments, an addr-spec in
  the display-name position, trailing text, stray backslashes and
  unterminated quotes. Reviewed twice (Sonnet, then Fable 5.1); each review
  found one further bypass, both fixed and pinned by tests.
- Toolchain raised to **go1.27.4** (`go.mod`, `ci.yml`, `release.yml`,
  README components): govulncheck reported GO-2026-6859 (`net/http`
  MaxBytesReader header race) in go1.27.3. `go mod tidy` changed nothing,
  and `go version -m` lists the same modules on linux and windows. `make ci`
  is green on go1.27.4 with gosec v2.30.0 and staticcheck 2026.2.2
  unchanged; the Windows test job is still CI-only.
- Eight places where `SECURITY.md` / `EXPLOIT-SURFACE.md` promised more
  than the code did were listed under "Open defects".

**Previous session**: 2026-11-05 — Small items from the fifth review:

- `store.backfillSummaries` runs on every Open as a repair for rows with
  attempts but no `last_class` (an interrupted migration), behind a
  read-only `EXISTS` check, in one transaction with `last_class` written
  last. Its values now mirror `RecordRequeue`: requeue rows are not counted
  in `attempt_count` and do not feed `first_attempt_at` or `last_smtp_*`.
  Databases already backfilled by an earlier release are not recounted.
- Toolchain raised to **go1.27.3** (`go.mod`, `ci.yml`, `release.yml`):
  govulncheck on go1.25.13 reported 12 standard-library vulnerabilities
  fixed only in 1.26.9+. `go mod tidy` changed nothing else.
- Verified on go1.27.3 (`~/sdk/go1.27.3`, `GOTOOLCHAIN=local`): gofmt,
  `go vet`, linux and windows build, `go test -race ./...`, banned
  imports, govulncheck v1.6.0 no vulnerabilities. gosec v2.28.0 and
  v2.29.0 cannot read go1.27 export data ("export data version 5 is
  greater than maximum supported version 4") and exit 1 with 0 issues
  reported, which first surfaced in CI; `GOSEC_VERSION` is now v2.30.0
  (x/tools v0.52.0), which exits 0 with 0 issues. staticcheck 2025.1.1
  and 2026.2.1 fail the same way; `STATICCHECK_VERSION` is now 2026.2.2
  (x/tools v0.51.0), clean. Every CI step was then rerun locally on
  go1.27.3 by exit code (windows vet, selftest, build-all included);
  cyclonedx-gomod v1.10.0 and nfpm v2.47.0 also run.
- `make ci` (`scripts/ci-local.sh`) runs every step of the Linux CI jobs
  with the versions read from `ci.yml`, refuses a local toolchain other
  than `GO_VERSION`, and exits non-zero if any step failed. Run it before
  pushing a toolchain or workflow change; the Windows test job is still
  CI-only.

**Previous session**: 2026-10-08 — Fifth architectural review, top five
acted on (since committed):

- `store.FindMessageByID` reads status, `attempt_count` and `last_smtp_*`
  from the summary columns like the list queries (shared `summaryScan`), so
  detail and list agree after a requeue; `deriveStatus` is gone. API.md
  states that a requeue is not counted in `attempt_count`.
- One `insertAttemptSQL` constant for `RecordAttempt` and `RecordRequeue`.
- `web.New` takes consumer-side `web.Store`/`web.Queue` interfaces.
- New tests: smarthost AUTH over implicit TLS (535 stays `AuthError`,
  XOAUTH2 challenge decoded), `housekeeping.pass` end to end.
- Bounce digest crash durability: accepted, recorded in `MEMORY.md` §8.

Other review findings (metrics as a leaf
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

From the security review of 2026-11-11 (each needs a decision: implement,
or strike the promise and record that in `MEMORY.md`), and from the fixes
that followed it. Low practical impact.

1. EXPLOIT-SURFACE §1: on Windows `ostrust` checks only reparse point and
   file type, never the binary directory ACL; `[tls] key_file` has no
   owner/mode check on either platform.
2. EXPLOIT-SURFACE §2/§11: no explicit service DACL, no
   `SetDefaultDllDirectories`, no installer test for either.
3. EXPLOIT-SURFACE §9: Windows Error Reporting dumps are not disabled for
   the service (Linux core dumps are).
4. Pre-existing: an envelope address with invalid UTF-8 is silently changed
   by `json.Marshal` (each bad octet becomes U+FFFD), so after a restart or
   requeue it is delivered to a different address than the client gave.
   Refusing non-UTF-8 in the listener or in `validate` closes it, but
   changes what the listener accepts.
5. Pre-existing: `mailaddr.CheckEnvelope` (formerly the listener's check)
   does not restrict the local part, so `MAIL FROM:<<a@b.example>` is
   accepted as `<a@b.example>` and relayed as is.
6. `clients.max_recipients` has no upper bound, while the spool now refuses
   metadata over 1 MiB (about 4000 maximum-length recipients on one route);
   such a message gets 451 at commit. Bounding `max_recipients` is a schema
   change (`SHORTCUT:` on `maxMetaBytes`).
7. Pre-existing: `go vet -tags loadtest ./internal/store` fails
   (`load_journal_test.go:203`, `retentionCleanup` arguments); CI does not
   build the `loadtest` tag.

Closed defects and their reasoning are in `docs/dev/HISTORY.md`.

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
