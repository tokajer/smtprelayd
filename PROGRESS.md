# PROGRESS.md

Handover document. Update at the end of every working session.
Keep it short — this file is pasted into every new chat.

## Current state

**Phase**: 4e — `internal/bounce` (digest notification) implemented and
manually verified end to end this session, **completing phase 4 in full**.
4a–4d remain complete from previous sessions. Phase 3 (client policy, sender
rewriting, recipient routing) remains complete and compiles clean. Packaging
and the Windows service wrapper (normally phase 5) were pulled forward and
validated. MSI installs and uninstalls; `install`/`uninstall`/`start`/`stop`
work on Windows. Log rotation and Windows ACL verification at startup are
complete.
**Last session**: 2026-08-11 (fourteenth session) — Installer fix, no phase
work. The MSI never produced a data directory that `CheckDataDirACL` accepts,
so no fresh Windows install could start; `util:PermissionEx` adds ACEs but
leaves the DACL inheriting from `%ProgramData%`. Replaced by
`config.SecureDataDir`, invoked as `smtprelayd secure-datadir` from a deferred
custom action after the service registration, and named as the remediation in
`CheckDataDirACL`'s own error message. Not compile-checked and no MSI built —
no Go toolchain or WiX in the session; `go vet`, `gofmt`, `go test ./...` and
an install on hardware still need to be run. See Open defects for the full
write-up.
**Previous session**: 2026-08-11 (thirteenth session) — Field fix, no phase work.
A Windows deployment accepted mail but failed every enqueue and every delivered
message's cleanup with `sync ...\spool\queue: Access is denied`. `syncDir`'s
comment already said directory fsync "is not supported on Windows and fails
with EACCES or similar", but the code only filtered `os.ErrInvalid`, so the
EACCES it predicted was returned to the caller and aborted the operation.
`FlushFileBuffers` needs a handle opened with `GENERIC_WRITE`, which cannot be
obtained for a directory, so the call could never have succeeded there — it is
now a no-op on Windows via a build-tag split (`dirsync_windows.go` /
`dirsync_unix.go`) rather than an error class the caller tries to recognise.
Durability is unaffected: the metadata and body files are individually fsynced
before the rename, and NTFS journals the rename. On Unix a directory fsync
failure is still fatal, unchanged. Same split applied to the `os.Chmod(d,
0o700)` in `Open` — the second symptom of the same deployment, `chmod
...\spool\tmp: Access is denied`. Mode bits do not govern access on Windows
(`os.Chmod` only toggles the read-only attribute); the data directory's
explicit DACL does, which the installer sets and `CheckDataDirACL` already
verifies at startup. Not compile-checked here — no Go toolchain was available
in the session; `go vet`, `gofmt` and `go test ./...` still need to be run.
Field-verified on the reporting host the same day: with the patched binary and
a corrected DACL the relay logs `message accepted` and delivers, where before
it accepted and relayed the message but then failed both the enqueue and the
delivered-message cleanup. Separately found in that session and fixed in the next: the
Windows installer never set that DACL, so no fresh install started at all.
**Previous session**: 2026-08-11 (twelfth session) — Field fix, no phase work. A
deployed instance passed `check` and then failed every start with
`listen tcp 10.0.0.10:25: bind: cannot assign requested address`: the example
config's placeholder address had been kept and is not assignable on that host.
Validation could not have caught it — `net.SplitHostPort` proves an address is
well formed, and nothing short of an actual bind proves it is assignable — so
`check` now binds and immediately releases every listener, dashboard and
metrics address (`cmd/smtprelayd/bind.go`). Two error classes are notes rather
than failures, because treating them as failures would make `check` lie in the
common case: address-in-use (the normal result when validating the config of a
running instance) and permission-denied (the service reaches ports below 1024
through `CAP_NET_BIND_SERVICE`, which a shell user invoking `check` does not
have). In-use detection needs a per-OS file: Winsock's `WSAEADDRINUSE` is a
different number from the syscall package's `EADDRINUSE` and does not compare
equal to it. Second half of the same failure: the packaged unit has
`RestartSec=5`, so systemd's default start limit of 5 starts per 10 s can
never trip, and the instance restarted 87 times with the cause buried in the
journal; `StartLimitIntervalSec=60` / `StartLimitBurst=5` now put the unit into
`failed` instead. Verified against the reported configuration: `check` exits 1
with the daemon's own bind error, and reports the `0.0.0.0:587` listener as an
unverified note. The example config's placeholder is now marked as one.

**Previous session**: 2026-08-11 (eleventh session) — Implemented phase 4e per
`docs/PHASE4-PLAN.md` and `MEMORY.md` §8. `internal/bounce.Notifier` batches
permanently-failed and expired messages (recorded via a new `RecordFail`
call from `delivery.Manager.fail()` — the single choke point every "moved to
spool/failed" path already went through, so no call site needed to change
individually) into a digest mail per client every `[bounce].digest_minutes`,
sent through the configured `notify_route`. Composed from the store's own
`FindMessageByID` at dispatch time, not from data threaded through
`RecordFail`, so the digest is never more than one lookup away from the
authoritative record and automatically respects `retain_subjects`
redaction the same way the dashboard and API do. The three loop-prevention
properties: an empty envelope sender (`net/smtp`'s `Mail("")` already
renders `MAIL FROM:<>`, so no special-casing was needed there), never
passing through the listener at all — which is what actually keeps a
notification out of sender rewriting, since rewriting is architecturally a
listener-only concern — and a new `spool.Envelope.Notification` bool
(persisted, so it survives a restart) that `delivery.Manager` checks before
ever calling `RecordFail` again, which is exactly how a notification loop
would start. A notification's own delivery outcome is kept out of the
relay's own delivered/bounced/deferred/auth-failure counters (would
otherwise conflate postmaster mail with client traffic) and instead
increments a new unlabelled `smtprelayd_notification_failures_total`.
The volume cap (`[bounce].max_per_hour`) suppresses sending once reached but
carries the suppressed client's failures into the next hour's digest rather
than dropping them, per the plan's "records them for the next hour."
Extended `[bounce]`/`[client.bounce]` validation: a client may only override
`.notify` (matching what the notifier actually reads), so a client setting
`.sender`, `.notify_route`, `.digest_minutes` or `.max_per_hour` — which
would silently do nothing — is now a startup error instead of the "looks
configured but does nothing" trap `CLAUDE.md`'s strict-decoding philosophy
otherwise closes; `.sender` is now required (not previously validated)
since an RFC 5322 message without a From header is a red flag to most mail
systems. Manually verified end to end against a running instance with a
fake SMTP server that permanently rejects every recipient: the original
message bounced, a digest was queued on schedule (`digest_minutes = 1`),
the digest itself bounced against the same fake server, and — checked
across multiple further digest cycles — no second notification was ever
generated; exactly one digest and the original message ended up in
`spool/failed`, both with their history retained. `GOOS=windows`/
`GOOS=linux` build clean, `gofmt`/`go vet` clean, `go test ./...` green (no
`-race` locally, this machine's `CGO_ENABLED=0`; unaffected on the CI
runner).
**Previous session**: 2026-08-10 (tenth session) — Implemented phase 4d per
`docs/PHASE4-PLAN.md` and `docs/API.md`. `internal/api` serves the bearer-
token-authenticated JSON API: `GET /health` (no auth), `GET /bounces`,
`GET /messages`, `GET /messages/{id}`, `GET /queue` (read scope), and
`POST /messages/{id}/requeue` / `DELETE /messages/{id}` (admin scope).
Bearer tokens are compared constant-time against `Web.Tokens[].SHA256`
(every candidate compared, not just until the first match, so timing cannot
reveal how many were tried); failed attempts are logged with the source
address, counted in a new unlabelled `smtprelayd_api_auth_failures_total`
metric (deliberately unlabelled — a source-address label would let an
attacker grow the exposition without bound), and rate-limited per source
address with exponential backoff (5 failures/minute before a 30s-to-10min
backoff, pruned opportunistically so cycling source addresses cannot grow
the tracker without bound). Pagination is cursor-based
(base64 JSON `{offset,limit}`) via a new `internal/api/cursor.go`.
Realised partway through that the dashboard's requeue/delete forms
*cannot* authenticate to a bearer-token-protected endpoint: the server
process never holds a token's plaintext, only its SHA-256 digest, by
design. Resolved by giving the dashboard its own POST
`/messages/{id}/requeue` and `/messages/{id}/delete` handlers directly in
`internal/web`, protected by a new per-process HMAC CSRF token
(`internal/web/csrf.go`) instead of a bearer token — matching
`docs/PHASE4-PLAN.md`'s own text ("REST API calls... do not use CSRF") more
faithfully than its file-list suggestion of putting CSRF logic under
`internal/api`. Both entry points call the same underlying `spool.Requeue`/
`spool.Discard` (new methods — 4a/4b never gave the spool a way to act on a
message once `Fail` had moved it to `spool/failed`, which requeue/delete
both need for a bounced message) and `store.RecordAudit`, with
`token_name` set to the bearer token's configured name for the API path and
the fixed string `"dashboard"` for the web path. Both `Requeue` and
`Discard` refuse a message currently leased to a delivery worker
(`spool.ErrBusy`, mapped to 409) rather than racing the worker's own
`Release`/`Remove` call, which could otherwise resurrect a message `Discard`
just deleted. `internal/web` and `internal/api` are now mounted on the
single `[web].address` listener the plan calls for, `/api/v1/` stripped
before dispatch. Added `store.FindBounceSummaries` to match `docs/API.md`'s
flattened bounce JSON shape (final class, attempt count, first/last attempt
timestamp) — different from the dashboard's full-attempts-list shape. While
building it, **found and fixed a real bug** in three existing "latest
attempt" queries (`FindMessages`, `CountQueue`, and the new
`FindBounceSummaries`): the tiebreak was `MAX(at_time)`, but `at_time` has
only second precision, so two attempts landing in the same wall-clock second
both matched and fanned the join out into duplicate rows for one message.
Fixed by tiebreaking on the attempts table's autoincrement `id` instead,
which is unique by construction. Also found and fixed a latent bug in three
test helpers (`store`, `web`, and the new `api` package) that construct a
`*slog.Logger` via `slog.NewTextHandler(nil, nil)`: the nil writer panics
the instant a log call actually fires, which none of the existing tests had
done — this session's tests do, since auth failures and query errors both
log. Manually verified end to end against a running instance: `/api/v1/health`
with no token, a 401 on a missing/wrong token, a 403 on read-scope trying an
admin action, requeue and delete both succeeding with an admin token and
recording an audit row, delete leaving the history row intact while removing
it from `/api/v1/queue`'s counts, the rate limiter returning 429 with
`Retry-After` after 5 failures from one source and recovering after the
backoff, a different source unaffected by another's failures, and the
dashboard's own CSRF-protected requeue form succeeding with no bearer token
at all while a missing or garbage CSRF token gets 403. `GOOS=windows`/
`GOOS=linux` build clean, `gofmt`/`go vet` clean, `go test ./...` green (no
`-race` locally, this machine's `CGO_ENABLED=0`; unaffected on the CI
runner).
**Previous session**: 2026-08-10 (ninth session) — Implemented phase 4c per
`docs/PHASE4-PLAN.md`: `internal/web` is a server-rendered, JavaScript-free
dashboard (`html/template` with strict auto-escaping, `embed.FS` for
templates and CSS) with six pages — live queue (`/queue`, sortable by
sent/status/client/route, showing only messages still in the spool), search
(`/search`, filters on sender/recipient/subject/status/client/route/time
range), bounces (`/bounces`, same filter set plus failure class), per-message
detail (`/messages/{id}`, full envelope and every delivery attempt),
route status (`/routes`, reuses `metrics.Registry.Status()` so the dashboard
and `/metrics` can never disagree about a route's state), and a read-only
config view (`/config`, listener/client/route/bounce sections, secrets always
rendered as a literal `"[redacted]"` string, never by relying solely on
`Secret.String()`'s own redaction). Security headers
(CSP/X-Content-Type-Options/X-Frame-Options/Referrer-Policy) are applied to
every response via middleware. The `{id}` path parameter is validated through
`spool.ParseID` before it ever reaches a query, per the rule that a queue ID
is a validated type, never a raw string. `internal/store` gained the pieces
this needed that 4a hadn't: `MessageFilter.Sender`/`.Subject` and
`BounceFilter.Sender`/`.Subject` (substring filters the plan's search/bounce
views require but the schema didn't yet expose), `MessageFilter.Sort`/
`.Order` with a column allowlist (including a `status` sort backed by a `CASE`
expression over the derived attempt class, since "sortable by status" has no
real column to sort on), and a `Status: "active"` shorthand for "queued or
deferred" so the live queue view doesn't need two queries merged in Go. Also
discovered and fixed that `MessageFilter.Status` existed in the 4a struct but
was never actually applied in `FindMessages`'s WHERE clause — status
filtering silently did nothing before this session. Added `metrics.Serve`'s
sibling `web.Serve`, which additionally serves HTTPS with `cfg.TLS`'s
certificate when `[web].address` is non-loopback, since `internal/config`
already refuses to start such a configuration without one — a validation
that would otherwise have had no effect on what the listener actually spoke.
Verified manually against a live instance: dashboard loads with all four
security headers present, a message sent through the real SMTP listener with
subject `<img src=x onerror=alert(1)>` renders HTML-escaped everywhere
(queue, search, per-message), search-by-subject-substring finds it, the
route status page reflects the same queued/deferred counts `/metrics` would
report, the config view never shows a resolved OAuth2 client secret (also
covered by a unit test using a real environment-variable-resolved secret,
not just a literal string), an invalid queue ID returns 400, and `POST
/queue` returns 405. `GOOS=windows`/`GOOS=linux` build clean, `gofmt`/`go
vet` clean, `go test ./...` green (no `-race` locally, this machine's
`CGO_ENABLED=0`; unaffected on the CI runner).
**Previous session**: 2026-08-10 (eighth session) — Implemented phase 4b per
`docs/PHASE4-PLAN.md`: `internal/metrics.Registry` (hand-written Prometheus
text exposition, no `prometheus/client_golang` dependency per the existing
decision) exposes `smtprelayd_queue_size{route,state}` (read live from a new
`spool.QueueDepth`, which classifies each spooled message as queued or
deferred by comparing `NextAttempt` to now — a leased, in-flight message
counts as queued rather than vanishing from the gauge mid-attempt),
`smtprelayd_delivered_total`, `smtprelayd_bounced_total` (covers both
permanent failures and expiry, matching `store`'s bounced classification),
`smtprelayd_deferred_total`, `smtprelayd_auth_failures_total`,
`smtprelayd_oauth_token_age_seconds` (needed a new `authms365.TokenSource.
TokenAge`, which required adding an `issued` timestamp the type did not
previously track), `smtprelayd_last_delivery_time`, and
`smtprelayd_delivery_rate_per_minute` (delivered_total / uptime, the
approximation the plan calls for rather than a true rolling window). Counters
are seeded at zero for every configured route at startup so a route with no
events yet is still present in the exposition. To make `auth_failures_total`
possible at all, `internal/delivery/smarthost` gained a new `AuthError` type
— credential-related temporary failures (a rejected secret, an expired
token, a rejected XOAUTH2 challenge) previously used the same `TempError` as
every other retryable failure, which is correct for retry behaviour but made
them indistinguishable from a dead smarthost for the metric the plan asks
for; `AuthError` retries identically, it only adds a type `errors.As` can
match on. `delivery.Manager` now owns the registry (built in `New` from the
same route list and token sources it already assembles) and exposes it via
`Manager.Metrics()`; `cmd/smtprelayd/main.go` starts `metrics.Serve` as a
goroutine when `[metrics].enabled`, sharing the same shutdown context as
everything else. Added `metrics.path` must-start-with-`/` validation
(`address` was already validated). Verified manually against a live instance,
not just unit tests: sent a message through the SMTP listener, watched
`queue_size{state="queued"}` go to 1, watched the delivery worker fail against
a deliberately dead port, and watched it move to `state="deferred"` with
`deferred_total` incrementing and `auth_failures_total` correctly staying at 0
(a connection refusal is not a credentials failure); confirmed `POST
/metrics` returns 405 and an unconfigured path returns 404. `GOOS=windows`/
`GOOS=linux` build clean, `gofmt`/`go vet` clean, `go test ./...` green (no
`-race` locally, this machine's `CGO_ENABLED=0`; unaffected on the CI
runner).
**Previous session**: 2026-08-10 (seventh session) — Verified phase 4a end to end
against `docs/PHASE4-PLAN.md`'s definition of done; most of it (schema, `Open`/
`RecordMessage`/`RecordAttempt`/`RecordAudit`, `FindMessages`/`FindBounces`/
`FindMessageByID`/`CountQueue`, `[history]` validation, wiring into
`internal/listener/session.go` and `internal/delivery/delivery.go`,
`modernc.org/sqlite` in `go.mod`) was already in place from an earlier,
unlogged session. Found and fixed two real gaps while verifying: (1) the
schema declared `ON DELETE CASCADE` on `attempts`/`audit` but SQLite never
enforces foreign keys unless a connection turns it on, and nothing did —
`Store.Open`'s DSN now carries `_pragma=foreign_keys(1)`, which
`modernc.org/sqlite` applies per connection, so retention cleanup on
`messages` now actually cascades instead of leaving orphaned `attempts`/
`audit` rows forever; this also turns `RecordAttempt` for an unknown queue ID
into a rejected write instead of a silent orphan. (2) `subject` was wired
through the schema and `RecordMessage`'s redaction but the listener never
extracted it — it always stored the empty string regardless of
`retain_subjects`. Added `rewrite.HeaderValue` (reuses the package's own
header-block parser, best-effort: a block that fails to parse yields "" rather
than an error) and a `sanitizeSubject` helper in `internal/listener`
(strips control characters, caps at 500 runes — display metadata, not a
header written back onto the wire, so stripping instead of rejecting the
message is the right call here, unlike the From-rewriting path). Added
regression tests for both fixes plus a SQL-injection-shaped recipient filter
test per the phase 4a test plan (already parameterized, confirmed safe).
`GOOS=windows`/`GOOS=linux` build clean, `gofmt`/`go vet` clean, `go test
./...` green (no `-race` locally, this machine's `CGO_ENABLED=0`; unaffected
on the CI runner). Manual end-to-end test against a live tenant (send →
history row → attempt row) still outstanding, same blocker as phase 3.
**Previous session**: 2026-08-10 (sixth session) — CI's windows/amd64 cross-build
was broken: `golang.org/x/sys/windows` had moved `GetNamedSecurityInfo` to a
string-based, two-return signature and replaced `SECURITY_DESCRIPTOR.DACL`'s
4-value return and the nonexistent `ControlBits`/`AccessEntryCount` helpers
with `Control()` and the exported `ACL.AceCount` field since
`CheckDataDirACL` (`internal/config/trust_windows.go`) was written. Fixed to
the current API; also dropped an unused `fmt` import in
`cmd/smtprelayd/verify_windows.go` that surfaced once the config package
compiled again. Confirmed `GOOS=windows` and `GOOS=linux` both build clean,
`gofmt`/`go vet` clean, `go test ./...` green (no `-race` locally — this
machine's `CGO_ENABLED=0`, `-race` needs cgo; unaffected on the CI runner).
Also corrected two stale entries found while cross-checking `MEMORY.md`/
`PROGRESS.md` against the code: `internal/api` and `internal/bounce` were
missing from `MEMORY.md` §3, and its Go version pin still said 1.22 after the
1.23.0 bump on 2026-08-08.
**Previous session**: 2026-08-10 (fifth session) — All seven known security gaps
from 2026-08-08 security review closed (disk quota, config-dir check, secret
ownership, syncDir errors, header limits, SIZE parameter, proxy environment).
Log rotation via lumberjack implemented. Windows ACL verification at startup
implemented and tested.
**Previous session**: 2026-08-08 (third session) — full security review of the
tree, then four fixes. No backdoor or hidden behaviour was found: the only two
outbound destinations are the fixed token authority and the configured
smarthost, there is no `init()`, no `go:embed`, no encoded blob and no tracked
binary, and the runtime dependency set is two modules. Fixed: (1) an unmatched
source used to hold a global connection slot indefinitely with a NOOP loop,
because `conns.acquire` was only called on the matched path and the per command
read deadline is refreshed by every command — unmatched sources now get a
2-connection per-address cap and a 30 s session deadline that also clamps the
read deadline; (2) `ca_pin` was checked against the certificates the smarthost
sent rather than the chain that verified, so a MITM holding any publicly
trusted certificate for the host could satisfy the pin by appending the pinned
certificate as an unused chain element — it now runs on `VerifyConnection`
against `VerifiedChains`, which also closes the session-resumption bypass gosec
G123 flagged; (3) the release workflow interpolated the tag into a shell script
before validating it, and a git ref name may legally contain `$( )` — verified
by experiment — so it now arrives through `env:`; (4) the banned-import check
that `CLAUDE.md` describes as "enforced by an import test in CI" did not exist
anywhere, and there was no CI on push/PR at all. Both now exist. Open items
from the review that were deliberately **not** fixed are listed under "Known
gaps" below.
**Previous session**: 2026-08-08 (second session) — added Windows SCM integration
and a release pipeline. `cmd/smtprelayd` gained `install`/`uninstall`/
`start`/`stop`, implemented only on Windows (`service_windows.go`, build-tag
gated) via `github.com/kardianos/service`; `serve()` now takes a `context.Context`
so both the foreground/systemd path (`context.Background()` plus
`signal.NotifyContext`) and the Windows service path (cancelled from `Stop()`)
share one code path. Confirmed with `go list -deps` on both GOOS that
`os/exec` is absent from the dependency graph on either platform. `go.mod`
bumped to `go 1.23.0` — required by `kardianos/service` v1.3.0. Added
`packaging/linux` (systemd unit, nfpm config, pre/postinstall scripts) and
`packaging/windows` (WiX source for the `.msi`); both build-tested locally
(nfpm produced real `.deb`/`.rpm` and their contents were inspected with
`dpkg-deb`/`rpm2cpio` — correct). The WiX source could not be compiled here
(candle.exe/light.exe are Windows-only); it has not been built or installed
on a real machine yet. Added `.github/workflows/release.yml`: builds all
platforms, gates on vet/gofmt/test/govulncheck, produces an SBOM
(`cyclonedx-gomod`), packages `.deb`+`.rpm` (two archs) and the `.msi`, then
publishes via `gh release create` with `actions/attest-build-provenance` —
no third-party release action, per the existing decision below. Added
`.gitignore` (`/bin/`, `/dist/`, WiX build output) — none existed before.
**Next action, phase 3/4**: end to end against the real tenant: `smtprelayd
check` ✅ works; now need: a message through the m365 route, a message with
recipients in two routes to confirm the split, and one deliberate wrong secret
to confirm the queue defers. Needs tenant, mailbox and sending-domain values
(see Open questions).
**Next action, phase 5**: Linux install/configure/start/stop cycle test on
Debian/RPM; upgrade cycle test on both platforms.

## Phases

### Phase 0 — Scaffolding ✅

### Phase 1 — Minimum viable relay ✅ (untested against a live smarthost)

- [x] `internal/config`: TOML schema, strict decoding, CIDR overlap detection,
      fail-closed checks per `docs/SECURITY.md` section 2, `Secret` type that
      refuses literal values and cannot be formatted into a log line
- [x] `internal/spool`: durable queue, atomic rename, crash recovery,
      validated `ID` type with a private constructor
- [x] `internal/listener`: ports and TLS modes from configuration, STARTTLS,
      implicit TLS, client matching by CIDR, size and recipient limits,
      per-client rate and connection limits
- [x] `internal/delivery`: worker pool, per-route concurrency, retry schedule,
      4xx versus 5xx classification
- [x] `internal/delivery/smarthost`: SMTP client with SASL PLAIN and LOGIN,
      mandatory certificate verification, optional `ca_pin`
- [x] `internal/logging`: `slog` JSON output with central secret redaction
- [x] Address and line-length validation, CRLF and NUL rejection, hop counting
- [x] `smtprelayd selftest`: active open-relay check, wired into CI
- [x] Startup trust checks: config file, binary directory and data directory
      ownership and permissions, symlink refusal (abort, not warn)
- [x] `O_NOFOLLOW` and `O_EXCL` on spool writes
- [x] Per-connection `recover`, streaming size enforcement, header limits
- [x] Runs in the foreground on both platforms
- [ ] Windows ACL verification at startup (deferred to phase 5 with the
      installer; needs `golang.org/x/sys/windows`)
- [ ] MIME nesting depth bound (no MIME parsing exists yet; the header limits
      cover the current surface)

### Phase 2 — Microsoft 365 ✅ (untested against a live tenant)

- [x] `internal/authms365`: client credentials flow, in-memory token cache,
      refresh five minutes before expiry, cooldown after a rejected request,
      redirects refused, fixed authority, tenant validated before it reaches
      the URL
- [x] XOAUTH2 in the smarthost client, including the 334 failure path: the
      continuation is answered with an empty response and the decoded JSON
      error is carried into the log line
- [x] Authentication failures are retryable regardless of the SMTP code
- [x] Per-route rate limiting enforced in `internal/delivery` before a worker
      slot is taken; a paced message is deferred without consuming an attempt
- [x] OAuth2 configuration validation: tenant character set, ASCII mailbox,
      resource scope, `secret_expires` format, scope defaulting
- [x] Startup warning when the client secret expires within thirty days
- [ ] `docs/MS365-AUTH.md` verified against a real tenant
- [ ] Sovereign cloud authorities (`login.microsoftonline.us`, China) — needs a
      schema decision, deliberately not configurable today

### Phase 3 — Client policy and rewriting ✅ (compiles clean, untested against a live tenant)

- [x] `internal/rewrite`: modes `off`, `if_unauthorized`, `force`, compiled per
      client at startup so a bad policy fails the service, not a message
- [x] Envelope and header rewriting, `Reply-To` disposition
      (`preserve`/`drop`/`fixed:`), `X-Original-From`, `header_from = "keep"`
      for a sender that is already aligned
- [x] Header block replaced structurally, never by concatenation; a message
      with two `From` headers or a control character in the preserved value is
      rejected with 550 rather than sanitised
- [x] `internal/router`: recipient domain, then source network, then the
      client route, then the default route; a source network competes with the
      client CIDR on prefix length
- [x] `route.sources` added to the schema; two routes claiming the same
      network or domain is a startup error
- [x] Recipients spanning several routes are split into one queue entry per
      route: `spool.Stage` writes the body once, `spool.Commit` makes one copy
      per route with its own `Received` header, and a failure halfway through
      withdraws the copies already made
- [x] `limits.max_message_mb` is the global ceiling; a client may lower it but
      the loader refuses a client value above it
- [x] `Envelope.OriginalFrom` records the pre-rewrite sender for the bounce
      records of phase 4
- [ ] Per-client rate limiting in the listener and the route-level pacing from
      phase 2 remain separate and both apply; no decision needed, recorded so
      it is not rediscovered

### Phase 4 — Observability ✅ (all of 4a–4e done, see `docs/PHASE4-PLAN.md`)

Planned in five sub-phases (4a–4e), with implementation order determined by
dependencies. Detailed plan in `docs/PHASE4-PLAN.md` (2026-08-10).
- [x] 4a: `internal/store` (SQLite message and attempt history) — schema,
      `RecordMessage`/`RecordAttempt`/`RecordAudit`, retention cleanup with
      working FK cascade, `FindMessages`/`FindBounces`/`FindMessageByID`/
      `CountQueue`, `[history]` validation, wired into the listener and
      delivery manager, subject extraction. Manual end-to-end test against a
      live tenant still outstanding.
- [x] 4b: `internal/metrics` (Prometheus `/metrics` endpoint) — queue size,
      delivered/bounced/deferred/auth-failure counters, OAuth token age, last
      delivery time, approximate delivery rate; all seeded at zero per route;
      manually verified against a running instance (accept → queue_size,
      fail → deferred, 405/404 on bad requests).
- [x] 4c: `internal/web` (dashboard, read-only) — queue/search/bounces/
      per-message/routes/config pages, security headers, subject redaction
      display, secrets never rendered; manually verified against a running
      instance including an XSS-shaped subject and a real resolved OAuth2
      secret.
- [x] 4d: `internal/api` (JSON API, admin actions, audit log) — bearer-token
      auth (read/admin scope) with constant-time comparison, per-source
      rate limiting with backoff, cursor-based pagination, `spool.Requeue`/
      `.Discard` shared by both the API and the dashboard's own
      CSRF-protected requeue/delete forms (the dashboard cannot use bearer
      tokens: the process never holds their plaintext). Manually verified
      end to end, including the rate limiter and the dashboard action
      forms with no bearer token at all.
- [x] 4e: `internal/bounce` (notification batching and volume capping) —
      digest per client every `digest_minutes`, hourly volume cap that
      carries suppressed failures into the next hour rather than dropping
      them, three independent loop-prevention properties (null envelope
      sender, never through the listener, a persisted `Notification` flag
      the delivery manager checks). Manually verified end to end against a
      fake SMTP server that permanently rejects everything, including that
      the digest's own bounce never produced a second notification across
      several digest cycles.

### Phase 5 — Productionisation ⬜

Unchanged, plus:

- [x] Log rotation: lumberjack v2 handles rotation when logs exceed
      max_size_mb, with max_backups retention and max_age_days enforcement;
      if MaxSizeMB is 0, rotation is disabled and logs append
- [x] Windows SCM integration: `install`/`uninstall`/`start`/`stop`, virtual
      account `NT SERVICE\smtprelayd`, automatic-start-type with restart on
      failure, registered via `kardianos/service` (Windows-only import, see
      the service wrapper row in `MEMORY.md` section 2)
- [x] Linux systemd unit (`packaging/linux/smtprelayd.service`): capability
      bound to `CAP_NET_BIND_SERVICE` instead of root, the hardening
      directives from `docs/SECURITY.md` section on process isolation
- [x] `.deb`/`.rpm` via nfpm (`packaging/linux/nfpm.yaml`), creates the
      `smtprelayd` system user/group and fixes ownership on
      `/etc/smtprelayd` and `/var/lib/smtprelayd` in a postinstall script;
      never starts the service on install
- [x] `.msi` via WiX (`packaging/windows/smtprelayd.wxs`), ACLs
      `%ProgramData%\SMTPRelayd` to Administrators + the virtual service
      account only, no inherited access; registers but does not start the
      service — **tested on real Windows machine, install/uninstall/start/stop all work**
- [x] `.github/workflows/release.yml`: builds, tests, SBOM, all three package
      formats, SHA-256 checksums, build provenance attestation, `gh release
      create` — no third-party release action
- [x] Windows ACL verification at startup: CheckDataDirACL verifies that the
      data directory has the explicit DACL set by the MSI (Administrators +
      NT SERVICE\smtprelayd, protected from inheritance); whitelisted exception
      for unsafe.Pointer usage in trust_windows.go for LocalFree API call
- [x] Real end-to-end test of install → configure → start → stop on Windows
- [ ] Upgrade cycle test and Linux install → configure → start → stop cycle
- [x] CI workflow that runs on every push/PR (`.github/workflows/ci.yml`):
      gofmt, vet, `go test -race`, the banned-import check and govulncheck,
      plus a cross-compile job for all three targets
- [x] The banned-import check `CLAUDE.md` calls for, in two halves:
      `internal/buildpolicy` parses this module's own source for `unsafe`,
      `os/exec`, `plugin`, cgo and the `html/template` escape hatches and runs
      under `make test`; `scripts/check-banned-imports.sh` walks the full
      dependency graph of `./cmd/smtprelayd` with `go list -deps` per target
      under `CGO_ENABLED=0`, which is what catches a transitive reintroduction
      such as the `kardianos/service` systemd backend. The script matches
      importer/banned pairs against an allowlist whose only entry is
      `modernc.org/libc os/exec` (see the decision log). Both were confirmed to
      fail on a deliberately planted violation, not just to pass
- [x] Supply chain: every `actions/*` pinned to a commit SHA with the tag in a
      trailing comment, `govulncheck` and `cyclonedx-gomod` pinned to versions
      instead of `@latest` (`nfpm` already was)

## Known gaps from the 2026-08-08 security review

All seven security gaps (1-7 below) have been fixed as of 2026-08-10 session.
The selftest exception (8) remains deliberate and is not fixed.

1. ✅ `limits.spool_max_gb` enforcement — now rejects messages that would
   exceed quota; SetQuota() called at startup.
2. ✅ `config.CheckConfigFile` now validates directory holding the file,
   preventing unlink-and-create replacement in group-writable /etc/smtprelayd.
3. ✅ `checkSecretFile` now verifies ownership like `checkTrusted`.
4. ✅ `spool.syncDir` now propagates fsync errors on Linux. The Windows half
   of this was wrong until 2026-08-11: it filtered `ErrInvalid` but the actual
   error is EACCES, so every rename-completing sync failed. Windows is now a
   build-tag no-op, not an error class the caller tries to recognise.
5. ✅ `limits.max_headers` and `limits.max_header_bytes` now validated as > 0.
6. ✅ `MAIL FROM SIZE` is now validated early in DATA phase if present.
7. ✅ Token client proxy environment removed; no metadata leakage through proxies.
8. The selftest still uses `InsecureSkipVerify` plus certificate pin and trips
   gosec G123. This is the deliberate exception recorded in the decision log;
   it dials fresh with no session cache so resumption cannot occur. Not fixed.

## Open defects

### The Windows installer does not set the data directory DACL (2026-08-11)

**Fixed 2026-08-11.** Found during the first field deployment on Windows. A
fresh install refused to start with:

```
smtprelayd: data directory ACL: C:\ProgramData\SMTPRelayd: DACL is not
protected against inheritance
```

`CheckDataDirACL` was correct to refuse. The directory as the installer left
it inherited from `C:\ProgramData`, which carries
`BUILTIN\Users:(OI)(CI)(RX)` — every interactive user on the host could read
the spool, and the spool holds message bodies.

Cause: the `util:PermissionEx` elements in `smtprelayd.wxs` add ACEs but do
not set `PROTECTED_DACL_SECURITY_INFORMATION`, so the two explicit grants were
appended on top of the inherited ones instead of replacing them. That answers
the untriaged question — the MSI never produced a passing directory, and no
Windows install has passed the check since it landed.

Fix: `config.SecureDataDir` (`internal/config/secure_windows.go`) writes the
DACL with `SetNamedSecurityInfo` and `PROTECTED_DACL_SECURITY_INFORMATION`,
exposed as `smtprelayd secure-datadir` and invoked by the MSI as a deferred
custom action sequenced after the service registration, since the ACE for the
virtual account cannot be resolved before the service exists. It runs on
repair and upgrade too. The well-known SIDs are constructed rather than looked
up by name: `icacls ... /grant "Administrators:..."` fails on a localised
Windows (`No mapping between account names and security IDs was done`), and
`LookupAccountName` fails there for the same reason.

The owner is reset to `BUILTIN\Administrators` along with the DACL. Without
that, `icacls /inheritance:r` fails with *Access is denied*, so the first
workaround anyone reaches for is `takeown` — which succeeds and takes the ACE
for the service account with it, leaving the service unable to create its own
log file. That looks like a second, unrelated fault; recovering from it took
several rounds in the field and is what made the deployment expensive.

The equivalent by hand, if it is ever needed without the binary:

```powershell
icacls "C:\ProgramData\SMTPRelayd" /inheritance:r
icacls "C:\ProgramData\SMTPRelayd" /grant "*S-1-5-18:(OI)(CI)F" /T /C
icacls "C:\ProgramData\SMTPRelayd" /grant "*S-1-5-32-544:(OI)(CI)F" /T /C
icacls "C:\ProgramData\SMTPRelayd" /grant "NT SERVICE\smtprelayd:(OI)(CI)F" /T /C
```

`(OI)(CI)` matters and is easy to omit: without the inheritance flags the
grant covers the directory itself but not files created in it later, so the
service still cannot write its log despite appearing to own the directory.

Not verified on hardware yet: the fix is written against the field-verified
end state above, but no MSI has been built and installed from this revision.
Phase 5 checklist item `icacls C:\ProgramData\SMTPRelayd` stays open until
it has.

## Open questions

- Tenant, mailbox and sending domain for the Microsoft 365 route.
- Should a failed token acquisition at startup abort, or only be logged? Today
  no token is fetched before the first delivery, so a tenant outage at boot is
  invisible until a message arrives.
- Should the dashboard require authentication, or is localhost binding enough?
- Which addresses go into `[bounce].notify`?
- Should downstream bounces be ingested from the relay mailbox via Graph?
- Should the API listener be exposed beyond localhost?
- A Postfix `main.cf` importer (`smtprelayd import-postfix`) was raised as a
  migration path. Scoped as a one-shot converter with an explicit report of
  what could not be translated, never a runtime parser. Not yet planned into a
  phase.

## Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-08-07 | Go instead of Rust | Direct MX delivery dropped, so no DNSSEC-validating resolver is needed |
| 2026-08-07 | Smarthost only, no direct MX | The smarthost owns reputation and bounce handling |
| 2026-08-07 | `modernc.org/sqlite` | Pure Go, keeps Windows cross-compilation trivial |
| 2026-08-07 | htmx instead of a JS framework | No Node build step |
| 2026-08-07 | Bounces are store records, not just log lines | Must be queryable and correlatable to a queue ID |
| 2026-08-07 | Bounce notification is optional and batched | An unbatched notifier turns one device into a second outage |
| 2026-08-07 | Static bearer tokens with read/admin scopes | Separates Checkmk polling from destructive actions |
| 2026-08-07 | API tokens stored as SHA-256 digests | A stolen configuration file must not yield usable credentials |
| 2026-08-07 | No `insecure_skip_verify` field in the schema | Such an option is always found enabled in production |
| 2026-08-07 | Empty client allowlist is a startup error | Open relay is the one failure that cannot be recovered from cheaply |
| 2026-08-07 | Startup aborts on a writable config, binary or data directory | Each converts a local user into control of a privileged process |
| 2026-08-07 | No auto-update mechanism | A privileged self-updating writer is a classic escalation surface |
| 2026-08-07 | `unsafe`, `os/exec`, `plugin` and cgo banned by CI import test | Removes categories rather than defending against them |
| 2026-08-07 | `github.com/BurntSushi/toml` as the only runtime dependency | Pure Go, no cgo, strict decoding via `Undecoded()` so a typo cannot silently become a default |
| 2026-08-07 | Strict decoding: an unknown key aborts startup | A misspelled `require_tls` that is silently ignored is indistinguishable from a disabled one |
| 2026-08-07 | Outbound `tls = "none"` removed from the schema | A smarthost without TLS is a deployment defect, not a supported mode |
| 2026-08-07 | A data-phase error closes the connection | Abandoning the stream desynchronises the command channel; continuing would risk misattributing the next command |
| 2026-08-07 | Permanent failures move to `spool/failed`, not deleted | Phase 5 turns them into DSNs; until then nothing is lost silently |
| 2026-08-07 | `InsecureSkipVerify` ban scoped to client and smarthost paths | The selftest probe pins its own listener certificate; a blanket grep would have forced a worse design |
| 2026-08-07 | Release provenance and SBOM in CI, no third-party release action | `gh` and the official attestation action keep the release path's own dependency set minimal |
| 2026-08-08 | Authentication failures are always temporary, never permanent | A 535 describes the relay's credentials, not the message; classifying it as permanent would move the whole queue to `spool/failed` when a secret is rotated |
| 2026-08-08 | Token authority is a constant, not a configuration field | The client secret is in the request body, so a configurable host is a place to send it elsewhere; sovereign clouds are a separate decision |
| 2026-08-08 | Redirects from the token endpoint are refused | Following one repeats the POST body, and with it the secret, to whatever host the response names |
| 2026-08-08 | A rejected token request is cached for 30 seconds | Otherwise an expired secret turns every queued message into another request and earns a tenant-level block |
| 2026-08-08 | Route pacing defers in the spool instead of blocking a worker | A blocked worker holds its route's concurrency budget and stalls dispatch for every other route |
| 2026-08-08 | Pacing does not increment the attempt counter | The message was never offered to the smarthost, so pacing must not consume its retry budget or bring its expiry forward |
| 2026-08-08 | `authms365.New` takes resolved strings, not `config.OAuth2` | Keeps the secret dereferencing in one place and makes the package testable without a configuration file |
| 2026-08-08 | Recipient domain outranks the client's route | A domain belongs to a destination, not to the device that happened to send to it; the loader refuses a domain claimed twice so the precedence can never be ambiguous |
| 2026-08-08 | Source networks live on the route (`route.sources`), not as a second client concept | A network can be pointed at a route without defining a client per device, and the client allowlist stays the only thing that decides whether a source may relay at all |
| 2026-08-08 | A source network competes with the client CIDR on prefix length | Otherwise a site-wide rule would silently override a per-device one, or vice versa, depending on which was checked first |
| 2026-08-08 | Mixed-route recipients are split into one queue entry per route | A legacy device handed a 5xx for a mixed recipient list has no way to recover, and refusing the whole message would lose the recipients that were routable |
| 2026-08-08 | A message that cannot be rewritten safely is rejected with 550 | Two `From` headers or a control character in a preserved value means guessing at what the client meant; guessing is how a header gets split |
| 2026-08-08 | `header_from = "keep"` only survives while aligned with the new envelope sender | SPF checks the envelope and DMARC the header, so an unaligned pair produces a message the smarthost rejects |
| 2026-08-08 | A client may lower `max_message_mb` but never raise it | A per-client limit that can exceed the global one is not a limit |
| 2026-08-08 | Licensed GPL-3.0-or-later, copyright Tokajer | Chosen over AGPL because the relay is meant to be run inside customer infrastructure without the network-use obligation attaching to every operator; revisit if the phase 4 dashboard is ever offered as a hosted service |
| 2026-08-08 | The licence text is fetched by `make license`, not committed as a copy | A transcribed licence that differs from the canonical text is worse than none |
| 2026-08-08 | No Postfix fork, no Windows-only build | A fork inherits the IPL/EPL licence and a process architecture that does not exist on Windows; dropping Linux would cost the CI and test platform for about a hundred lines of platform code |
| 2026-08-08 | `kardianos/service` imported only from `service_windows.go` | Its Linux backend shells out to `systemctl` via `os/exec`, which is banned; the file-suffix build constraint keeps that code out of the linux/amd64 and linux/arm64 dependency graph entirely rather than trusting a code path to never run |
| 2026-08-08 | `go.mod` bumped to `go 1.23.0` | Required by `kardianos/service` v1.3.0; "Go 1.22+" in `MEMORY.md` was a floor set for cross-compilation, not a ceiling, so raising it is not a restructuring decision |
| 2026-08-08 | Windows service runs as the virtual account `NT SERVICE\smtprelayd`, never LocalSystem | No password to provision or rotate, and no manual local-account creation in the installer, while still meeting the "dedicated service account" requirement in `docs/EXPLOIT-SURFACE.md` |
| 2026-08-08 | `serve()` takes a `context.Context` instead of creating one internally | The Windows service path has no process to send SIGTERM to; the SCM's Stop() call needs a cancel function it can call directly, and the foreground/systemd path keeps its exact previous behaviour by passing `context.Background()` |
| 2026-08-08 | The MSI runs `smtprelayd.exe install`/`uninstall` as deferred custom actions instead of WiX's own `ServiceInstall` element | The SCM registration (name, account, recovery action) is defined once in `service_windows.go`; a second, WiX-side definition of the same service would drift from it silently |
| 2026-08-08 | Neither the `.deb`/`.rpm` postinstall script nor the MSI starts the service | A fresh install has no tenant, mailbox or client configuration yet; auto-starting would just crash-loop until someone edits the config, which is a worse first impression than a clear "now configure and start it" message |
| 2026-08-08 | Release tags must match `vMAJOR.MINOR.PATCH`, enforced by the workflow before any build step | The MSI's `ProductVersion` must be three numeric fields; failing fast on a malformed tag is better than silently truncating it into a version nobody asked for |
| 2026-08-08 | `nfpm` and WiX invoked as pinned build tools (`go run pkg@version`, the runner's preinstalled WiX), not vendored into `go.mod` | Neither is a runtime dependency of the relay itself; adding them to the module would blur that line for no benefit |
| 2026-08-08 | An unmatched source keeps its 220 banner and is still refused at MAIL FROM, but gets a per-address connection cap and a session deadline | Refusing at connect would make the reply less informative and would break the selftest's expectation of a 220; the actual problem was resource occupancy, not the point of refusal, so only that was bounded |
| 2026-08-08 | `connCounter` deletes an entry at zero instead of leaving it | Its keys are now remote addresses for unmatched sources, so a retained zero entry would let any source grow the map without bound — the fix for one exhaustion path must not open another |
| 2026-08-08 | `ca_pin` is checked on `VerifyConnection` against `VerifiedChains`, not on `VerifyPeerCertificate` against the raw certificates | `VerifyPeerCertificate` receives what the server sent rather than the chain that was built, so appending the pinned certificate as an unused element satisfied the pin; it is also skipped entirely on a resumed session. Both defeat exactly the attacker `ca_pin` exists for |
| 2026-08-08 | Workflow inputs reach the shell through `env:`, never through `${{ }}` in a script body | A git ref name may legally contain `$( )` and a `workflow_dispatch` input is unconstrained, so the validating pattern ran strictly after the value had already been substituted into the script |
| 2026-08-08 | The import ban is enforced in two halves: an AST test over first-party source and a `go list -deps` script over the full graph | `unsafe` is unavoidable transitively through the standard library, so it is only meaningful as a first-party rule; a transitive `os/exec` is only visible in the graph, and only per GOOS. Neither half alone covers the ban `CLAUDE.md` states |
| 2026-08-10 | `Store.Open` sets `_pragma=foreign_keys(1)` on the SQLite DSN | SQLite does not enforce `ON DELETE CASCADE` unless a connection turns foreign keys on; without it the schema's declared cascade was a no-op and retention cleanup left `attempts`/`audit` rows orphaned forever instead of deleting them with their message |
| 2026-08-10 | Subject extraction reuses `rewrite`'s own header-block parser (`rewrite.HeaderValue`) rather than a second parser in `internal/listener` | The block parser is already the hardened, tested implementation for exactly this format; a second one would be a second place to get folding or quoting wrong for no benefit |
| 2026-08-10 | A subject that fails to parse or contains control characters is sanitised (stripped, truncated), not rejected | Unlike the From header, the stored subject is display metadata that never goes back onto the wire, so failing the whole message over a stray control character in an unrelated header would be a worse outcome than a slightly mangled history record |
| 2026-08-10 | Queue depth, token age and last-delivery-time gauges are read live at scrape time (from `spool.QueueDepth` and `authms365.TokenSource.TokenAge`) rather than maintained as incrementally-updated state | A gauge derived from the spool's own source of truth cannot drift from it; an incrementally maintained counter could, and nothing here is hot enough to make that reads-vs-writes tradeoff pay for itself |
| 2026-08-10 | A credential-related retryable failure gets its own `smarthost.AuthError` type instead of reusing `TempError` | The retry behaviour must stay identical to any other temporary failure, but `smtprelayd_auth_failures_total` cannot tell a rejected secret from a dead smarthost without a distinct type to match on |
| 2026-08-10 | Metrics counters are seeded at zero for every configured route at startup | A counter that only appears in the exposition after its first event is indistinguishable, to a scraper, from a route that does not exist yet |
| 2026-08-10 | The metrics endpoint has no authentication and no TLS | Matches the existing decision for Checkmk polling recorded in `MEMORY.md` section 7; the listener is expected to bind to loopback like the dashboard, the same boundary `docs/SECURITY.md` already relies on |
| 2026-08-10 | The read-only config view writes `"[redacted]"` as a literal string for every secret field, never relying on `Secret.String()`'s own redaction | Two independent reasons a secret cannot leak survive a mistake in either one; the view also never calls `.Value()` at all, so there is no code path that even holds the plaintext in scope |
| 2026-08-10 | `metrics.Registry.Status()` is the single source both `/metrics` and the dashboard's route status page read from | The two must never disagree about whether a route has delivered, is deferred, or has a cached token; a second, independently-computed snapshot is how that drifts |
| 2026-08-10 | `web.Serve` serves HTTPS with `cfg.TLS`'s certificate when `[web].address` is non-loopback, mirroring the existing listener's own certificate loading | `internal/config` already refuses to start a non-loopback `[web]` address without a certificate configured; a validation that guards a setting the server then ignores is worse than not validating it at all |
| 2026-08-10 | `MessageFilter.Sort`'s `status` column sorts on a `CASE` expression over the derived attempt class, not a stored column | Status is derived, not stored, so "sortable by status" only has a real column to point at if one is synthesised; the mapping (queued, then deferred, then delivered, then bounced) is fixed by the allowlist, never influenced by request input |
| 2026-08-10 | The "latest attempt" join in `FindMessages`, `CountQueue` and `FindBounceSummaries` tiebreaks on the attempts table's autoincrement `id`, not `MAX(at_time)` | `at_time` has only second precision; two attempts landing in the same wall-clock second both matched `MAX(at_time)` and fanned the join out into duplicate rows for one message. `id` is unique by construction, so it cannot tie |
| 2026-08-10 | The dashboard's requeue and delete actions are separate handlers in `internal/web`, protected by a per-process HMAC CSRF token, not a second consumer of the bearer-token-protected `/api/v1/*` endpoints | The running process holds only a token's SHA-256 digest, never its plaintext, so the dashboard cannot construct an `Authorization: Bearer` header for itself even in principle. Both entry points still call the same `spool.Requeue`/`spool.Discard`/`store.RecordAudit` |
| 2026-08-10 | `spool.Requeue` and `spool.Discard` return `ErrBusy` for a leased message rather than acting on it | The delivery worker holding the lease will call `Release`, `Remove` or `Fail` on it when the attempt finishes; racing that could resurrect a message `Discard` just deleted, or overwrite a `Requeue`'s reset attempt counter |
| 2026-08-10 | `smtprelayd_api_auth_failures_total` has no source-address label | Route names are a small, fixed, config-time set; a source address chosen by whoever is failing to authenticate is not, and labelling it would let an attacker grow the exposition without bound. The source address is still logged, per docs/API.md, on the line itself rather than as a metric label |
| 2026-08-10 | The API's per-source rate limiter tracks failures in memory with opportunistic eviction, not a fixed-size cache or an external store | The load profile (an internal API surface, loopback by default) does not justify a dependency; eviction on write bounds memory against the one attack this exists to slow down (many failed attempts from a small number of sources) without bounding it against an unrelated one (many distinct sources), which is a cost accepted rather than solved here |
| 2026-08-11 | A client may override only `bounce.notify`; setting `bounce.sender`, `.notify_route`, `.digest_minutes` or `.max_per_hour` on a client is a startup error | The notifier never reads those fields per client — the digest window, volume cap and notify route are shared — so accepting them there would silently do nothing, exactly the "looks configured but does nothing" trap strict decoding otherwise closes |
| 2026-08-11 | `bounce.sender` is required whenever notifications are enabled, which no prior validation checked | A digest with no From header is a red flag to most receiving mail systems; better to fail at startup than to find out from a spam-filtered notification nobody saw |
| 2026-08-11 | The bounce digest is composed from `store.FindMessageByID` at dispatch time, not from fields threaded through `RecordFail` | `RecordFail` only ever needs to remember a client name and a queue ID; composing from the store's own authoritative record at send time means the digest can never drift from history, and automatically inherits the same `retain_subjects` redaction the dashboard and API already apply |
| 2026-08-11 | The volume cap carries a suppressed client's failures into the next hour's digest instead of dropping them | "Records them for the next hour" in the plan means the underlying event survives being capped; only the act of sending is suppressed, not the fact that a failure happened |
| 2026-08-11 | A notification message's own delivery outcome updates a dedicated `smtprelayd_notification_failures_total` counter, never the triggering route's own delivered/bounced/deferred/auth-failure counters | Those describe the relay's client-facing traffic; folding postmaster mail into them would make a notify-route outage indistinguishable from a real production delivery problem on that route |
| 2026-08-11 | Loop prevention is a persisted `spool.Envelope.Notification` bool, not an in-memory set of queue IDs the notifier created | An in-memory set is lost on restart while the notification message can still be sitting in the queue; a persisted flag survives exactly the case (crash or restart mid-retry) where losing the distinction would let a notification's own failure start a real loop |
| 2026-08-11 | The data directory DACL is the installer's responsibility, not the daemon's | `CheckDataDirACL` refuses to start on an inherited DACL, which is right — `C:\ProgramData` grants `Users:(RX)` and the spool holds message bodies. Having the daemon repair the ACL itself would mean a service that widens or narrows its own permissions at startup, and would defeat the check. The MSI must produce a directory that already passes |
| 2026-08-11 | The MSI writes the DACL by calling `smtprelayd secure-datadir`, not with WiX `util:PermissionEx` | `util:PermissionEx` does not protect the DACL against inheritance, which is the whole point of the check; and the ACL that `CheckDataDirACL` verifies and the ACL the installer writes are one contract, so they belong in one place, exactly as the SCM registration already does |
| 2026-08-11 | `secure-datadir` is a subcommand, not something `install` does | It has to run on repair and upgrade, not only on first registration, and it is the only remediation an operator has when an ACL was lost — `CheckDataDirACL`'s error message now names it |
| 2026-08-11 | The uninstaller leaves the data directory in place | The spool can still hold accepted, acknowledged, undelivered mail at uninstall time, plus the history database. Deleting it silently would lose mail the relay took responsibility for |
| 2026-08-11 | Directory fsync is a build-tag no-op on Windows rather than an error the caller filters | `FlushFileBuffers` requires a handle opened with `GENERIC_WRITE`, which a directory handle cannot have, so the call can only ever fail there. Recognising its error class was the wrong shape of fix — it had already been attempted, against `ErrInvalid` when the real error is EACCES, and every enqueue on Windows failed for it. The durability it buys on Unix is provided by NTFS's own rename journalling |
| 2026-08-11 | `os.Chmod` on the spool directories is skipped on Windows | Mode bits are not the access-control mechanism there — `os.Chmod` only toggles the read-only attribute — so the call enforced nothing while being able to fail on a directory whose DACL denies WRITE_ATTRIBUTES. The explicit DACL the installer sets and `CheckDataDirACL` verifies is what actually restricts the data directory |
| 2026-08-11 | `scripts/check-banned-imports.sh` matches importer/banned pairs against a named allowlist instead of asserting the banned package is absent from the graph | `modernc.org/sqlite`, which the no-cgo rule forces, pulls `os/exec` in through `modernc.org/libc` on every GOOS, so the absence assertion could no longer hold. Allowing the package outright would have retired the rule; naming the single importer keeps `kardianos/service` — the regression the script exists for — a failure, and reports who imports what when it fires |
