# Security findings — full-tree review, 2026-08-11 (second pass)

Working list for the review that followed the six-finding review recorded in
`PROGRESS.md` under "Known gaps from the 2026-08-11 security review". Those
six are closed, and **all eleven below were closed on 2026-08-12.** The
original finding text is kept verbatim under each heading; what was done about
it is added above it as **Fixed**, so the reasoning that produced each fix
stays next to the defect that motivated it.

The review itself changed no code. Findings 1, 2 and 5 were reproduced against
the tree rather than reasoned about — the reproduction is written out under
each one, so a later session can re-run it instead of re-deriving it.

**Baseline at review time**: `gofmt`, `go vet ./...`, `go test ./...` and both
cross-builds clean; `govulncheck` v1.1.4 reports no vulnerabilities.

**Baseline after the fixes (2026-08-12)**: `gofmt`, `go vet` for `linux/amd64`
and `windows/amd64`, `go test ./...` and `go test -race ./...`, all three
cross-builds, `scripts/check-banned-imports.sh`, `govulncheck` v1.6.0 (no
vulnerabilities) and `gosec` v2.28.0 (0 issues, 15 annotated exceptions) — all
clean.

## Order of work

1, 2 and 3 first — they are the ones with a remote or semi-remote reachable
consequence. 5 is a one-line fix that also repairs a filter that has never
worked, so it is cheap to take along. 6–10 are hygiene and can be one pass.

- [x] 1 — SMTP smuggling: bare `<LF>.<LF>` ends DATA (Medium)
- [x] 2 — Dashboard does not check the Host header (Medium)
- [x] 3 — `limits.spool_max_gb` does not bound disk usage (Medium)
- [x] 4 — Bounce headers concatenated from unvalidated config (Low/Medium)
- [x] 5 — `/bounces?class=…` is a guaranteed 500 (Low)
- [x] 6 — Unvalidated numeric limits silently mean "unlimited" (Low)
- [x] 7 — `service.hostname` unchecked in the `Received:` header (Low)
- [x] 8 — `ca_pin` has no length check (Low)
- [x] 9 — CI pins a Go toolchain it does not use; no gosec anywhere (Low)
- [x] 10 — Three informational items (dead dependency, dead code, timeouts)

## 1 — Medium: bare `<LF>.<LF>` ends DATA and the rest is executed

**Fixed 2026-08-12.** `readLineLimited` now reports which terminator it saw,
and `dotReader` tracks the previous body line's terminator alongside the dot
line's own — checking only the dot line would have left `<LF>.<CRLF>`
smuggling just as well, which the original finding did not spell out.

The Postfix shape was chosen over strict RFC enforcement: a device that speaks
bare LF throughout is exactly this relay's user, and refusing its end-of-data
would hang every message until the data timeout. So the message is queued and
acknowledged, and then `doData` returns false, which closes the session
instead of returning the stream to the command loop. The message is
delivered; the injection is not. A warning line names the queue IDs.

Verified live against a running relay on 2026-08-12, and against a binary
built from the pre-fix `HEAD` to prove the test can fail: the same script
queued **two** messages before the fix, the second carrying
`from: forged@evil.example to: ['mass@target.example']` in its spooled
envelope, and queues exactly one after it, with the log line
`data ended on a bare LF dot line, closing the session`. Also verified that a
bare-LF legacy device still gets its message queued, and that a conforming
CRLF client can still send two messages over one connection and QUIT cleanly.

*The original finding follows.*

`internal/listener/session.go:665` (`dotReader.Read`) via
`internal/listener/session.go:622` (`readLineLimited`).

`readLineLimited` strips `\n` and then optionally `\r`, so a bare LF is
accepted as a line terminator. `dotReader` therefore treats `\n.\n` as the
end of data, and everything after it goes back to the command loop as SMTP
commands. RFC 5321 requires `<CRLF>.<CRLF>`.

**Reproduced**: feeding `dotReader` the body
`"Subject: a\r\n\r\nbody\n.\nMAIL FROM:<x@y.de>\r\n"` yields the body
`"Subject: a\r\n\r\nbody\r\n"`, and the next `readStructuredLine` on the same
reader returns `MAIL FROM:<x@y.de>`.

The attacker needs to control the message body, not the connection — which is
exactly the position of a contact form or an ERP system on an allowlisted
host that relays through this service. It turns "controls body content" into
"controls the envelope": an arbitrary MAIL FROM and RCPT TO, bypassing
whatever the relaying application itself permits. Per-client rewriting and
rate limiting still apply to the smuggled envelope, so this is not an open
relay.

The reverse direction is sound and needs no change: `dotReader` normalises
every line to CRLF on the way into the spool, so this relay can never be the
*sending* side of a smuggling chain.

**Fix**: accept `.` as end-of-data only on a CRLF-terminated line. If legacy
devices that speak bare LF throughout must keep working, accept it but then
close the session instead of returning to the command loop — the Postfix
approach, which removes the injection without dropping those devices.

## 2 — Medium: the dashboard does not check the Host header

**Fixed 2026-08-12.** `config.IsLoopbackHostHeader` reduces a `Host` value to
a bare host — with or without a port, IPv6 literal in brackets or not — and
runs it through the same loopback test the validator uses, rather than a
second spelling of it. `web.Server.requireLoopbackHost` wraps the dashboard
mux; the loopback metrics listener got the same treatment, since the finding
noted it is readable the same way and a loopback listener has no credential to
check either. A metrics listener that binds beyond loopback is left alone: it
is reached by its real name, so requiring loopback there would refuse every
legitimate scrape.

The refusal is `421 Misdirected Request` with a message naming the remedy,
not a bare 404, because the deployment `config.Validate` points operators at —
a reverse proxy that authenticates — forwards the original `Host` by default
and would otherwise fail with nothing to go on.

Verified live: `/config` with `Host: rebind.attacker.example` returns 421 and
renders nothing, `127.0.0.1:8025`, `localhost:8025` and `[::1]` all return
200, the metrics endpoint behaves the same way, and `/api/v1/queue` is
unaffected — 401 either way, since it wants a bearer token a rebound page
cannot obtain.

*The original finding follows.*

`internal/web/http.go:22-37`.

The 2026-08-11 decision made loopback the dashboard's authentication (finding
1 of the previous review). A browser sits *inside* that boundary. With no
Host allowlist, a page the operator visits can rebind a name it controls to
127.0.0.1 and then talk to the dashboard same-origin.

**Reproduced**: `GET /config` with `Host: rebind.attacker.example` returns 200
and the full page.

What that yields: `/queue`, `/search` and `/config` are readable (senders,
recipients, subjects, client names, `oauth2.tenant_id`, `oauth2.client_id`,
`oauth2.mailbox`, `credentials.username` — secrets stay redacted), the CSRF
token can be lifted out of `/messages/{id}`, and requeue/delete can then be
driven. `/api/v1/*` is unaffected: it wants a bearer token. The loopback
metrics endpoint is readable the same way.

**Fix**: one middleware beside `securityHeaders` that rejects any request
whose `Host` is not `127.0.0.1`, `[::1]` or `localhost`, with or without the
configured port.

## 3 — Medium: `limits.spool_max_gb` does not bound disk usage

**Fixed 2026-08-12**, both halves, after the schema decision the finding asked
for. Counting alone would have made a full `spool/failed` a relay that
permanently refuses new mail; sweeping alone would have left the quota lying
between sweeps.

`Spool` gained a `failedIndex` mirroring `spool/failed` — a separate map from
`index`, because nothing may ever claim, lease or deliver these — populated at
startup by `indexFailed`, on failure by `Fail`, and cleared by `Requeue`,
`Discard` and the sweep. `spoolSize` sums both. The recorded size is the
files' own size rather than `Envelope.Size`, since what the quota protects is
what the filesystem holds, and the two differ by the per-copy `Received`
header. The failure timestamp is the metadata file's mtime, which `Fail` sets
by writing the file immediately before the rename — so it needs no new
persisted field and is already correct for messages that failed under an
earlier version.

New key `queue.failed_retention_hours`, default 168 (7 days); 0 keeps failed
messages forever, which is the old behaviour, now chosen rather than
inherited. `Spool.SweepFailed` is called from the delivery dispatch loop,
throttled to once an hour — that loop is the only thing already ticking over
the spool's lifecycle, so it needs no goroutine of its own. Only the spool
copy goes: the history row, every attempt and the verbatim SMTP response
survive under `history.retention_days`, so the bounce view still shows what
failed and why; what is lost is the ability to requeue it.

`SetQuota` no longer turns a negative or overflowing `spool_max_gb` into no
quota at all (see finding 6 for the validation that now rejects both).

Verified live on 2026-08-12: a two-week-old failed message of 300589 bytes was
planted in `spool/failed`, and the relay logged
`failed spool retention sweep removed=1 freed_bytes=300589` on startup —
freeing exactly what was on disk, which is also what proves the size
accounting. A freshly failed message planted the same way survived the next
startup. Unit tests cover the accounting directly, which the live surface
cannot: quota held while failed, released by both `Discard` and `Requeue`,
carried across a reopen, and retention honoured in both directions.

*The original finding follows.*

`internal/spool/spool.go:610` (`spoolSize`) and `internal/spool/spool.go:445`
(`Fail`).

`spoolSize()` sums `Envelope.Size` over `s.index` only. `Fail()` deletes the
message from the index and renames both files into `spool/failed`, where they
are never counted again — so a permanently failing message frees quota while
still occupying the disk. Nothing prunes `spool/failed`: `recover()` sweeps
only `tmp` and `queue`, and `Requeue`/`Discard` are the only ways out.
`history.retention_days` covers the SQLite rows, not the spool files.

A client that produces permanent failures therefore fills the data
directory's filesystem, and the quota check never sees it.

**Fix**: count `spool/failed` towards the quota, or add an age-based sweep of
that directory. The second needs a schema decision (reuse
`queue.max_lifetime_hours` or add a setting), so ask before adding a key.

## 4 — Low/Medium: bounce headers built from unvalidated configuration

**Fixed 2026-08-12.** `Validate()` now runs `config.ValidAddress` over
`bounce.sender`, every `bounce.notify` entry and every `client.bounce.notify`
entry. `ValidAddress` accepts only printable ASCII outside the specials, so CR,
LF, NUL and space are all rejected along with anything that is not an address.
The notify lists are checked whether or not notifications are enabled, so a
typo is reported when it is written rather than when it is first used.

*The original finding follows.*

`internal/bounce/notifier.go:175-179`, `internal/config/validate.go:481-496`.

`bounce.sender` is only checked for non-emptiness; `bounce.notify[]` and
`client.bounce.notify[]` are not validated at all. All three land directly in
`From:` and `To:` lines through `fmt.Fprintf`, so a CR or LF in any of them
splits the header block. The values are operator-controlled, so this is not a
remote vector, but it is exactly the "header built by concatenation from an
unvalidated string" pattern `CLAUDE.md` bans. Outbound SMTP is already
covered — `net/smtp.Rcpt` rejects CR/LF — but the header is not.

**Fix**: `config.ValidAddress` on `bounce.sender` and on every `notify` entry
in `Validate()`.

## 5 — Low: `/bounces?class=…` is a guaranteed 500

**Fixed 2026-08-12.** The `last` subquery now selects `class`, and the filter
reads `last.class` — matching `FindBounceSummaries`, whose API path was
already correct. The final attempt's class is also the one the bounce view
displays, so the filter and the column now agree.

Two regression tests were added, the absence of which is what let this ship:
one covering each class plus the unfiltered case, one covering a message that
failed temporarily before failing permanently, which must be found under
`permanent` and not under `temporary`. Verified live as well: `/bounces`,
`/bounces?class=permanent` and `/bounces?class=expired` all return 200.

*The original finding follows.*

`internal/store/query.go:459` against the derived table at
`internal/store/query.go:413-415`.

`AND a.class = ?` references a column the subquery aliased `a` does not
select — it selects `queue_id` alone.

**Reproduced**: `FindBounces(BounceFilter{Class: "permanent"})` returns
`store: find bounces: SQL logic error: no such column: a.class (1)`. The
dashboard's failure-class filter has therefore never worked. The API path is
correct: `FindBounceSummaries` filters on `last.class`, which its own
subquery does select.

**Fix**: filter on the `last` subquery like `FindBounceSummaries` does, and
add the regression test the previous absence of one allowed.

## 6 — Low: unvalidated numeric limits silently mean "unlimited"

**Fixed 2026-08-12.** `Validate()` rejects a negative
`client.rate_limit_per_min`, `client.max_connections`,
`route.rate_limit_per_min`, `limits.spool_max_gb` and the new
`queue.failed_retention_hours`, and bounds `limits.spool_warn_percent` to
0–100. The overflow the finding mentioned is rejected too: `spool_max_gb`
above `maxSpoolGB` (1 EiB) fails startup, and `SetQuota` clamps rather than
wraps if a value ever reaches it anyway, so a configuration that slipped
through still enforces something instead of nothing.

Zero remains legal everywhere it already meant "unlimited" — that is the
documented way to say so, and the point of the fix is that it becomes the
*only* way.

*The original finding follows.*

`Validate()` rejects a negative `client.max_message_mb` and
`client.max_recipients`, but never looks at `client.rate_limit_per_min`,
`client.max_connections`, `route.rate_limit_per_min` or
`limits.spool_max_gb`.

`rateLimiter.allow` (`internal/listener/match.go:76`) and
`connCounter.acquire` (`internal/listener/match.go:110`) both treat
`limit <= 0` as unlimited, and `Spool.SetQuota`
(`internal/spool/spool.go:624`) turns a negative `spool_max_gb` — or one
large enough to overflow `int64(maxGB) * 1024³` — into no quota at all.

A mistyped minus sign disables the control instead of failing startup, which
is the "looks configured but does nothing" class the strict TOML decoding
exists to prevent.

**Fix**: reject negative values for all four in `Validate()`.

## 7 — Low: `service.hostname` is unchecked in the `Received:` header

**Fixed 2026-08-12.** `strings.ContainsAny(h, "\r\n\x00")` in `Validate()`,
immediately after the hostname defaulting so the value is checked whether it
came from the file or from `os.Hostname()`. The error names the reason rather
than the rule.

*The original finding follows.*

`internal/listener/session.go:534` and `internal/listener/session.go:129`.

Every other value interpolated into that header has been proved free of CR,
LF and NUL — the comment on `receivedHeader` says so explicitly. The
configured hostname has not, and it also goes into the 220 banner.

**Fix**: `strings.ContainsAny(h, "\r\n\x00")` in `Validate()`, next to the
existing hostname defaulting.

## 8 — Low: `ca_pin` has no length check

**Fixed 2026-08-12.** The decoded pin must be exactly `sha256.Size` bytes. The
error reports the expected and the actual character count, since the realistic
mistakes are a truncated copy-paste and a SHA-384 fingerprint pasted into a
SHA-256 field. Colon-separated pins are still accepted, as before.

*The original finding follows.*

`internal/config/validate.go:311` requires only valid hex. A truncated pin
decodes cleanly and then never matches the full-length comparison in
`internal/delivery/smarthost/client.go:255`, so the route fails closed — but
with a misleading runtime error ("no certificate in the verified chain
matches ca_pin") instead of a startup failure naming the real problem.

**Fix**: require exactly 32 decoded bytes.

## 9 — Low: CI pins a Go toolchain it does not use, and never runs gosec

**Fixed 2026-08-12.** Both workflows raised to `GO_VERSION: "1.25"`. Lowering
`go.mod` was the alternative and was rejected on evidence: `golang.org/x/sys`
v0.47.0 itself declares `go 1.25.0`, and that is the module
`internal/config/trust_windows.go` needs for the Windows DACL check — so
lowering `go.mod` would have forced a dependency downgrade in exactly the
wrong place.

`gosec` v2.28.0 now runs in CI with no excluded rule and no skipped directory.
The version matters: v2.21.4, the version current when this was written, fails
to build under Go 1.26. Bringing the tree to zero findings needed one real
simplification and fifteen annotations:

- `internal/api/auth.go` built its backoff as
  `baseBackoff * time.Duration(uint(1)<<uint(shift))`. With `shift` already
  capped at 8 and non-negative by construction, `baseBackoff << shift` says
  the same thing with no conversion for G115 to flag.
- Fifteen `#nosec` annotations, each on the line it applies to and each naming
  the property that makes it an exception: validated queue-ID paths with
  `O_NOFOLLOW`/`O_EXCL` (G304 ×7), `config.LogPath`'s lexical containment
  proof, `checkSecretFile`'s ownership and mode check, a directory needing its
  execute bit (G302), literal SQL fragments with bound values (G202 ×3), a
  redirect built from a fixed path plus a `ParseID`-validated ID (G710), a
  date layout mistaken for a credential (G101), and the recorded selftest
  exception (G402/G123).

The blanket `-exclude` was deliberately not used: an annotation at the line
fails the build when a later change breaks the property it claims, where an
excluded rule silently would not.

*The original finding follows.*

`.github/workflows/ci.yml:17` and `.github/workflows/release.yml:23` set
`GO_VERSION: "1.23"` while `go.mod` declares `go 1.25.0`. With the default
`GOTOOLCHAIN=auto` the build silently downloads whatever 1.25.x the proxy
serves, so the release binary is produced by an unpinned toolchain and the
pin in the workflow is decorative. This is the item `PROGRESS.md` already
records as "found and not fixed"; it is repeated here because it is a supply
chain property, not only a version mismatch.

Separately: `CLAUDE.md`'s definition of done requires `gosec` clean, but no
workflow runs it. Only `govulncheck` does.

**Fix**: decide whether to lower `go.mod` or raise both workflows (a decision,
not a mechanical change), and either add gosec to CI or record in the
decision log why it is not there.

## 10 — Informational

**Fixed 2026-08-12**, all three.

- `go mod tidy` removed the dead `github.com/natefinch/lumberjack/v3
  v3.0.0-alpha` and promoted `github.com/natefinch/lumberjack` and
  `golang.org/x/sys` out of the `// indirect` block, where they did not
  belong. It also added `gopkg.in/natefinch/lumberjack.v2` and
  `gopkg.in/yaml.v2` as indirect: `go mod tidy` covers the tests of imported
  packages, and lumberjack's own tests import both. Confirmed with `go list
  -deps` per GOOS that neither reaches the binary, and `make sbom` runs
  `cyclonedx-gomod app`, which is binary-scoped — so the SBOM is unaffected
  in both directions. Switching `internal/logging` to the canonical
  `gopkg.in/natefinch/lumberjack.v2` module would remove the pair outright,
  but that is a dependency swap and needs its own decision.
- The dead `sql.ErrNoRows` branch in `RecordMessage` is gone. An INSERT never
  returns it and a duplicate primary key surfaces as a UNIQUE constraint
  violation, so the branch never ran — and swallowing a real write failure
  into a nil return is the wrong direction for a journal to fail in.
- Both HTTP servers got `ReadTimeout`, `WriteTimeout` and `IdleTimeout`. The
  dashboard's write budget is the more generous of the two because a search
  across a large history renders under it; the metrics endpoint renders from
  in-memory counters and one spool index walk and is tighter.

*The original finding follows.*

- `go.mod` carries two lumberjack modules:
  `github.com/natefinch/lumberjack v2.0.0+incompatible`, which
  `internal/logging` imports, and `github.com/natefinch/lumberjack/v3
  v3.0.0-alpha`, which `go mod why` reports as "main module does not need".
  A dead alpha entry in the dependency graph is dead weight in the SBOM;
  `go mod tidy` removes it.
- `internal/store/store.go:278` maps `sql.ErrNoRows` onto "message was
  already recorded". A duplicate primary key surfaces as a UNIQUE constraint
  error, never as `ErrNoRows`, so that branch is dead. The call site ignores
  the return value anyway.
- Both HTTP servers set `ReadHeaderTimeout` but no `WriteTimeout` or
  `IdleTimeout`. Marginal for a loopback listener; worth a line if either
  ever binds wider.

## Audited and found solid — not worth re-reviewing

Recorded so a later review starts from what was already established rather
than repeating it.

- SQL is parameterised throughout. The one interpolation is the
  `messageSortColumns` allowlist lookup; LIKE patterns are bound values, so
  `%` and `_` only widen or narrow a match.
- Header rewriting replaces fields structurally through the `block` type,
  rejects control characters and a duplicate `From`, bounds
  `X-Original-From`, and quotes display names in a way that cannot escape the
  quoted string.
- `ca_pin` runs on `VerifyConnection` against `VerifiedChains`. No
  `InsecureSkipVerify` outside the pinned selftest exception.
- The token endpoint has a fixed authority, no proxy, redirects refused, a
  tenant character set that cannot traverse a path, a capped response size,
  and rejects a token carrying characters that could forge a SASL field.
- Bearer tokens are compared constant-time against every configured digest.
- `config.LogPath` splits on both separators and re-checks containment with
  `filepath.Rel`.
- Queue IDs are validated everywhere a path is built; spool writes use
  `O_NOFOLLOW` and `O_EXCL`.
- STARTTLS discards the pre-handshake buffer, so plaintext pipelined ahead of
  the handshake is never executed (CVE-2011-0411 class).
- Theme colours are validated as literal hex twice, once in `internal/config`
  and once in `web.themeOverrides`.
- Templates use `html/template` with no `template.HTML`/`JS`/`URL`
  conversions; hrefs are built from fixed paths plus `url.Values.Encode()`.
- `Secret` refuses literals, `String()` is lossy, and the config view never
  calls `Value()`.
- Prometheus label values are escaped.
- Client matching is fail-closed, with connection and session caps for an
  unmatched source.

# Security findings — targeted review, 2026-08-19

Requested as "prüfe das Projekt auf Sicherheit und eventuelle Schwachstellen
bzw Sicherheitslücken." Not a full-tree review: scoped to what changed since
the second review's fixes landed (`fa2432c`, 2026-08-12) — four sessions
covering the htmx dashboard, the Windows uninstall `purge-datadir` feature,
the lumberjack module swap and the Go toolchain pin — plus a re-check that
the eleven previously closed findings and the banned-import/pattern rules had
not regressed.

**Fixed 2026-08-19.**

## 1 — Low: `purge-datadir` does not check the data directory for a symlink or reparse point before recursing into it

`cmd/smtprelayd/verify_windows.go` (`purgeDataDir`), added in the
twenty-second session alongside the MSI's opt-in "delete
`%ProgramData%\SMTPRelayd` on uninstall" feature. The function validated the
resolved directory only by its basename
(`strings.EqualFold(filepath.Base(dir), "SMTPRelayd")`) and then called
`os.RemoveAll(dir)` directly, running as SYSTEM (`Impersonate="no"`) from a
deferred custom action with `Return="ignore"`, so a failure there is silent.
Every other function touching this same directory — `secureDataDir` in the
same file, via `config.SecureDataDir` → `config.CheckDir`, and
`verifyDataDirSecurity` via `config.CheckDataDirACL` — Lstats the path first
and refuses it if `os.ModeSymlink` is set, which on Windows `os.Lstat` sets
for NTFS junctions (mount-point reparse points) as well as true symbolic
links. `purgeDataDir` was the one place in the tree that skipped it, despite
being the one function that recurses into the directory rather than only
reading or ACLing it — exactly the case `docs/EXPLOIT-SURFACE.md` §1 has in
mind requiring the data directory "must not be a symlink," and §4's "refuse
to follow symlinks anywhere under the data directory."

Whether this was independently exploitable was not established: Go's
`os.RemoveAll` tries a direct `os.Remove` on every path before ever opening
and listing a directory's contents, and `RemoveDirectory` on a Windows
reparse point is generally understood to delete only the link, not recurse
into its target, so a planted junction at this exact path may well have been
harmless in practice. That could not be verified in this environment — no
Windows available. The fix does not depend on resolving that either way: it
reuses `config.CheckDir`, the same check `secureDataDir` already runs, so the
ambiguity is closed regardless of the underlying `RemoveAll`/
`RemoveDirectory` semantics on a reparse point.

**Fix**: call `config.CheckDir(dir)` before `os.RemoveAll(dir)`, refusing a
symlink or reparse point the same way `secureDataDir` does; a missing
directory (`os.IsNotExist`) is not an error, since purge may run against a
data directory that never existed or was already removed.

Not build-verified — no Go toolchain in this environment, and the function is
Windows-only (`//go:build windows`) with no existing test file. Reviewed by
hand against `config.CheckDir`'s existing signature and behaviour
(`internal/config/trust_windows.go`); should be exercised on real hardware (a
fresh uninstall with "Yes, delete it") before being trusted, alongside the
rest of the not-yet-hardware-verified half of this feature already tracked in
`PROGRESS.md`.

## Also checked, found solid — no regression from the second review

- `hx-get="{{.CurrentURL}}"` (new in the htmx dashboard): rendered through
  `html/template` in a plain (non-URL) attribute context, so it is
  HTML-attribute-escaped; a query string crafted to contain `"` cannot break
  out of the attribute.
- CSP tightened to `script-src 'self'`, no `unsafe-inline`/`unsafe-eval`
  introduced.
- Vendored `internal/web/static/htmx.min.js` hashes to the `sha256:e209dda5…`
  value `PROGRESS.md` already records.
- WiX sequencing for `PurgeDataDlg`/`PurgeDataDirCA`/`CLEANDATA` reasoned
  through again: never reachable under `msiexec /qn`, never reachable during
  an upgrade's nested removal (`UPGRADINGPRODUCTCODE`).
- No new occurrence of `InsecureSkipVerify`, `os/exec`, `unsafe`, or
  `template.HTML`/`.JS`/`.URL` outside the existing, already-documented and
  annotated exceptions.
- The `lumberjack` → `gopkg.in/natefinch/lumberjack.v2` swap and the
  `go1.25.13` toolchain pin are both a straight version/import change with no
  behavioural difference relevant here.
