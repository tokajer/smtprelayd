# Open security findings — full-tree review, 2026-08-11 (second pass)

Working list for the review that followed the six-finding review recorded in
`PROGRESS.md` under "Known gaps from the 2026-08-11 security review". Those
six are closed; **none of the eleven below has been touched yet.** This file
tracks them until they are; `PROGRESS.md` stays the handover document and
carries only a pointer here.

The review changed no code. Findings 1, 2 and 5 were reproduced against the
tree rather than reasoned about — the reproduction is written out under each
one, so a later session can re-run it instead of re-deriving it.

**Baseline at review time**: `gofmt`, `go vet ./...`, `go test ./...` and both
cross-builds clean; `govulncheck` v1.1.4 reports no vulnerabilities.

## Order of work

1, 2 and 3 first — they are the ones with a remote or semi-remote reachable
consequence. 5 is a one-line fix that also repairs a filter that has never
worked, so it is cheap to take along. 6–10 are hygiene and can be one pass.

- [ ] 1 — SMTP smuggling: bare `<LF>.<LF>` ends DATA (Medium)
- [ ] 2 — Dashboard does not check the Host header (Medium)
- [ ] 3 — `limits.spool_max_gb` does not bound disk usage (Medium)
- [ ] 4 — Bounce headers concatenated from unvalidated config (Low/Medium)
- [ ] 5 — `/bounces?class=…` is a guaranteed 500 (Low)
- [ ] 6 — Unvalidated numeric limits silently mean "unlimited" (Low)
- [ ] 7 — `service.hostname` unchecked in the `Received:` header (Low)
- [ ] 8 — `ca_pin` has no length check (Low)
- [ ] 9 — CI pins a Go toolchain it does not use; no gosec anywhere (Low)
- [ ] 10 — Three informational items (dead dependency, dead code, timeouts)

## 1 — Medium: bare `<LF>.<LF>` ends DATA and the rest is executed

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

`internal/listener/session.go:534` and `internal/listener/session.go:129`.

Every other value interpolated into that header has been proved free of CR,
LF and NUL — the comment on `receivedHeader` says so explicitly. The
configured hostname has not, and it also goes into the 220 banner.

**Fix**: `strings.ContainsAny(h, "\r\n\x00")` in `Validate()`, next to the
existing hostname defaulting.

## 8 — Low: `ca_pin` has no length check

`internal/config/validate.go:311` requires only valid hex. A truncated pin
decodes cleanly and then never matches the full-length comparison in
`internal/delivery/smarthost/client.go:255`, so the route fails closed — but
with a misleading runtime error ("no certificate in the verified chain
matches ca_pin") instead of a startup failure naming the real problem.

**Fix**: require exactly 32 decoded bytes.

## 9 — Low: CI pins a Go toolchain it does not use, and never runs gosec

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
