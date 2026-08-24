# MEMORY.md — Architecture Decisions

Stable document. Changes here require an explicit decision, recorded with a
date and a short rationale.

## 1. Purpose and scope

**In scope**

- Accept SMTP submissions from internal, trusted devices: printers, MFPs, ERP
  systems, monitoring, line-of-business applications.
- Queue them durably and forward them to one or more smarthosts.
- Primary smarthost is Microsoft 365 using OAuth2 client credentials (XOAUTH2).
- Per-client sender rewriting so legacy devices with arbitrary sender addresses
  are accepted by Microsoft 365.
- Operational visibility: structured logs, searchable message history, a web
  dashboard and a Prometheus-format metrics endpoint for Checkmk.

**Explicitly out of scope**

- Direct MX delivery, DANE, MTA-STS. Dropped 2026-08: everything goes through a
  smarthost, so the DNSSEC-validating resolver these would require is not
  needed. This is the decision that made Go the right language instead of Rust.
- Inbound mail from the internet, mailbox storage, IMAP/POP, webmail.
- Spam and virus filtering. The smarthost handles this.
- DKIM signing. Microsoft 365 signs outbound mail itself. Revisit only if
  direct delivery is ever reintroduced.

**Load profile**: a few thousand messages per day, i.e. roughly 0.1 msg/s on
average. Throughput is not a design driver. Durability, correct retry
behaviour and diagnosability are.

## 2. Technology decisions

**Corrected 2026-08-11.** The rows for the SMTP server and client, SASL,
message parsing and OAuth2 named `emersion/go-smtp`, `emersion/go-sasl`,
`emersion/go-message` and `golang.org/x/oauth2` — a plan from before phase 1
that was never how the code was written. None of the four has ever been in
`go.mod`; all of that is first-party. The table now describes the tree. The
runtime dependency set is three direct modules, which is the property the
security posture in section 9 actually rests on, so a table naming four
libraries that do not exist understated it in the one direction that matters.

| Area | Choice | Rationale |
|---|---|---|
| Language | Go | Single static binary, trivial cross-compilation, no runtime dependency on Windows. `go.mod` declares `go 1.25.0`, which `golang.org/x/sys` itself requires; CI and the release workflow pin the same version since 2026-08-12, so the pin describes the toolchain that actually builds |
| SMTP server | First-party, `internal/listener` | Written against the protocol directly: the command loop, size and header limits, per-client matching and the data-phase failure behaviour are all security-relevant decisions this project makes differently from a general-purpose library |
| SMTP client | First-party, `internal/delivery/smarthost`, over stdlib `net/smtp` | `net/smtp` covers the client side of the conversation; the TLS policy, `ca_pin` verification and the 4xx/5xx classification sit above it |
| SASL | First-party, `internal/delivery/smarthost` | PLAIN, LOGIN and XOAUTH2 are a few dozen lines each against `net/smtp`'s `Auth` interface, including the 334 continuation path Microsoft 365 needs |
| Message parsing | First-party header-block parser, `internal/rewrite` | Only the header block is parsed, structurally, never the MIME body — the relay rewrites `From` and reads a few values for the journal, and no MIME parsing exists at all (see the open MIME nesting-depth item) |
| OAuth2 | First-party, `internal/authms365`, over `net/http` | The client credentials flow is one form POST; a library would have added a dependency without removing the parts that actually needed care — the fixed authority, refused redirects and the cooldown after a rejected request |
| Service wrapper | `github.com/kardianos/service`, Windows-only | Its systemd backend shells out to `systemctl` via `os/exec`, which section 9 bans; imported only from a `_windows.go` file so that backend is never compiled in. Linux runs under the packaged systemd unit directly, no self-registration code needed |
| Config | TOML via `github.com/BurntSushi/toml` | Comments allowed, readable for operators |
| History store | `modernc.org/sqlite` | **Pure Go**, no cgo, keeps Windows builds trivial. Its `modernc.org/libc` runtime imports `os/exec` on every GOOS for the C `system()`/`popen()` shims; the SQLite amalgamation never calls either (`system()` belongs to the sqlite3 CLI, not the library), so the code is linked but unreachable. Recorded decision, 2026-08-11: this is the **only** accepted `os/exec` importer, named explicitly in `scripts/check-banned-imports.sh` |
| Logging | stdlib `log/slog` (JSON) + `gopkg.in/natefinch/lumberjack.v2` | Structured, rotating, no external agent. The import path settled on 2026-08-12 and the history is worth keeping straight: this row named the `gopkg.in/...v2` path while the code imported `github.com/natefinch/lumberjack v2.0.0+incompatible`, so on 2026-08-11 the row was corrected to describe the tree. The code then moved to the path the row had originally named — not a reversal but the other half of the same fix: the `gopkg.in` module is the properly versioned one with its own `go.mod`, and `+incompatible` dragged two test-only modules into the graph that nothing needed. The API is field-identical, so the change is one import line |
| Dashboard | Go `html/template` + CSS, embedded via `embed.FS`, plus vendored htmx | No Node build step, ships inside the binary. The 2026-08-07 decision was `html/template` plus htmx; phase 4c needed no client-side behaviour, so htmx was left out and the dashboard carried no JavaScript through phase 4. **Added 2026-08-18**: htmx 2.0.4, vendored as a static file (`internal/web/static/htmx.min.js`, `embed.FS`, never fetched from a CDN — a loopback-only page should not depend on an outside host), so the live queue/bounces/routes/message views poll their own URL every 10s via `hx-get`/`hx-trigger`/`hx-select`/`hx-swap="outerHTML"` and refresh in place instead of requiring a manual reload. `/search`'s results table and the filter forms on `/search` and `/bounces` are deliberately excluded from polling — swapping that region on a timer would overwrite text the operator is still typing. CSP tightened to `default-src 'self'; script-src 'self'` (was bare `default-src 'self'`) to say explicitly that scripts load only from the dashboard's own origin; htmx needs neither inline script nor eval, so no CSP relaxation beyond that was needed. Its appearance is themeable from `[web.theme]` (2026-08-11): CSS custom properties, one generated override block appended to the stylesheet, hex colours only — see `docs/dev/EXPLOIT-SURFACE.md` section 8. Light and dark come from `prefers-color-scheme` and a `data-theme` attribute, still without JavaScript |
| TLS | stdlib `crypto/tls` | No OpenSSL linkage |

## 3. Component layout

```
cmd/smtprelayd/        service wrapper, CLI (run, install, uninstall, queue)
internal/config       TOML load, validation, reload
internal/listener     ports 25 / 587 / 465, STARTTLS, SASL, client matching
internal/spool        durable on-disk queue
internal/rewrite      per-client sender rewriting
internal/router       recipient domain -> route
internal/delivery     worker pool, backoff, per-route concurrency
internal/delivery/smarthost  SMTP client, PLAIN / LOGIN / XOAUTH2
internal/authms365    Entra ID token acquisition and caching
internal/store        SQLite message and attempt history
internal/web          dashboard, server-side rendered
internal/metrics      Prometheus text exposition
internal/api          JSON API, admin actions, audit log
internal/bounce       bounce digest notification, loop prevention, volume cap
internal/fsmode       restrict files created by dependencies to 0600
internal/buildpolicy  first-party import ban, enforced as a test
```

## 4. Queue design

File-based, no database in the hot path.

- One message is two files: `<id>.env` (JSON envelope) and `<id>.eml` (raw data).
- Durability sequence: write to `tmp/`, `fsync` the file, `fsync` the directory,
  then `rename` into the target state directory. Rename is atomic on both
  Linux and Windows (NTFS) for same-volume moves.
- States are directories: `incoming/`, `active/`, `deferred/`, `failed/`.
  A state transition is a rename, which makes crash recovery trivial: anything
  found in `active/` at startup is moved back to `incoming/`.
- `failed/` is bounded, decided 2026-08-12. It counts towards
  `limits.spool_max_gb` — a permanently failed message still occupies the
  filesystem the quota exists to protect — and `queue.failed_retention_hours`
  (default 168) sweeps it by age. Only the spool copy goes; the history row,
  every attempt and the verbatim SMTP response survive under
  `history.retention_days`. Before this, nothing ever left `failed/` and the
  quota stopped counting a message the moment it went there, so a client
  producing only permanent failures filled the disk unseen.
- Queue ID: time-ordered, sortable, e.g. ULID. It is the correlation key across
  log lines, history rows and the dashboard.
- Separate queue buckets per route so one stalled smarthost cannot block others.

**Retry schedule**: 1, 5, 15, 30, 60 minutes, then every 2 hours up to a
configurable maximum lifetime (default 4 days), then a DSN bounce.
Distinguish 4xx (retry) from 5xx (fail immediately) responses.

## 5. Client model and sender rewriting

Clients are **named groups of CIDRs**, not individual IPs. Matching is
longest-prefix-wins; overlapping CIDRs are reported at config load time.

Rewrite modes:

- `off` — pass the sender through unchanged.
- `if_unauthorized` — rewrite only if the sender does not match
  `allowed_senders`. This is the recommended default: legitimate senders stay
  intact and everything else is rewritten instead of rejected.
- `force` — always rewrite.

Rules when rewriting:

- Envelope `MAIL FROM` and header `From:` are rewritten separately but must end
  up in the same domain (SPF checks the envelope, DMARC alignment the header).
- Set `Reply-To` to the original sender, but only if the message does not
  already carry one.
- Preserve the original in `X-Original-From` for diagnostics.
- Rewriting invalidates any pre-existing DKIM signature. Acceptable because
  Microsoft 365 signs on egress.

Per client, additionally configurable: maximum message size, rate limit,
maximum recipients, whether TLS is required, and the minimum TLS version.
Legacy devices frequently support neither STARTTLS nor TLS 1.2, so plaintext
must remain possible but only from allowlisted networks.

## 6. Microsoft 365 authentication

Client credentials flow, no user interaction, no password.

- Entra ID app registration, application permission `SMTP.SendAsApp`
  (Office 365 Exchange Online), admin consent granted.
- The service principal must be registered in Exchange Online
  (`New-ServicePrincipal`) and granted mailbox access
  (`Add-MailboxPermission`).
- Token endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`,
  scope `https://outlook.office365.com/.default`.
- Delivery to `smtp.office365.com:587`, STARTTLS, SASL `XOAUTH2`.
- SASL payload: `user=<mailbox>\x01auth=Bearer <token>\x01\x01`, base64 encoded.
- Cache the token in memory and refresh roughly 5 minutes before expiry. Never
  persist it to disk. Expose token age as a metric.
- **Decided 2026-08-21**: a token is also fetched eagerly for every xoauth2
  route at startup (`delivery.Manager.VerifyTokens`, called from `serve()`
  right after `delivery.New`), and a failure aborts startup rather than only
  being logged. Before this, no token was fetched before the first delivery
  attempt, so a rejected credential or an unreachable tenant at boot was
  silent until mail was already queued behind it. Accepted cost: an outage
  or rejected secret that outlasts the restart-on-failure burst window
  (Linux: `StartLimitBurst=5` within `StartLimitIntervalSec=60`) leaves the
  service down until an operator intervenes — the literal request, not a
  side effect.

**Throttling**: Microsoft 365 permits on the order of 10 concurrent connections
and roughly 30 messages per minute per connection, with a daily recipient cap.
Per-route concurrency and rate limits must therefore be configurable, and
conservative by default.

Basic authentication for client submission is deprecated by Microsoft. XOAUTH2
is the primary path; PLAIN and LOGIN exist only for non-Microsoft smarthosts.

Alternatives considered and rejected for now: High Volume Email
(`smtp-hve.office365.com`) and IP-based connector / direct send. Both are
documented in `docs/guides/MS365-AUTH.md` in case requirements change.

## 7. Observability

Three layers, deliberately separate:

1. **Event log** — JSON via `slog`, rotated by size and age. Every line carries
   the queue ID. Timestamps are process-local time by default; optional
   `service.timezone` (added 2026-08-21, IANA name or `UTC`/`Local`) converts
   them, and the same setting also converts every timestamp the dashboard
   renders (queue, message detail, search, bounces, route list) — the history
   database itself still stores and the API still reports in UTC either way,
   so only display changes, never the stored or wire value.
2. **History** — SQLite. One row per message, one row per delivery attempt
   including the verbatim SMTP response. Configurable retention, default 90
   days. This is the data source for the dashboard.

   Decided 2026-08-11: the message row is a **metadata journal**, never an
   archive. It carries the envelope, client, route, listener, remote address,
   HELO name, `Message-ID`, `Content-Type`, spooled size and header count,
   plus the most recent attempt's SMTP code and response so a list view needs
   no per-message follow-up query. The body is still deleted on delivery:
   retaining message content is a different feature with a different legal
   footprint and is out of scope until decided separately.
3. **Metrics** — `/metrics` in Prometheus text format for Checkmk: queue depth
   per state and route, deferred count, bounce count, authentication failures,
   OAuth token age, delivery rate, last successful delivery timestamp.

   Decided 2026-08-11, superseding "no authentication and no TLS": that held
   only because the listener was *expected* to bind to loopback, which nothing
   enforced. On loopback it is unchanged — open and unencrypted, what a local
   agent wants. Beyond loopback it now requires a read-scope bearer token and
   a certificate, and the loader refuses the address unless both exist.
   The dashboard got the opposite treatment for the opposite reason: it has no
   credential it could present, so a non-loopback `[web].address` is refused
   outright. See `docs/guides/SECURITY.md` section 7.

Dashboard features: live queue view, message search by sender, recipient,
subject, status and time range, per-attempt delivery history, route status,
requeue and delete actions, read-only configuration view.

## 8. Bounce handling

### Two distinct kinds of failure

**Local failures** are produced by the relay itself: the smarthost returned a
permanent 5xx response, or the message exceeded its maximum lifetime while
being deferred. The relay owns these completely — it knows the message, the
recipients, every attempt and the verbatim SMTP response.

**Remote bounces** arrive after the smarthost has already accepted the message
and then fails to deliver it downstream. Because sender rewriting points the
envelope sender at a Microsoft 365 mailbox, these bounces land in that mailbox
and never reach the relay. The relay therefore cannot show them.

Closing that gap would require polling the relay mailbox through the Graph API
and correlating the returned DSNs back to queue IDs. This is deliberately
**not implemented** — it is recorded as a possible later phase. Operators must
understand that the dashboard shows what the relay could not hand over, not
everything that ultimately failed to be delivered.

### Storage and presentation

Local failures are first-class records in the history store, not merely log
lines. Each carries the queue ID, envelope sender before and after rewriting,
recipients, subject, matched client, route, final SMTP response, attempt count
and both the first and last attempt timestamps. Retention follows the general
history retention setting.

The dashboard gets a dedicated bounce view with filtering by time range,
client, route, recipient and failure class, plus requeue and delete actions.

### Notification by mail

Optional, configurable as a global list of recipients and overridable per
client, so that a printer's failures can be routed to whoever administers the
printers rather than to a single central inbox.

Three rules that must not be skipped:

- **Loop prevention.** Notification messages are submitted with an empty
  envelope sender, are never subject to sender rewriting, and a failure to
  deliver a notification never generates another notification. It is logged and
  counted only.
- **Aggregation.** A digest window (default 15 minutes) batches failures into
  one message. A misconfigured device can fail hundreds of times, and an
  unbatched notifier turns that into a second outage.
- **Volume cap.** A maximum number of notification messages per hour, after
  which further failures are recorded and counted but not mailed.

### HTTP API

Read access to bounces, messages and queue state over JSON, authenticated with
a bearer token. This is the integration path for Checkmk and for any external
ticketing or reporting.

- Static tokens configured with environment variable expansion, never written
  to the configuration file in plain text.
- Two scopes: `read` and `admin`. Requeue and delete require `admin`.
- Constant-time token comparison. Failed attempts are logged with the source
  address and exposed as a metric.
- Cursor-based pagination, RFC 3339 timestamps throughout.
- The API and the dashboard share the same listener and the same store.

See `docs/guides/API.md` for the endpoint contract.

### Canary probe

Optional (`[canary]`, disabled unless `recipient` is set): a synthetic test
message the relay composes and enqueues itself, on a configurable interval,
through a configured route — so a working delivery path is noticed even
without real traffic, and a silently broken one (expired credential, changed
smarthost policy) does not go unnoticed just because no client happened to
send anything.

Deliberately reuses the bounce mechanism above for alerting rather than
introducing a second one: a canary failure is recorded through the same
`RecordFail` path a real client message's failure would be, so it reaches
`[bounce].notify` through the existing digest — which is also why enabling
`[canary]` requires `[bounce].notify` to be configured too, checked at load
time. What a canary does *not* share with a bounce notification is loop
prevention: a notification's own failure is deliberately never reported (that
is exactly how a notification loop would start), but a canary's failure is
the one thing this feature exists to report, so that exemption does not
apply to it. Canary traffic is kept out of its route's own delivered/bounced/
deferred/auth-failure metrics either way, with its own pair instead
(`smtprelayd_canary_last_delivery_time`, `smtprelayd_canary_failures_total`)
— see `docs/guides/CONFIGURATION.md` section 7 and `docs/guides/CHECKMK.md`.

## 9. Security posture

Security is a primary design driver, not a later hardening pass. The full
threat model and the binding requirements live in `docs/guides/SECURITY.md`; that
document is authoritative and must be read before touching the listener, the
rewriting code or the API.

The load-bearing principles:

- **Fail closed.** An unmatched source is rejected. An empty client allowlist
  on a non-loopback listener is a startup error, never an implicit allow.
  There is no default-trusted network and no localhost exemption.
- **No dangerous option exists.** Outbound certificate verification cannot be
  disabled, because such a switch always ends up enabled in production. The
  schema simply has no field for it. Dropping TLS on a route entirely is
  possible (`tls = "none"`, for legacy internal MTAs), but it is not the same
  switch: it declares an unprotected transport instead of pretending to verify
  one, it is never reached by fallback from a failed handshake, and it forces
  `auth = "none"` so no credential is ever exposed by it.
- **Secrets never touch disk in plaintext.** Environment references, a
  restricted file, or — **added 2026-08-20**, Windows only — a file encrypted
  with the machine's DPAPI key (`dpapi:<path>`, written once by
  `smtprelayd protect-secret`, decrypted by `internal/config`'s
  `resolveDPAPISecret`). `dpapi:` genuinely raises the bar over `file:`: the
  ciphertext is useless if copied off the machine. It does not, and cannot,
  defend against an attacker who already has Administrator/SYSTEM on the
  machine the service runs on — the service decrypts unattended at boot, with
  no human to prompt for a passphrase, so the decryption capability
  necessarily lives on the same box as the ciphertext. `file:` stays the only
  option on Linux; there is no first-party equivalent there. API tokens are
  stored as SHA-256 digests; the plaintext is printed once by
  `smtprelayd token new` and never persisted. This supersedes the earlier plan
  of plaintext tokens expanded from environment variables.
- **Rewriting is the highest-risk code.** It writes attacker-influenced values
  into headers. CR, LF, NUL and control characters cause rejection, never
  sanitisation. Headers are built structurally, never by concatenation.
- **Least privilege by default.** Unprivileged service account on both
  platforms, capability-based binding for port 25, hardened systemd unit,
  explicit Windows ACLs, 0600 spool files verified at startup. On Windows the
  data directory DACL is an invariant, not a default: full control for SYSTEM,
  Administrators and `NT SERVICE\smtprelayd`, inheritable, and **protected**
  against inheritance from `%ProgramData%`, whose `BUILTIN\Users:(OI)(CI)(RX)`
  would otherwise expose message bodies to every interactive account. The
  installer writes it (`config.SecureDataDir`), startup verifies it
  (`config.CheckDataDirACL`) and refuses to run otherwise. The daemon never
  repairs it itself — a service that widens its own permissions at startup
  would defeat the check.
- **Misconfiguration is the realistic attack.** `smtprelayd selftest` actively
  verifies the service is not an open relay and runs in CI.
- **The service account is the escalation target.** Configuration file,
  executable directory and data directory ownership are verified at startup
  and abort on failure, because each of them lets an unprivileged local user
  steer a privileged process. See `docs/dev/EXPLOIT-SURFACE.md`.
- **No dynamic behaviour.** No cgo, no `os/exec`, no plugins, no auto-update.
  Command injection and updater escalation are made structurally impossible
  rather than defended against. In the dependency graph the single accepted
  `os/exec` importer is `modernc.org/libc` (see section 4), and the CI check
  fails on any other. `unsafe` is banned the same way, with a narrow,
  explicitly named exception in `internal/buildpolicy`'s
  `allowedBannedImports` for hand-written Windows API bindings that have no
  safe wrapper in `golang.org/x/sys/windows`: `trust_windows.go` (ACL
  `LocalFree`) and, **added 2026-08-20**, `dpapi_windows.go`
  (`CryptProtectData`/`CryptUnprotectData`, the `dpapi:` secret above). Each
  entry is one file, named in the allowlist with its reason, so a later
  addition anywhere else in the tree still fails the build.

## 10. Deployment

- Windows: installs as a service via the SCM, data under
  `%ProgramData%\SMTPRelayd`, additional logging to the Windows Event Log.
- Linux: systemd unit, data under `/var/lib/smtprelayd`, config in
  `/etc/smtprelayd`. Logging goes to a rotated file under the data directory,
  not to journald — corrected 2026-08-12, this line claimed both and the
  packaged unit never passed `-console`. `-console` in the unit mirrors the
  full log into journald and is documented there as an option rather than
  made the default: journald rate limits and drops the excess, which would
  make the copy an operator reaches for first the incomplete one during
  exactly the mail burst worth reading about.
- **Startup failures reach the log file too, not only stderr/journald/the
  Windows Event Log** — added 2026-08-21, closing a real gap: `spool.Open`,
  `store.Open`, `listener.New`, `web.New`, `delivery.New` and the listener's
  own `Serve` all now call `log.Error` in `cmd/smtprelayd/main.go`'s `serve()`
  before returning, so any of those failing writes its reason into
  `smtprelayd.log` before the process exits.
- **A `config.Load` failure is now also written to disk**, in
  `<data_dir>/smtprelayd-error.log` — added 2026-08-21 same session, from a
  concrete report: a typo'd `service.timezone` made `run` fail with nothing
  in the log, even though `check` reported it correctly on stdout.
  `config.Load` now returns the decoded `*Config` alongside the error once
  the file itself has decoded (only a totally unparsable file or a failed
  trust check still returns nil), which is enough to know `data_dir` even
  when a later field is what actually failed validation.
  `main.logStartupFailure` uses that to write the failure, but only after
  running `checkEnvironment` itself first — `config.Load` failing is
  precisely the case where the directory has not been vetted yet, so this
  cannot assume an earlier call already did. Deliberately a fixed filename
  rather than `cfg.Log.File`: the configuration that just failed to validate
  is exactly the one value that cannot be trusted to name its own error log.
  What remains unreachable, and is structural rather than an oversight: a
  totally unparsable config file, or one that fails its own trust check
  (`CheckConfigFile`) — `data_dir` is never known in either case. Those stay
  stderr/journald/Windows-Event-Log-only.
- **On Windows, a startup failure now also stops the SCM from showing the
  service as running** — added 2026-08-21, closing the gap the two bullets
  above did not: every one of those failures was logged correctly, but
  `winProgram.Start` (`cmd/smtprelayd/service_windows.go`) returned `nil` to
  the SCM unconditionally, before `config.Load` or any other check had even
  run, so Windows kept showing "running" over a process that had already
  exited. `serve()` now takes a `ready chan<- error`, sent to exactly once —
  by an explicit call once every synchronous, fail-fast step has succeeded
  (including the SMTP listener's own socket bind, now `listener.Set.Bind`,
  split out of the old combined `Serve` so a bind conflict is caught at the
  same point), or by a deferred fallback carrying whatever error an earlier
  return produced. `winProgram.Start` blocks on it and forwards the result,
  so a bad configuration, an unopenable spool/store, a bind conflict or a
  rejected OAuth2 credential now surfaces as a real SCM start failure
  (`OnFailureRestart` fires, `services.msc`/`sc query` shows it stopped with
  an error) instead of a silently dead "running" service. The foreground and
  systemd paths pass `nil` for `ready` and are unaffected — a non-zero exit
  already is a startup failure there. **Found as a side effect, not part of
  what was asked**: the `Set`-level test the `Bind`/`Run` split needed
  exposed a genuine pre-existing data race between `Server.accept`'s
  `wg.Add` and `Set.Close`'s `wg.Wait`, present in the previous combined
  `Serve` too but never before exercised by a `-race` test at that level.
  Fixed with a `closeMu`/`closed` pair on `Server` serialising the two, per
  `sync.WaitGroup`'s own ordering requirement.
- Never store state next to the binary.
- Configuration reload without restart: SIGHUP on Linux, a service control code
  or a dashboard action on Windows. Listener socket changes require a restart
  and must be reported as such.
- Packaging lives in `packaging/`: an nfpm config building `.deb`/`.rpm` with a
  postinstall script that creates the `smtprelayd` system user, and a WiX
  source building an `.msi` that registers the service by running
  `smtprelayd.exe install` as a deferred custom action rather than WiX's own
  `ServiceInstall`, so the SCM registration always matches what
  `cmd/smtprelayd/service_windows.go` configures. The data directory ACL is set
  the same way, by `smtprelayd.exe secure-datadir` after the service
  registration, and for the same reason: WiX's `util:PermissionEx` cannot
  protect a DACL against inheritance, and the code that writes the ACL belongs
  next to the code that verifies it. `.github/workflows/release.yml` builds and
  publishes all three on a `vX.Y.Z` tag. Neither package starts the service
  automatically — there is no configuration yet on a fresh install. The MSI
  does not remove `%ProgramData%\SMTPRelayd` on uninstall **by default**: the
  spool may still hold accepted, undelivered mail. **Added 2026-08-18**: an
  interactive uninstall now asks (`PurgeDataDlg`, a minimal hand-authored
  WiX dialog, not WixUI — nothing else in this MSI shows a wizard either)
  whether to delete it anyway; answering yes sets `CLEANDATA=1`, which gates
  a new deferred custom action, `smtprelayd.exe purge-datadir`
  (`cmd/smtprelayd/verify_windows.go`), in `InstallExecuteSequence` — same
  pattern as `secure-datadir`, including the same data-directory resolution
  (configured `data_dir` when the configuration still loads, the config
  file's own directory otherwise), plus one extra guard `secure-datadir`
  does not need: it refuses to act unless the resolved directory's last path
  element is literally `SMTPRelayd`, since this deletes recursively and runs
  unattended with no further confirmation. The dialog is conditioned on
  `REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE`, so it never appears during an
  upgrade's nested removal of the old product, and `InstallUISequence` does
  not run at all under `msiexec /qn`, so a silent or scripted uninstall never
  deletes data unless `CLEANDATA=1` is passed explicitly on the command
  line — the default stays "leave it in place."
