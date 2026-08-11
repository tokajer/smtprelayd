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

| Area | Choice | Rationale |
|---|---|---|
| Language | Go 1.23.0+ | Single static binary, trivial cross-compilation, no runtime dependency on Windows; raised from 1.22 on 2026-08-08, required by `kardianos/service` v1.3.0 |
| SMTP server | `github.com/emersion/go-smtp` | Mature, hooks for auth and per-connection state |
| SMTP client | `github.com/emersion/go-smtp` client | Same message model on both sides, supports SASL |
| SASL | `github.com/emersion/go-sasl` | PLAIN, LOGIN, XOAUTH2 |
| Message parsing | `github.com/emersion/go-message` | Header rewriting without corrupting MIME |
| OAuth2 | `golang.org/x/oauth2/clientcredentials` | Standard Entra ID client credentials flow |
| Service wrapper | `github.com/kardianos/service`, Windows-only | Its systemd backend shells out to `systemctl` via `os/exec`, which section 9 bans; imported only from a `_windows.go` file so that backend is never compiled in. Linux runs under the packaged systemd unit directly, no self-registration code needed |
| Config | TOML via `github.com/BurntSushi/toml` | Comments allowed, readable for operators |
| History store | `modernc.org/sqlite` | **Pure Go**, no cgo, keeps Windows builds trivial. Its `modernc.org/libc` runtime imports `os/exec` on every GOOS for the C `system()`/`popen()` shims; the SQLite amalgamation never calls either (`system()` belongs to the sqlite3 CLI, not the library), so the code is linked but unreachable. Recorded decision, 2026-08-11: this is the **only** accepted `os/exec` importer, named explicitly in `scripts/check-banned-imports.sh` |
| Logging | stdlib `log/slog` (JSON) + `gopkg.in/natefinch/lumberjack.v2` | Structured, rotating, no external agent |
| Dashboard | Go `html/template` + htmx, embedded via `embed.FS` | No Node build step, ships inside the binary |
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

**Throttling**: Microsoft 365 permits on the order of 10 concurrent connections
and roughly 30 messages per minute per connection, with a daily recipient cap.
Per-route concurrency and rate limits must therefore be configurable, and
conservative by default.

Basic authentication for client submission is deprecated by Microsoft. XOAUTH2
is the primary path; PLAIN and LOGIN exist only for non-Microsoft smarthosts.

Alternatives considered and rejected for now: High Volume Email
(`smtp-hve.office365.com`) and IP-based connector / direct send. Both are
documented in `docs/MS365-AUTH.md` in case requirements change.

## 7. Observability

Three layers, deliberately separate:

1. **Event log** — JSON via `slog`, rotated by size and age. Every line carries
   the queue ID.
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

See `docs/API.md` for the endpoint contract.

## 9. Security posture

Security is a primary design driver, not a later hardening pass. The full
threat model and the binding requirements live in `docs/SECURITY.md`; that
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
- **Secrets never touch disk in plaintext.** Environment references or a
  restricted file only. API tokens are stored as SHA-256 digests; the plaintext
  is printed once by `smtprelayd token new` and never persisted. This supersedes
  the earlier plan of plaintext tokens expanded from environment variables.
- **Rewriting is the highest-risk code.** It writes attacker-influenced values
  into headers. CR, LF, NUL and control characters cause rejection, never
  sanitisation. Headers are built structurally, never by concatenation.
- **Least privilege by default.** Unprivileged service account on both
  platforms, capability-based binding for port 25, hardened systemd unit,
  explicit Windows ACLs, 0600 spool files verified at startup.
- **Misconfiguration is the realistic attack.** `smtprelayd selftest` actively
  verifies the service is not an open relay and runs in CI.
- **The service account is the escalation target.** Configuration file,
  executable directory and data directory ownership are verified at startup
  and abort on failure, because each of them lets an unprivileged local user
  steer a privileged process. See `docs/EXPLOIT-SURFACE.md`.
- **No dynamic behaviour.** No `unsafe`, no cgo, no `os/exec`, no plugins, no
  auto-update. Command injection and updater escalation are made structurally
  impossible rather than defended against. First-party source carries no
  exception; in the dependency graph the single accepted `os/exec` importer is
  `modernc.org/libc` (see section 4), and the CI check fails on any other.

## 10. Deployment

- Windows: installs as a service via the SCM, data under
  `%ProgramData%\SMTPRelayd`, additional logging to the Windows Event Log.
- Linux: systemd unit, data under `/var/lib/smtprelayd`, config in
  `/etc/smtprelayd`, logging to journald plus file.
- Never store state next to the binary.
- Configuration reload without restart: SIGHUP on Linux, a service control code
  or a dashboard action on Windows. Listener socket changes require a restart
  and must be reported as such.
- Packaging lives in `packaging/`: an nfpm config building `.deb`/`.rpm` with a
  postinstall script that creates the `smtprelayd` system user, and a WiX
  source building an `.msi` that registers the service by running
  `smtprelayd.exe install` as a deferred custom action rather than WiX's own
  `ServiceInstall`, so the SCM registration always matches what
  `cmd/smtprelayd/service_windows.go` configures. `.github/workflows/release.yml`
  builds and publishes all three on a `vX.Y.Z` tag. Neither package starts the
  service automatically — there is no configuration yet on a fresh install.
