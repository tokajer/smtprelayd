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
| Dashboard | Go `html/template` + CSS, embedded via `embed.FS`, plus vendored htmx | No Node build step, ships inside the binary. The 2026-08-07 decision was `html/template` plus htmx; phase 4c needed no client-side behaviour, so htmx was left out and the dashboard carried no JavaScript through phase 4. **Added 2026-08-18**: htmx 2.0.4, vendored as a static file (`internal/web/static/htmx.min.js`, `embed.FS`, never fetched from a CDN — a loopback-only page should not depend on an outside host), so the live queue/bounces/routes/message views poll their own URL every 10s via `hx-get`/`hx-trigger`/`hx-select`/`hx-swap="outerHTML"` and refresh in place instead of requiring a manual reload. `/search`'s results table and the filter forms on `/search` and `/bounces` are deliberately excluded from polling — swapping that region on a timer would overwrite text the operator is still typing. CSP tightened to `default-src 'self'; script-src 'self'` (was bare `default-src 'self'`) to say explicitly that scripts load only from the dashboard's own origin; htmx needs neither inline script nor eval, so no CSP relaxation beyond that was needed. Its appearance is themeable from `[web.theme]` (2026-08-11): CSS custom properties, one generated override block appended to the stylesheet, hex colours only — see `docs/dev/EXPLOIT-SURFACE.md` section 8. Light and dark come from `prefers-color-scheme` and a `data-theme` attribute, still without JavaScript. **Amended 2026-09-14**: the queue page's bulk selection added `internal/web/static/queue.js`, the first first-party script in the tree — see section 7 for why it could not be done server-side and what keeps the CSP unchanged |
| TLS | stdlib `crypto/tls` | No OpenSSL linkage |

## 3. Component layout

**Amended 2026-09-21.** `internal/ratelimit` is new, and is the one
restructuring so far taken out of the fifty-third session's architectural
review. The per-minute token bucket existed twice — `listener.rateLimiter`
capping a compromised internal device, `delivery.routeLimiter` pacing what one
smarthost is handed — as the same algorithm in two files, differing only in
whether the caller wanted a bool or also the wait until the refill. A
correctness fix to a bucket refill should not have to be remembered in two
places, and `internal/config`'s negative-value check already had to reason
about both conventions at once. One `Limiter` with
`Allow(key, limit, now) (wait, ok)`; the listener ignores the wait, since it
refuses the transaction rather than scheduling it. Behaviour-preserving: the
token accounting, the 451 reply and the dispatcher's `hold(meta, wait)` are
unchanged. `internal/api`'s `failLimiter` is deliberately **not** folded in —
its keys are source addresses chosen by whoever is failing to authenticate, so
it needs eviction and a ceiling on the table, which a `Limiter` has neither of
and must not grow.

The `internal/metrics` row is widened the same day for restructuring **2** of
that review: the package was described only as "Prometheus text exposition",
but its `Status()` is the read model the dashboard's route page and sidebar and
`GET /api/v1/queue` render from — which is why `internal/web` and
`internal/api` import it, and why a change to the wire format used to land in
the same file as the data three HTTP surfaces depend on. The exposition now
sits in its own `exposition.go`; nothing moved packages and nothing became
exported.

Restructurings **3** to **6** of the same review landed with them, and one is
a schema-adjacent decision worth recording here rather than only in
`PROGRESS.md`. **`spool.Envelope.Client` is now `Origin`, and its JSON tag
stays `"client"`.** The field holds three different things — a client's name
for relayed mail, a canary's own name, a notification source for a digest or
an expiry warning — and `internal/bounce` groups digest entries by it, so the
overload is load-bearing and was being re-explained at every site that set or
read it. The tag is unchanged because this is persisted metadata: a spool
directory written by an earlier binary has to stay readable, and one written
by this binary has to survive a rollback. Two tests pin that in both
directions. `config.reservedNames` **stays**: naming the field honestly does
not stop the three uses sharing one key space, which is what that guard
refuses a collision in.

Also from 3 to 6, none of which changes behaviour or any exported symbol:
`spool.Spool`'s mirror of `spool/failed` and its quota ledger are now
`failedStore` and `quotaLedger`, types with their own locks inside the same
package, so "these locks are never held nested" is a property of the call
graph rather than a comment — the only place the three meet is
`Spool.liveAndFailedBytes`, which asks each in turn; `httpx.Serve` holds the
HTTP serve-and-drain loop the dashboard and the metrics endpoint had a copy of
each; and `internal/listener`'s connection counter moved to its own
`admission.go`, which is what was left of that file's second concern once the
rate limiter went to `internal/ratelimit`.

**Corrected 2026-09-21.** The `internal/config` row said "TOML load,
validation, reload". Nothing in the tree reloads a configuration and nothing
ever has: the loaded `*Config` is handed to the listener set, the delivery
manager, the dashboard, the API and the metrics registry, each of which holds
it for the life of the process, so there is no snapshot boundary a new one
could be swapped in at. Changing the configuration means restarting the
service. The row now describes the code; adding reload later is a design
decision that starts with those consumers, not with the loader.

```
cmd/smtprelayd/        service wrapper, CLI (run, install, uninstall, queue)
internal/config       TOML load and validation
internal/listener     ports 25 / 587 / 465, STARTTLS, SASL, client matching,
                      per-client connection caps
internal/spool        durable on-disk queue, failed-message mirror, quota ledger
internal/rewrite      per-client sender rewriting, header-block parser
internal/router       recipient domain -> route
internal/ratelimit    per-minute token bucket, shared by listener and delivery
internal/delivery     worker pool, backoff, per-route concurrency
internal/delivery/smarthost  SMTP client, PLAIN / LOGIN / XOAUTH2
internal/authms365    Entra ID token acquisition and caching
internal/store        SQLite message and attempt history
internal/web          dashboard, server-side rendered
internal/metrics      in-memory counters, Status() read model,
                      Prometheus text exposition (exposition.go)
internal/api          JSON API, admin actions, audit log
internal/bounce       bounce digest notification, loop prevention, volume cap
internal/expiry       what is about to stop working: certificate, client secret
internal/selfmail     spools mail the relay composed itself (digest, warning,
                      canary), so the three cannot drift apart
internal/canary       periodic synthetic message per [[canary]] entry
internal/queueaction  requeue and delete, shared by the dashboard and the API
internal/httpx        bearer token, source address, loopback Host check,
                      HTTP serve-and-drain -- the primitives more than one of
                      the three HTTP surfaces needs
internal/logging      structured JSON logging, rotation, central redaction
internal/certgen      self-signed certificate for an internal listener
internal/selftest     active open-relay check against the running instance
internal/fsmode       restrict files created by dependencies to 0600
internal/buildpolicy  first-party import ban, enforced as a test
```

**Completed 2026-09-21.** This list had seventeen rows for twenty-five
components. The eight it left out were not new -- `expiry`, `selfmail`,
`canary`, `queueaction`, `httpx`, `logging`, `certgen` and `selftest` had all
been in the tree for sessions -- so a section called "component layout"
described two thirds of the components, which is worse than describing none:
a reader checking whether a concern already has a home could conclude it did
not, and write a second one. The order is roughly the order a message
travels.

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
- **Decided 2026-08-21, narrowed 2026-09-18**: a token is also fetched
  eagerly for every xoauth2 route at startup (`delivery.Manager.VerifyTokens`,
  called from `serve()` right after `delivery.New`). A rejection the token
  endpoint itself issued (`authms365.CredentialError`: HTTP 400 or 401 with
  an OAuth2 error code, so a wrong secret, an unknown client or tenant, a
  scope never granted) aborts startup rather than only being logged, because
  no retry changes it. Any other failure -- a timeout, a refused connection,
  a 5xx, a 429 -- is logged at Warn and the service starts: the listeners
  bind, devices hand their mail to the spool, and the token is fetched again
  at the first delivery attempt. Before 2026-09-18 every failure aborted,
  which meant a Microsoft outage at reboot time left the listeners unbound
  and the devices, which do not queue, losing mail -- a delivery outage
  turned into an acceptance outage. Accepted cost of the remaining abort: a
  rejected secret that outlasts the restart-on-failure burst window (Linux:
  `StartLimitBurst=5` within `StartLimitIntervalSec=60`) leaves the service
  down until an operator intervenes — the literal request, not a side
  effect.

- **Decided 2026-09-18**: the dispatcher claims in batches
  (`spool.ClaimBatch(now, max, skip)`, 1 000 per scan) rather than one
  message per scan of the index, and excludes routes it has already found
  saturated for the rest of the tick. One scan per message made a tick
  quadratic in queue depth, which is worst precisely when a smarthost hangs
  and the queue behind it is deepest; the load test had measured the
  one-at-a-time drain at 22 hours for a million messages. The batch is
  selected with a bounded max-heap, so the oldest mail is still what goes
  out first -- a bounded scan that kept the wrong end of a map's random
  iteration order would starve it.

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

**Queue management, added 2026-09-14** (requested after 94 messages piled up
in one installation and clearing them one message at a time was the only
option): the queue page carries a bulk form — per-row checkboxes, a select-all
box, and whole-queue variants of both actions bounded at 1000 messages per
submission. Three decisions worth keeping:

- "All" is resolved from the **history store's** active set, not from the
  spool index, because that is what the operator is looking at when they ask
  for it, and the two can legitimately disagree.
- A message the queue view lists with **no spool copy** behind it is the case
  that made this a bug report rather than a feature request. It arises without
  operator error (`Spool.recover` drops a half-written pair at startup, a
  crash lands between the unlink and the attempt row) and, before this, every
  delete of such a row answered 404, so nothing could clear it and it stayed
  listed as queued forever. `Store.ReconcileRemoved` now marks the row removed
  when — and only when — its derived status is still queued or deferred; a
  delivered or bounced row is never rewritten. The dashboard and the API both
  go through it, so "delete" means the same thing at both entry points, and
  the queue view marks such rows so requeue's refusal is not a mystery.
- The dashboard gained its **first first-party JavaScript**
  (`internal/web/static/queue.js`, queue page only), which the "no JavaScript"
  half of the row in section 2 no longer describes. A select-all box cannot be
  built server-side, and the ten-second htmx refresh would otherwise swap the
  table out from under a selection in progress — the same objection that keeps
  `/search`'s results table out of the polling set. It is event-delegated so it
  survives a swap, and uses neither `eval` nor `new Function`, so
  `script-src 'self'` is unchanged. An htmx trigger filter would have needed
  `unsafe-eval` and was rejected for that reason.

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

### Canary probes

Optional, zero or more `[[canary]]` entries: a synthetic test message the
relay composes and enqueues itself, on a configurable schedule, through a
configured route — so a working delivery path is noticed even without real
traffic, and a silently broken one (expired credential, changed smarthost
policy) does not go unnoticed just because no client happened to send
anything. One entry per route worth watching independently; each carries its
own `name`, unique among canaries and against every configured client name.

Deliberately reuses the bounce mechanism above for alerting rather than
introducing a second one: a canary failure is recorded through the same
`RecordFail` path a real client message's failure would be, keyed by the
canary's own `name` exactly as a real client's messages are keyed by client
name — so it reaches `[bounce].notify` (or that name's own override, which
is exactly why the name must not collide with a real client's) through the
existing digest. This is also why configuring any `[[canary]]` at all
requires `[bounce].notify` to be configured too, checked at load time. What
a canary does *not* share with a bounce notification is loop prevention: a
notification's own failure is deliberately never reported (that is exactly
how a notification loop would start), but a canary's failure is the one
thing this feature exists to report, so that exemption does not apply to it.
Canary traffic is kept out of its route's own delivered/bounced/deferred/
auth-failure metrics either way, with its own pair instead, labeled by name
(`smtprelayd_canary_last_delivery_time`, `smtprelayd_canary_failures_total`)
— see `docs/guides/CONFIGURATION.md` section 7 and `docs/guides/CHECKMK.md`.

**Schedule, added 2026-09-15.** An entry configures exactly one of
`interval_minutes` (every n minutes from service start) or `daily_at` (fixed
times of day); both, or neither, is a load-time error. An interval is the
wrong instrument for "a test mail every morning before anyone is in": it
drifts with every restart, so the one thing an operator wants to be able to
say about a daily canary — *it is late* — stops being answerable. `daily_at`
accepts a single `"HH:MM"` or an array of them, decoded by a custom
`config.DailyAt` unmarshaller, because once a day is the common case and a
one-element array would be noise an operator has to be told about; strict
`HH:MM` parsing, not `time.Parse`, so `"7:00"` and a rolling-over `"24:00"`
are refused rather than silently meaning something else.

The times are **UTC**, not `service.timezone`. That setting only ever changed
how a timestamp is displayed; this one decides when mail is sent, and a zone
with daylight saving has one day a year without 02:30 and one with two — plus
`time.LoadLocation` on Windows would mean either embedding `time/tzdata` or
depending on the registry. A local-time schedule can be reconsidered, but it
needs that cost accepted explicitly.

The wait is taken in steps of at most a minute and recomputed from the wall
clock, instead of one timer armed for up to 24 hours: a Go timer counts on
the monotonic clock, which stops while the machine is suspended and does not
follow an NTP step, so a single long timer would miss 07:00 by exactly as
much as either event moved the day. A scheduled time that has already passed
when the process looks again sends once, late — a late canary is a signal, a
missing one is indistinguishable from the failure the canary exists to
detect.

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
