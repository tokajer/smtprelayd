# Phase 4 plan — observability (dashboard, history, metrics, API, bounce notification)

Working plan for Phase 4 implementation in sub-phases. Each sub-phase
gets its own Go/No-Go; only move to the next phase when the previous one
is completed and approved. Reference `MEMORY.md` §7 and §8 for the
detailed architecture.

## Context

Phase 4 adds three layers of observability (event log, history, metrics),
a web dashboard and a JSON API, all already decided in `MEMORY.md` §7/§8
and `docs/API.md`. The config schema exists (`[bounce]`, `[web]`,
`[metrics]`, `[history]` in `smtprelayd.example.toml`), four placeholder
packages exist (`internal/store`, `internal/web`, `internal/metrics`,
`internal/api` each with `doc.go` only), but the implementation order
must be explicit because the components have hard dependencies:
`internal/store` is the data source for everything else.

## Dependency graph

```
spool (existing)
  ↓
store (4a: SQLite history)
  ├→ metrics (4b: read spool + store)
  ├→ web (4c: dashboard, read-only first)
  └→ api (4d: JSON endpoints)
     ├→ web (4c: requeue/delete forms, CSRF, audit log)
     └→ bounce (4e: notification, read store)
```

## Sub-phase 4a — `internal/store` (SQLite history store)

**Goal**: Durable append-only history of every message and every delivery attempt.

**Files modified**:
- `internal/store/store.go` — database open, schema, transactions
- `internal/store/schema.sql` — CREATE TABLE, indices
- `internal/store/history.go` — `RecordMessage`, `RecordAttempt`, retention
- `internal/config/validate.go` — add `[history]` validation (retention_days
  > 0, retain_subjects bool)
- `internal/delivery/delivery.go` — add `store *Store` field to `Manager`,
  call `store.RecordAttempt()` at each outcome in `attempt()` before
  `spool.Remove()` or `spool.Fail()`
- `go.mod` — add `modernc.org/sqlite`

**Key decisions**:
- Two tables:
  - `messages`: one row per queue entry per route (FK: queue_id). Columns:
    queue_id (PK), client, route, envelope_from, original_from, recipients
    (JSON array), subject, listener, remote_addr, received, expires,
    tls_used. Retention: `[history].retention_days`.
  - `attempts`: one row per delivery attempt, with verbatim SMTP response.
    Columns: id (PK), queue_id (FK), attempt_num, at_time, smtp_code,
    smtp_response, class (temporary/permanent/expired), next_attempt_at.
    Retention: cascades from `messages`.
  - `audit` (initially empty, added now for future 4d): admin actions.
    Columns: id (PK), at_time, token_name, source_addr, action, queue_id, details (JSON).
    Retention: cascades from `messages` for action-specific rows.
- Schema is created at startup in `serve()` if it doesn't exist (using
  `CREATE TABLE IF NOT EXISTS`).
- No ORM; `database/sql` with parameterized queries only.
- Retention job: at startup and every 24 hours, delete `messages` and
  cascaded `attempts`/`audit` rows older than `[history].retention_days`.
- **Subject retention**: `[history].retain_subjects` controls whether the
  `subject` column is populated (if false, store empty string). Personal
  data sensitivity per `docs/SECURITY.md` §7.

**Integration points**:
- `internal/delivery.attempt()`: after a delivery outcome is decided,
  before calling `spool.Remove()` or `spool.Fail()`, call
  `m.store.RecordAttempt(meta.ID, meta.Attempts, outcome, smtpCode, smtpResponse)`.
- `internal/listener` or `internal/spool`: Where is `RecordMessage` called?
  Options:
  1. In the SMTP listener after `spool.Commit()` succeeds → called once per
     route (correct for the messages table, one row per queue copy).
  2. In `spool.Commit()` itself → intrusive, spool should not know about
     history.
  3. Recommendation: in the caller of `spool.Commit`, after commit succeeds.
     For multi-route messages, the caller (rewriter in phase 3) already
     loops and calls Commit per route. But this is **an open question**: the
     exact call site must be chosen during implementation and documented.
- `smarthost.Deliver()` must return not just an error but also the verbatim
  SMTP response code and text. Check if it already does (likely `textproto.Error`);
  if not, extend it.

**Testing**:
- Unit tests for `store` package: `t.TempDir()` spool, real SQLite file,
  no mocks. Test `RecordMessage`/`RecordAttempt` paths, schema integrity,
  retention job, subject filtering.
- Negative tests: invalid queue ID format (should reject), SQL-shaped
  inputs in subject/sender (should escape/store safely), attempt with
  mismatched queue ID.
- No database fixtures; each test creates fresh tables.

**Definition of done**:
- [ ] Schema design (`schema.sql`) reviewed and matches `MEMORY.md` §8.
- [ ] `internal/store` package builds, tests pass, no lint errors.
- [ ] `go.mod` updated with `modernc.org/sqlite`, builds for both GOOS.
- [ ] `serve()` creates schema at startup if missing.
- [ ] `internal/delivery.attempt()` calls `store.RecordAttempt()` after
      every outcome (delivered, permanent fail, expired, deferred).
- [ ] Call site for `RecordMessage` identified and documented.
- [ ] `[history]` validation added to `validate.go`.
- [ ] A manual test: send a message, watch it appear in the `messages` table
      with the correct envelope/client/route, then watch an `attempts` row
      after the first delivery attempt.

## Sub-phase 4b — `internal/metrics` (Prometheus text exposition)

**Goal**: Expose queue depth, bounce counters, token age, and delivery rates
via a `/metrics` HTTP listener.

**Files modified**:
- `internal/metrics/metrics.go` — `New`, `Register`, text exposition handler
- `internal/delivery/delivery.go` — call `metrics.Counter/Gauge/Histogram`
  at relevant points
- `internal/authms365/token.go` — expose token age metric
- `cmd/smtprelayd/main.go` (`serve()`) — start metrics listener as goroutine

**Metrics to expose** (per `MEMORY.md` §7):
- Queue depth by state (queued, deferred) and route: gauges,
  `smtprelayd_queue_size{state,route}`.
- Delivered/bounced/deferred counts by route: counters,
  `smtprelayd_delivered_total{route}`, `smtprelayd_bounced_total{route}`,
  `smtprelayd_deferred_total{route}`.
- Authentication failures: counter, `smtprelayd_auth_failures_total{route}`.
- OAuth token age: gauge, `smtprelayd_oauth_token_age_seconds{route}` (for
  M365 routes).
- Last successful delivery timestamp per route: gauge,
  `smtprelayd_last_delivery_time{route}`.
- Delivery rate (msg/min, 5-min rolling average): gauge.

**Key decisions**:
- No `prometheus/client_golang` dependency. Metrics are exposed in plain
  Prometheus text format (generated by hand). Simpler, keeps dependencies
  minimal, sufficient for Checkmk.
- Metrics are in-memory only, not persisted. They reset on service
  restart (acceptable for a relay).
- Separate listener from `[web]`, address `[metrics].address`, path
  `[metrics].path` (default `127.0.0.1:9025`, `/metrics`).
- No authentication on metrics (decision from `MEMORY.md`; Checkmk polling
  does not need a token).

**Integration points**:
- `internal/delivery.attempt()`: increment delivered/bounced/deferred counters.
- `internal/delivery`: track queue depth (read `spool.Len()`, gauge it).
- `internal/authms365`: expose token age at each refresh.
- Rate calculation: on-demand at `/metrics` scrape time by dividing
  delivered count by uptime in seconds (approximation, acceptable).

**Testing**:
- Unit tests: synthetic metrics registry, assert counter/gauge values
  after operations.
- Negative test: malformed `/metrics` request, should return 400 or 404.
- Scrape test: `http.Get` the `/metrics` endpoint, parse response, check
  for expected metric names.

**Definition of done**:
- [ ] `internal/metrics` package builds.
- [ ] All metrics from `MEMORY.md` §7 are emitted.
- [ ] `/metrics` listener is up at the configured address and path.
- [ ] Manual test: `curl 127.0.0.1:9025/metrics` returns valid Prometheus
      text format.
- [ ] Metrics are correct for a known state (e.g., after sending a test
      message, delivered/bounced/deferred counts and queue depth match
      expectations).

## Sub-phase 4c — `internal/web` (dashboard, read-only)

**Goal**: Server-rendered HTML dashboard for queue inspection and history
search.

**Files modified**:
- `internal/web/web.go` — HTTP server, template loading
- `internal/web/*.html` (embedded via `embed.FS`) — dashboard, search
  results, queue view, bounce view
- `internal/store/query.go` — add `FindMessages`, `FindBounces`,
  `FindMessageByID` with filtering (time range, sender, recipient,
  status, client, route)
- `cmd/smtprelayd/main.go` (`serve()`) — start web listener as goroutine,
  pass config, store, spool

**Features** (read-only only; state-changing actions in 4d):
- Live queue view: message list, sortable by sent/status/client/route,
  filterable by time range.
- Search: sender, recipient, subject (substring), status (queued/deferred/
  delivered/bounced), time range, client, route.
- Per-message view: full envelope, all attempts with SMTP responses,
  subject, original/rewritten sender.
- Route status: current queue depth, last successful delivery,
  authentication status (from metrics).
- Bounce view: list of failed messages, same filters as search.
- Read-only config view (text of `[listener]`, `[client]`, `[route]`,
  `[bounce]` sections as read from `smtprelayd.toml`, no secrets).

**Key decisions**:
- `embed.FS` for templates and static assets (CSS, no JS for now).
- `html/template` with strict auto-escaping; all user input (sender,
  recipient, subject, SMTP responses from `store`) is escaped by default.
- No inline scripts. Security headers per `docs/SECURITY.md` §7:
  - `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- Loopback-by-default binding (127.0.0.1:8025), TLS enforced on non-loopback
  addresses (existing validation in `validate.go`).
- Subject retention: if `[history].retain_subjects == false`, subjects are
  displayed as `[redacted]`, not suppressed from the view.
- Message bodies are never retrieved or displayed (per `docs/EXPLOIT-SURFACE.md` §8).
- Pagination: limit results to 100 per page (cursor-based offset via LIMIT/OFFSET
  in SQL, opaque cursor passed as query parameter).

**HTML/CSS structure**:
- Base layout: header (logo, version, "Search" link), sidebar (queue status,
  recent errors), main content.
- Queue view: sortable table, filters in the sidebar.
- Search form: sender/recipient/subject text, status/client/route dropdowns,
  date range (RFC 3339 input).
- Per-message view: tabbed interface (envelope, attempts, raw metadata).
- Responsive design via CSS grid (no framework, vanilla CSS).

**Testing**:
- Unit tests for `FindMessages`, `FindBounces` queries (test parameterization,
  LIMIT/OFFSET).
- Negative tests: subjects with quotes/angle-brackets/control chars are
  escaped in HTML output (verify via `html.EscapeString` or template default
  behavior).
- Manual: send a message with a tricky subject (e.g., `<img onerror=alert(1)>`),
  verify the dashboard displays it safely (no script execution).

**Definition of done**:
- [ ] Dashboard loads at `[web].address`, displays queue.
- [ ] All filter/search parameters work correctly.
- [ ] Tricky input (XSS-shaped subject, control chars, etc.) is displayed
      safely.
- [ ] `Content-Security-Policy` and other headers are set.
- [ ] Message bodies are never exposed (verify by checking the code path
      through `store.FindMessageByID()`).
- [ ] Read-only config view renders without secrets (password/client_secret
      fields are redacted or omitted).

## Sub-phase 4d — `internal/api` (JSON API + admin actions + audit log)

**Goal**: JSON API for programmatic access and remote control. Adds state-
changing actions (requeue, delete) and audit logging.

**Files modified**:
- `internal/api/api.go` — HTTP router, middleware for auth/CSRF/rate-limit
- `internal/api/auth.go` — bearer token validation (constant-time
  comparison against `Web.Tokens` SHA256 hashes), scope check
- `internal/api/endpoints.go` — implement all `/api/v1/*` routes
- `internal/api/csrf.go` — CSRF token generation and validation (for web
  forms only, not REST calls)
- `internal/store/query.go` — add cursor-based pagination helpers, audit log
  insertion
- `internal/spool` — add `Requeue` method (move from `spool/failed` back to
  `spool/queue`, reset `Attempts` to 0)
- `internal/web/*.html` — add forms for requeue/delete with CSRF tokens
  (integrates 4c + 4d)
- `cmd/smtprelayd/main.go` — wire both web and api to the same HTTP server
  (shared listener, shared store, same root logger)

**Endpoints** (per `docs/API.md`):
- `GET /api/v1/bounces` — filter by time, recipient, client, route, class
- `GET /api/v1/messages` — same filters plus status (queued/deferred/
  delivered/bounced)
- `GET /api/v1/queue` — current queue state per route
- `GET /api/v1/messages/{queue_id}` — one message + all attempts
- `POST /api/v1/messages/{queue_id}/requeue` (admin) — move to queue, reset
  attempts, record audit
- `DELETE /api/v1/messages/{queue_id}` (admin) — remove, retain history,
  record audit
- `GET /api/v1/health` (no auth) — status, uptime, route auth status

**Key decisions**:
- Single HTTP listener for both dashboard and API (`[web].address`).
- Router: stdlib `net/http` + `ServeMux` or a lightweight `chi`-like mux.
  Recommendation: `ServeMux` (stdlib only, minimal).
- Bearer tokens: constant-time comparison (`crypto/subtle.ConstantTimeCompare`)
  against `Web.Tokens[i].SHA256`. No plaintext token is ever stored or displayed
  (existing config schema `Web.Token.SHA256` is the only persisted form).
- Failed auth attempts are logged and counted in metrics. Per `docs/SECURITY.md` §7:
  rate-limit per source address (e.g., 5 failures per minute before exponential
  backoff). Use a simple in-memory token-bucket per source IP.
- CSRF: Dashboard state-changing forms (requeue/delete) generate a cryptographic
  token (HMAC(secret, session_id, action)) valid for 1 hour, embedded in the form,
  validated on POST. REST API calls from Checkmk do not use CSRF (Checkmk sends
  Bearer token, which suffices).
- Audit log: `audit` table in `store`, record every admin action with
  token_name (from `Web.Token.Name`), source_addr, action, queue_id, timestamp,
  optional details (JSON). This data is queryable (not exposed via API in 4d,
  but available for future audit dashboard).
- Cursor-based pagination: LIMIT/OFFSET in SQL, cursor is base64-encoded
  `{offset, limit}` struct. Parameter name: `cursor`.
- Sort/filter parameters mapped via allowlist: sort columns (time, status, client, route),
  filter columns (time, status, client, route, recipient). No free-form column
  names from the request.

**Testing**:
- Unit tests for auth (correct token → 200, malformed → 401, read token
  on admin endpoint → 403, wrong token → 401).
- Negative tests: CSRF token missing on POST → 403, token expired, or for
  a different session → 403.
- SQL parameterization: attempt to pass `' OR 1=1 --` in recipient filter,
  verify it is treated as a literal string, not SQL.
- Pagination: send `limit=1&cursor=<next>`, verify results are different
  and ordered consistently.
- Rate-limit: send 10 failed auth attempts from the same source, verify
  later requests are delayed or rejected.
- Manual: `curl -H "Authorization: Bearer <token>" https://localhost:8025/api/v1/bounces`
  returns valid JSON; admin action with wrong scope (read token) is rejected.

**Definition of done**:
- [ ] All endpoints from `docs/API.md` return correct JSON responses.
- [ ] Bearer token auth works: valid token → 200, no/bad token → 401,
      read scope on admin endpoint → 403.
- [ ] Pagination is correct: `limit`, `cursor` parameters work; results
      are ordered; next page has different data.
- [ ] CSRF protection on web forms: requeue/delete buttons submit with
      CSRF token; requests without or with bad token → 403.
- [ ] Admin actions (requeue, delete) record audit log entries.
- [ ] Rate-limiting on failed auth is enforced.
- [ ] SQL injection attempts (` ' OR 1=1 --`) in filters are treated as
      literals, not SQL syntax.
- [ ] `/api/v1/health` returns 200 (no auth).

## Sub-phase 4e — Bounce notification (mail)

**Goal**: Send digest batches of failed messages to configured recipients,
with loop prevention, volume capping, and no state-changing re-delivery.

**Files modified**:
- `internal/bounce/notifier.go` — Notifier struct, digest batching, volume cap
- `internal/store/query.go` — add `FindBouncesSince` for digest source
- `internal/delivery/delivery.go` — call `notifier.RecordFail()` when
  `spool.Fail()` is called
- `cmd/smtprelayd/main.go` (`serve()`) — create notifier, start digest
  dispatch goroutine
- Config: `[bounce]` and per-client `[client.bounce]` already exist in schema
  (and are unvalidated); add validation to `validate.go`.

**Key behaviors** (per `MEMORY.md` §8):
- Digest window: `[bounce].digest_minutes` (default 15), batches failures
  into one message per time window.
- Volume cap: `[bounce].max_per_hour`, exceed sends no more notifications
  in that hour (but records them for the next hour).
- Loop prevention:
  1. Notification messages have an empty envelope sender (`MAIL FROM: <>`).
  2. Notifications are never subject to sender rewriting (handled in listener,
     flag the message somehow).
  3. Notification delivery failures are logged and counted, never triggering
     another notification (check in `delivery.attempt()`: if this is a
     notification, do not call `notifier.RecordFail()`).
- Recipient selection: `[bounce].notify` (global) can be overridden per client
  via `[client.bounce].notify`. If both are empty, notifications are disabled.

**Implementation**:
- `Notifier` struct: digest map (key: time bucket, value: list of failed queue
  IDs), volume-cap counter (resets hourly), lock.
- `RecordFail(queueID)`: add queue ID to current hour's digest bucket.
- Background goroutine: every `[bounce].digest_minutes`, collect pending
  digests, check volume cap, if OK, compose a message (list of failures with
  sender, recipients, SMTP response, subject) and call `spool.Enqueue` with
  the notification recipient list. Enqueued message is flagged as a notification
  (e.g., a `notification=true` flag in the Envelope — requires schema change
  to spool.Meta or a separate tracking map in Notifier).
- Failure scenario: if a notification message itself fails to deliver, log it
  and increment a "notification_failures" metric, but do not call
  `notifier.RecordFail()` again (loop prevention).

**Testing**:
- Unit tests: `Notifier.RecordFail()` adds to correct digest, digest dispatch
  respects volume cap, loop prevention (notification_fails flag is checked).
- Negative test: notification message with `notification=true` flag, simulate
  delivery failure, verify no second notification is sent.
- Timing test: set digest window to 5 seconds (synthetic), verify digest is
  sent after 5 seconds, not immediately.

**Definition of done**:
- [ ] Bounce notifications are sent as configured.
- [ ] Digest batching works: multiple failures within `digest_minutes` are
      batched into one message.
- [ ] Volume cap is enforced: more than `max_per_hour` notifications are
      suppressed, logged, and counted.
- [ ] Loop prevention: a notification delivery failure does not trigger
      another notification.
- [ ] `[bounce]` and `[client.bounce]` are validated (notify list nonempty
      if notifications are enabled, digest_minutes/max_per_hour > 0).

## Overall definition of done (Phase 4)

- [ ] All 4a–4e sub-phases are complete and tested.
- [ ] `go build ./...` clean for both `linux/amd64` and `windows/amd64`.
- [ ] `go vet ./...` clean.
- [ ] `go test -race ./internal/store ./internal/web ./internal/metrics ./internal/api ./internal/bounce`.
- [ ] `govulncheck ./...` clean.
- [ ] `gosec ./...` clean (no issues beyond expected XSS surface on attacker-
      controlled subjects/senders, which are escaped by template auto-escaping).
- [ ] No use of `template.HTML`, `template.JS`, `template.URL` conversions.
- [ ] `PROGRESS.md` updated: Phase 4 complete, all four components operational.
- [ ] Manual end-to-end test:
  - Send a message, watch it in the queue via the web dashboard.
  - Retrieve bounces via the API (`curl /api/v1/bounces`).
  - Check metrics are exposed (`curl /metrics`).
  - Trigger a bounce (wrong recipient or credential), watch it appear in
    bounces and receive a notification mail (or observe it in the spool if
    `[bounce].notify` is not configured).
  - Requeue a bounced message via the dashboard, watch the audit log.
  - Verify a read-scoped API token cannot delete, and an admin token can.

## Open questions to resolve during implementation

1. **Where is `store.RecordMessage()` called?** During `spool.Commit()`, or
   in the caller after commit succeeds? During 4a, the call site must be
   chosen.
2. **How does `smarthost.Deliver()` return the SMTP response?** Currently,
   does it propagate the response code and text to the error, or only the
   error message? Needs investigation in `internal/delivery/smarthost/client.go`
   and possibly extension.
3. **Is `[metrics].address` always loopback, or can it be non-loopback?**
   Unlike `[web]`, metrics endpoint does not require authentication. Per
   `MEMORY.md` §7, Checkmk should scrape it, so likely loopback is sufficient,
   but this should be decided and documented if allowing non-loopback.
4. **Should the dashboard require bearer-token auth, or is loopback binding
   sufficient?** Currently: loopback binding is sufficient (decision from
   `PROGRESS.md` "Open questions"). If changed to require auth, web forms
   also need CSRF *and* bearer tokens, which is complex. Recommend:
   keep loopback binding, no web auth (API auth via token is separate).
5. **How are failed `Requeue` actions handled?** If a requeued message fails
   again, do we audit that separately, or does the normal delivery path
   handle it? (Likely: normal delivery path, no special handling.)
6. **Notification message format and content** — is plain text sufficient,
   or should it be MIME multipart with an HTML version for richer display?
   Recommendation: plain text for simplicity, one failure per line (queue ID,
   sender, recipients, SMTP response, subject).

## References

- `MEMORY.md` §7 (Observability), §8 (Bounce handling)
- `docs/API.md` (endpoint contract)
- `docs/SECURITY.md` §7 (Dashboard and API security)
- `docs/EXPLOIT-SURFACE.md` §8 (Dashboard and API injection surface)
- `docs/MS365-AUTH.md` (not directly relevant to Phase 4)
- `CLAUDE.md` (code style, testing, commit message format)
