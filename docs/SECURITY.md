# Security Design

Binding requirements. A change that weakens anything in this document needs an
explicit decision recorded in `MEMORY.md`.

The realistic threat to this service is not an exotic exploit. It is a
misconfiguration that turns it into an open relay, a leaked Entra ID client
secret, or a header injection that silently adds recipients. The design
prioritises those three.

## 1. Threat model

| Threat | Impact | Mitigation |
|---|---|---|
| Open relay | Domain and IP blacklisted, tenant suspended | Default deny, explicit CIDR allowlist, startup self-check, relay test command |
| Entra ID client secret leaked | Attacker sends as the organisation | Secret never on disk in plaintext, env or OS keystore only, no logging, rotation alert |
| Header injection via rewriting | Hidden recipients, spoofed headers | Strict CRLF rejection, structural header rebuild, never string concatenation |
| Compromised internal device | Mass sending under a valid client identity | Per-client rate and size limits, recipient caps, anomaly metrics |
| API token theft | Read of message metadata, or requeue and delete | Hashed tokens at rest, scopes, localhost binding, audit log, attempt rate limiting |
| Spool read by another local user | Full message content disclosure | 0600 files, 0700 directories, restrictive Windows ACLs, dedicated service account |
| Resource exhaustion | Service outage, disk full | Connection caps, timeouts, streaming size enforcement, disk watermarks |
| Dependency compromise | Arbitrary code in the binary | Minimal dependency set, pinned modules, `govulncheck` in CI, reproducible builds |
| Transport interception | Credential and message disclosure | Mandatory certificate verification upstream, TLS 1.2 minimum outbound, no downgrade |

Explicitly **not** in the threat model: a hostile internet-facing attacker on
the SMTP port. The listeners belong on internal networks only. If that ever
changes, this document must be revisited before deployment.

## 2. Relay policy — fail closed

The single most damaging failure mode gets the strictest handling.

- No default-allow path exists. A source address that matches no configured
  client is rejected with `550`, regardless of listener, authentication state
  or destination.
- Relaying to external domains requires a matched client. There is no
  "trusted by default" localhost exemption.
- The configuration loader **refuses to start** when a listener binds a
  non-loopback address and no client CIDR is defined. An empty allowlist is
  treated as a configuration error, never as "allow all".
- CIDR overlaps are reported at load time. Ambiguous matching is a failure,
  not a warning.
- `smtprelayd selftest` performs an active check: it connects to its own
  listeners from an unlisted source, attempts to relay to an external domain
  and fails loudly if the attempt succeeds. This runs in CI and should run
  after every configuration change.
- Received-header hop counting rejects mail exceeding a maximum hop count, so
  a routing mistake cannot become an amplification loop.

## 3. Secrets

- No secret is ever written to the configuration file. The loader accepts only
  `${ENV_VAR}` references or a path to a file readable exclusively by the
  service account.
- Secrets are held in memory as long as needed and are never logged, never
  included in error strings, never rendered in the dashboard's configuration
  view, and never serialised into history or metrics.
- OAuth access tokens live in memory only. They are not persisted, not cached
  to disk and not exposed through the API. Only the token's age is observable.
- Client secret expiry is read from configuration and surfaced as a metric so
  it can be alerted on before it lapses and delivery stops.
- **API tokens are stored as hashes.** The configuration holds a SHA-256 hex
  digest, not the token. `smtprelayd token new` generates a 256-bit random
  token, prints it once and emits the digest to paste into the configuration.
  This supersedes the earlier plan of expanding plaintext tokens from
  environment variables.
- Log redaction is applied centrally in the logging layer rather than at each
  call site, so a new call site cannot forget it.

## 4. Header and envelope handling

Sender rewriting is the highest-risk code in the project, because it takes
attacker-influenced values and writes them into a message.

- Any address or display name containing CR, LF, NUL or a bare control
  character is rejected outright. It is never sanitised and re-used.
- A bare CR inside a command or a header line is rejected too, because the
  line is either interpreted or written back into the spooled header block,
  and whether that CR ends a line is then the next parser's decision. The
  message body is deliberately exempt: a lone CR there cannot split a header,
  and rejecting it would cost a legacy device the whole message.
- Rewritten headers are produced by replacing whole fields in a parsed header
  block (`internal/rewrite`), never by concatenating strings. The block parser
  is first-party; `go-message`, which this section named until 2026-08-11, has
  never been a dependency.
- `X-Original-From` carries a properly encoded value, or is omitted. It is
  never a raw copy of untrusted input.
- Envelope addresses are validated against RFC 5321 length limits: 64 octets
  local part, 255 domain, 254 total.
- Line length is enforced at 1000 octets including CRLF. Over-long lines are
  rejected during the data phase, not repaired.
- Limits on header count and total header size prevent parser resource
  exhaustion. A MIME nesting depth bound is named here as future work, not as
  a control that exists: no MIME parsing exists at all, so there is no nesting
  to bound and nothing that could recurse on it.
- The relay adds its own `Received` header and strips any client-supplied
  header that would misrepresent its origin. Every value interpolated into it,
  including the configured `service.hostname`, is proved free of CR, LF and
  NUL before it gets there.
- **Only `<CRLF>.<CRLF>` may end the data phase and hand the stream back to
  the command loop.** Accepting a bare `<LF>.<LF>` there is SMTP smuggling: it
  turns "controls the message body" into "controls the envelope", so a contact
  form or an ERP system on an allowlisted host could inject its own `MAIL
  FROM` and `RCPT TO`. Checking the dot line's own terminator is not enough —
  `<LF>.<CRLF>` smuggles just as well — so the preceding line's terminator is
  checked with it.
  Legacy devices that speak bare LF throughout are this relay's users, so
  their end-of-data is still honoured rather than left to time out: the
  message is queued and acknowledged, and then the session is closed instead
  of being returned to the command loop. The message is delivered; the
  injection is not.
  The reverse direction needs no control: the data reader normalises every
  line to CRLF on the way into the spool, so this relay can never be the
  sending side of a smuggling chain.

## 5. Transport security

- Outbound: wherever TLS is negotiated, certificate verification is
  **mandatory**. There is no configuration option to disable it — no
  `insecure_skip_verify` exists in the schema, because such a flag is
  invariably found switched on in production. Optional pinning to an expected
  CA or certificate fingerprint per route.
- Outbound minimum TLS 1.2. If a smarthost offers only STARTTLS and then fails
  the handshake, the message is deferred, never sent in the clear.
- A route may be declared cleartext outright with `tls = "none"`, for legacy
  internal MTAs on a segment the operator controls. This is a distinct setting,
  never a fallback: no failed handshake and no missing STARTTLS advertisement
  can reach it. Since such a session protects nothing, the loader accepts only
  `auth = "none"` on it, and the delivery path refuses to send credentials over
  an unencrypted connection even if a Route reached it some other way.
- Inbound: per-listener minimum version. TLS 1.0 remains possible on the
  internal port 25 listener for legacy devices, but only there, only from
  allowlisted networks, and it is reported at startup as a deliberate
  weakening.
- SASL authentication on inbound listeners is offered only after TLS is
  established. `PLAIN` and `LOGIN` are never advertised on a cleartext
  connection.
- Certificate expiry for the relay's own certificate is exposed as a metric.

## 6. Process privileges and file permissions

- Linux: runs as a dedicated unprivileged user. Port 25 is obtained through
  `CAP_NET_BIND_SERVICE` or systemd socket activation, never by running as
  root. The systemd unit sets `NoNewPrivileges`, `PrivateTmp`,
  `ProtectSystem=strict`, `ProtectHome`, `ReadWritePaths` limited to the data
  directory, `RestrictAddressFamilies`, `MemoryDenyWriteExecute` and a
  restrictive `SystemCallFilter`.
- Windows: a dedicated service account, never `LocalSystem`. The data
  directory carries an explicit ACL granting only that account and
  administrators.
- Spool files 0600, directories 0700. Permissions are verified at startup and
  a mismatch is a startup failure.
- **`limits.spool_max_gb` bounds the whole spool, `spool/failed` included.**
  Counting only the live queue meant that a permanently failing message freed
  its quota the moment it was moved aside, while still occupying the disk —
  so a client that produced nothing but permanent failures filled the
  filesystem and the quota never saw it. `queue.failed_retention_hours` then
  bounds how long those files are kept, because counting alone would turn a
  full `spool/failed` into a relay that permanently refuses new mail. Only the
  spool copy is swept; the history row and every attempt survive under
  `history.retention_days`.
- A limit of zero means "unlimited" throughout, which makes a mistyped minus
  sign a way to switch a control off silently. Negative values for
  `client.rate_limit_per_min`, `client.max_connections`,
  `route.rate_limit_per_min`, `limits.spool_max_gb` and
  `queue.failed_retention_hours` are therefore startup errors, as is a
  `spool_max_gb` large enough to overflow the gigabytes-to-bytes conversion
  back into "no quota".
- The history database and the log file are 0600 as well. Both are created by
  code that does not let the caller choose a mode — the SQLite driver and
  lumberjack, which default to 0644 — so `fsmode.RestrictFile` restricts them
  after creation, including a file an earlier version left world-readable.
  For the log this happens before lumberjack opens it, because lumberjack
  copies the mode of the current file onto each rotation. Both files hold
  every sender, recipient and, unless `retain_subjects` is off, every subject.
- Every file the service writes lives under the data directory, and the
  configuration cannot move one outside it. `log.file` is the only setting
  that becomes a path by being joined to another; `config.LogPath` is the
  single place that join happens, it rejects an absolute path, a Windows
  volume name, a NUL byte and any `..` element (on both separators, since a
  configuration written on Windows is routinely deployed on Linux), and it
  re-checks containment on the result. A violation fails startup rather than
  relocating the log. The check is lexical: it proves the *configured value*
  cannot name a location outside the data directory, not that the path is
  safe to open — a symlink planted inside the data directory is the data
  directory's own trust check to catch.
- The service never executes external commands and never loads plugins. No
  first-party file imports `os/exec`. The pure-Go SQLite runtime
  `modernc.org/libc` does, for the C `system()`/`popen()` shims that the
  amalgamation never calls; it is the only importer CI accepts, and
  `scripts/check-banned-imports.sh` fails on any other, per GOOS.

## 7. Dashboard and API

- **The dashboard must bind to loopback.** It has no authentication of its
  own: the CSRF token on its requeue and delete forms is fetched from the page
  itself, so it stops another site from driving those actions but is not a
  credential. Bearer tokens cannot close this either — the process holds only
  their SHA-256 digests, so the dashboard cannot present one for itself.
  Loopback therefore *is* the authentication, and the loader refuses a
  non-loopback `[web].address` outright rather than serving it with a
  certificate and no credential. Remote access goes through an SSH tunnel or
  an authenticating reverse proxy. A login that verifies a pasted token
  against the stored digests is possible and is recorded as future work.
- **A loopback bind is not by itself the boundary; the `Host` header completes
  it.** A browser sits inside the loopback boundary and resolves names on
  someone else's behalf, so a page the operator visits can point a name it
  controls at 127.0.0.1 and then talk to the dashboard same-origin — DNS
  rebinding. Both the dashboard and a loopback metrics listener therefore
  refuse any request whose `Host` is not `127.0.0.1`, `[::1]` or `localhost`,
  with or without the configured port, answering `421 Misdirected Request`. A
  reverse proxy placed in front must set `Host` to the configured address.
  The `/api/v1/*` endpoints need no such check: they want a bearer token,
  which a rebound page cannot obtain.
- **The metrics endpoint may bind beyond loopback, but only authenticated and
  only over TLS.** Unlike the dashboard, a monitoring system can present a
  credential, so this is a token check rather than a refusal: a read-scope
  bearer token, plus a certificate, because a token sent in the clear across a
  LAN is a credential handed to whoever is listening. The loader refuses such
  an address unless both exist. On loopback the endpoint stays open and
  unencrypted, which is what a local Checkmk agent wants. Failed attempts are
  logged with the source address but not rate limited: this endpoint exists to
  be polled continuously, and locking a monitoring system out after five bad
  requests would turn a credential mistake into an alerting outage.
- Bearer tokens compared in constant time against stored hashes, in one place
  (`config.MatchToken`) shared by the API and the metrics endpoint. Scopes
  `read` and `admin`; every destructive action requires `admin`.
- Failed authentication is rate limited per source address with exponential
  backoff, logged, and exposed as a metric.
- Every `admin` action writes an immutable audit record: token name, source
  address, action, queue ID, timestamp.
- Dashboard state-changing actions require a CSRF token. Cookies are
  `HttpOnly`, `SameSite=Strict` and `Secure` when served over TLS.
- Strict `Content-Security-Policy` with no inline scripts, plus
  `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy`.
- Message bodies are never exposed through the API or the dashboard. Metadata
  and SMTP responses only. Whether subjects are retained is configurable, since
  they frequently contain personal data.

## 8. Supply chain and build

- Minimal dependency set. Every addition needs justification in `MEMORY.md`.
- `go.sum` committed, builds run with `-mod=readonly` and module verification
  enabled.
- CI runs `govulncheck` and `gosec` on every push and fails the build on
  findings. `gosec` runs with no excluded rule and no skipped directory: the
  exceptions the tree needs are `#nosec` annotations on the line they apply
  to, each naming the property that makes it one, so a change that breaks that
  property fails the build instead of inheriting a blanket exemption.
- The Go toolchain pinned in the workflows must not fall behind the `go`
  directive in `go.mod`. A lower pin does not lower the toolchain — the
  default `GOTOOLCHAIN=auto` downloads a newer one — it only stops describing
  what actually produced the release binaries.
- Release binaries are built reproducibly with trimmed paths, checksummed, and
  signed. Windows binaries additionally carry an Authenticode signature.
- An SBOM is produced per release.

## 9. Data protection

Message metadata is personal data. Retention is configurable and enforced by
an actual deletion job, not merely by a query filter. Subject retention can be
disabled independently. Log files follow the same retention. Everything stays
on the operator's own infrastructure; the service performs no telemetry and
contacts no endpoint other than the configured smarthosts and the Entra ID
token endpoint.

## 10. Pre-deployment checklist

- [ ] `smtprelayd selftest` passes, including the open-relay check
- [ ] Listeners bound only to internal interfaces, firewalled accordingly
- [ ] Every client CIDR reviewed and justified
- [ ] No secret present in the configuration file
- [ ] Service account is unprivileged, data directory ACLs verified
- [ ] Outbound certificate verification confirmed active
- [ ] API bound to loopback or behind TLS, tokens issued per consumer
- [ ] Rate and size limits set per client
- [ ] Monitoring covers queue depth, auth failures, secret expiry, certificate
      expiry
- [ ] Backup and restore of the data directory tested
