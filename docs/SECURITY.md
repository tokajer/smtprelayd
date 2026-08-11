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
- Rewritten headers are produced by structural encoding through
  `go-message`, never by concatenating strings.
- `X-Original-From` carries a properly encoded value, or is omitted. It is
  never a raw copy of untrusted input.
- Envelope addresses are validated against RFC 5321 length limits: 64 octets
  local part, 255 domain, 254 total.
- Line length is enforced at 1000 octets including CRLF. Over-long lines are
  rejected during the data phase, not repaired.
- Limits on header count, total header size and MIME nesting depth prevent
  parser resource exhaustion.
- The relay adds its own `Received` header and strips any client-supplied
  header that would misrepresent its origin.

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

- Bound to loopback by default. Binding elsewhere requires TLS to be
  configured; the loader refuses a non-loopback bind without it.
- Bearer tokens compared in constant time against stored hashes. Scopes `read`
  and `admin`; every destructive action requires `admin`.
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
  findings.
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
