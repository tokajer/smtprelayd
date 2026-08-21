# Configuration Guide

Step-by-step recipes for every configurable part of smtprelayd. Start from
`configs/smtprelayd.example.toml` — copy it to the path in the table below and
edit in place; every recipe here assumes that starting point rather than an
empty file. For the Microsoft 365 route specifically, `docs/MS365-AUTH.md` has
its own complete walkthrough, from Entra ID app registration through secret
provisioning — this guide covers everything else and points there instead of
repeating it.

One procedure serves both platforms throughout; only paths and service
commands differ, so they are given side by side instead of duplicating each
recipe per OS.

| | Linux | Windows |
|---|---|---|
| Config file | `/etc/smtprelayd/smtprelayd.toml` | `%ProgramData%\SMTPRelayd\smtprelayd.toml` |
| Data directory | `/var/lib/smtprelayd` | `%ProgramData%\SMTPRelayd` |
| Service account | `smtprelayd` system user | `NT SERVICE\smtprelayd` |
| Restart | `sudo systemctl restart smtprelayd` | `Restart-Service smtprelayd` (elevated) |

## Validate and apply — do this after every recipe below

There is no live reload: the configuration is read once at startup.

```sh
smtprelayd -config <config file from the table above> check      # validate, does not restart
```
Then restart the service (table above), and confirm:
```sh
smtprelayd -config <config file> selftest    # fails loudly if it can relay from an unlisted address
```
`check` also binds and releases every listener, dashboard and metrics address,
so an unassignable `address` is caught here rather than in a restart loop.

A secret field (`client_secret`, `credentials.password`) is never a literal
value — it is `${ENV_VAR}`, `file:<path>`, or (Windows only) `dpapi:<path>`.
`docs/MS365-AUTH.md` step 2 walks through all three in detail; that walkthrough
applies to any secret field in the configuration, not only Microsoft 365's.

## 1. Inbound listeners and the relay's own TLS certificate

`configs/smtprelayd.example.toml` ships three ready-to-copy listener patterns
— pick the one matching each device class and adjust `address`:

| Pattern | Port | `tls` | Typical use |
|---|---|---|---|
| `smtp` | 25 | `starttls`, `min_tls = "1.0"` | legacy devices (printers, scanners) that cannot negotiate modern TLS |
| `submission` | 587 | `starttls`, `min_tls = "1.2"`, `require_tls = true` | modern devices and applications |
| `smtps` | 465 | `implicit`, `min_tls = "1.2"` | clients that only speak implicit TLS |

A non-loopback listener with no matching `[[client]]` CIDR is a startup
error — the loader refuses to become an accidental open relay rather than
warn and continue.

Any listener with `tls` other than `none` needs the shared `[tls]` block:

```toml
[tls]
cert_file = "/etc/smtprelayd/tls/relay.crt"   # leaf cert, intermediates appended if any
key_file  = "/etc/smtprelayd/tls/relay.key"   # unencrypted PEM private key
```

Steps:

1. Obtain a certificate for the relay's hostname from whatever CA the network
   already trusts (internal PKI, ACME, or a purchased cert) — smtprelayd does
   not issue or renew certificates itself.
2. Place `cert_file` and `key_file` on disk. The loader does not enforce
   permissions on these two paths the way it does for `file:` secrets, but
   the private key deserves the same treatment: on Linux, owned by the
   `smtprelayd` user, mode `0600`; on Windows, put it inside the data
   directory so it inherits the protected ACL `SecureDataDir` sets there (see
   `docs/MS365-AUTH.md`'s `file:` option for exactly how that inheritance
   works).
3. Validate and apply (see above) — `check` fails immediately with
   `tls.LoadX509KeyPair`'s own error if the pair does not parse or does not
   match.

The same `[tls]` pair is reused for a metrics listener bound beyond loopback
(section 8).

## 2. Clients — who may relay, and sender rewriting

Clients are matched by source address, longest CIDR prefix wins; an empty
client list is a startup error rather than an implicit allow-all.

```toml
[[client]]
name  = "printers-vienna"
cidr  = ["10.10.5.0/24"]
route = "m365"                 # a route name from section 3/4, or a default route
max_message_mb     = 25
max_recipients     = 20
rate_limit_per_min  = 30
max_connections     = 10
```

Sender rewriting (`[client.rewrite]`) has three modes — the example
configuration ships one client per mode, so the fastest path is copying
whichever one matches:

| Mode | Behaviour | Required fields |
|---|---|---|
| `off` (default) | Message passes through unmodified | none |
| `force` | Envelope and header `From` are always rewritten | `envelope_from`; `header_from` optional |
| `if_unauthorized` | Rewritten only when the original envelope sender is **not** in `allowed_senders` | `envelope_from`, `allowed_senders` (at least one entry) |

```toml
  [client.rewrite]
  mode          = "force"                          # or "if_unauthorized" / "off"
  allowed_senders = ["*@example.at"]                # if_unauthorized only; address or *@domain
  envelope_from = "relay@example.at"
  header_from   = "Printer Vienna <relay@example.at>"   # or "keep"; domain must match envelope_from's
  reply_to      = "preserve"                        # preserve | drop | fixed:<address>
```

`header_from`'s domain must match `envelope_from`'s domain — SPF checks the
envelope, DMARC checks the header, so a mismatch fails alignment at the
smarthost regardless of what the smarthost itself accepts.

A client can override the global bounce recipients:

```toml
  [client.bounce]
  notify = ["druckeradmin@example.at"]   # overrides [bounce].notify for this client only
```

## 3. Routes — a generic smarthost with SMTP AUTH and TLS

For anything that is not Microsoft 365: an internal relay, a hoster, a
partner's MTA that requires SMTP AUTH.

```toml
[[route]]
name = "partner-smarthost"
host = "mail.partner.example"
port = 587
tls  = "starttls"          # or "implicit"
min_tls = "1.2"
auth = "plain"              # or "login" — some smarthosts only offer AUTH LOGIN
domains = ["partner.example"]   # recipient domains that use this route
sources = ["10.10.5.128/25"]    # optional: source networks that use this route instead of the client's own

  [route.credentials]
  username = "relay@example.at"
  password = "${SMTPRELAYD_PARTNER_PASSWORD}"   # same three secret forms as any other secret
```

`plain`/`login` both require `credentials.username` and `credentials.password`
— a startup error otherwise. Credentials are refused outright on `tls =
"none"`: nothing hands a password or a token over an unencrypted connection.

**Pinning the smarthost's certificate** (optional, in addition to the normal
chain verification that is always on and has no disable switch): compute the
SHA-256 fingerprint of the certificate you want to require and set `ca_pin`.

```sh
openssl s_client -connect mail.partner.example:587 -starttls smtp -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```
```toml
ca_pin = "AA:BB:CC:...:FF"   # colons optional, case-insensitive
```
The fingerprint must match a certificate that was actually part of the chain
that verified, not merely one the smarthost happened to present alongside it.
`ca_pin` is meaningless (and a startup error) together with `tls = "none"`.

**A route with no TLS at all** (`tls = "none"`) is accepted only for a
smarthost reachable exclusively over a network segment you control end to
end; `auth` must then be `"none"` too, and `min_tls`/`ca_pin` must be absent.
A route that cannot negotiate the TLS it asked for **defers**, it never
silently downgrades to cleartext.

## 4. Routes — Microsoft 365

See `docs/MS365-AUTH.md` in full: Entra ID app registration, Exchange Online
mailbox permissions, the `[route.oauth2]` block, and all three ways to
provision `client_secret` with Linux and Windows steps side by side.

## 5. Multiple routes and recipient splitting

Recipient → route selection, in order: a route's `domains` matching the
recipient's domain, a route's `sources` matching the client's address if more
specific than the client's own CIDR, the route named by the client, then
whichever route has `default = true`. Recipients of one message that resolve
to different routes are split into one queue entry per route — no extra
configuration needed for that, it follows from the rules above.

## 6. Queue behaviour

```toml
[queue]
retry_schedule_min   = [1, 5, 15, 30, 60, 120]   # minutes between attempts, then the last interval repeats
max_lifetime_hours   = 96                        # message is bounced after this regardless of retries left
failed_retention_hours = 168                      # how long a permanently failed message's spool copy is kept
```
`failed_retention_hours = 0` keeps failed messages' spool files forever, which
counts against `limits.spool_max_gb` for as long as they sit there — only the
spool copy is deleted when it expires, the history row and every attempt
survive under `history.retention_days`.

## 7. Bounce notifications

```toml
[bounce]
sender         = "postmaster@example.at"   # empty envelope sender used on the wire
notify         = []                        # global recipients; empty disables bounce mail entirely
notify_route   = "m365"                    # which route sends the notification itself
digest_minutes = 15                        # batch failures into one message
max_per_hour   = 12                        # cap; excess is recorded in history but not mailed
```
Covers only failures the relay itself produced (a permanent 5xx, or expiry
after `max_lifetime_hours`) — a bounce Microsoft 365 generates after it
already accepted the message lands in the rewritten sender's own mailbox and
is invisible here. A client's `[client.bounce] notify` (section 2) overrides
this list for that client only.

## 8. Dashboard, API tokens, and the metrics endpoint

### Dashboard

```toml
[web]
address = "127.0.0.1:8025"
enabled = true
```
The dashboard has no login of its own — loopback binding **is** the
authentication, and a non-loopback `address` is a startup error with no
config override. For remote access, use an SSH tunnel or a reverse proxy that
authenticates in front of it.

Optional recolouring, every field optional, values must be literal
`#rgb`/`#rrggbb` hex (they are written into the stylesheet, so nothing else is
accepted):
```toml
[web.theme]
mode   = "dark"      # auto (default, follows the browser) | light | dark
accent = "#f5a524"
```
An override applies to light and dark alike, which is why recolouring beyond
the accent usually goes with pinning `mode`.

### API and metrics bearer tokens

There is no `token new` helper yet — generate and register one by hand. The
same `[[web.token]]` list authenticates both `/api/v1/*` (`docs/API.md`) and,
when the metrics listener is bound beyond loopback, `/metrics` too.

1. Generate a random token:
   ```sh
   openssl rand -base64 32
   ```
2. Compute its SHA-256 digest — only the digest is stored, never the token
   itself:
   ```sh
   printf '%s' 'the-generated-token' | sha256sum
   ```
3. Add it to the configuration:
   ```toml
   [[web.token]]
   name   = "checkmk"
   scope  = "read"       # "admin" additionally allows requeue and delete
   sha256 = "<digest from step 2>"
   ```
4. Validate and apply (top of this document).
5. Use it:
   ```sh
   curl -H "Authorization: Bearer the-generated-token" http://127.0.0.1:8025/api/v1/queue
   ```
6. Save the plaintext token somewhere recoverable (password manager) — it
   cannot be reconstructed from the configuration afterwards, only the digest
   lives there.

A malformed or missing token yields `401`; a valid token with insufficient
scope yields `403`; comparison is constant-time and failures are logged with
the source address and counted in `/metrics`.

### Metrics endpoint

```toml
[metrics]
address = "127.0.0.1:9025"
path    = "/metrics"
enabled = true
```
On loopback this is open and unauthenticated, for a monitoring agent running
on the same host. Bound beyond loopback it requires **both** a `[tls]`
certificate (section 1) **and** a `[[web.token]]` with at least `read` scope
— `check` refuses to start without either, so the two requirements cannot
drift apart. Prefer `/metrics` over the JSON API for monitoring: it needs no
token when local and carries queue depth, bounce counters, auth failures and
OAuth token age; use the API when the ticket text of one specific failure is
needed.

## 9. History and logging retention

```toml
[service]
timezone = "Europe/Vienna"   # optional; IANA name, or "UTC"/"Local"

[log]
file        = "smtprelayd.log"   # relative to data_dir; an absolute path or ".." is a startup error
max_size_mb = 50
max_backups = 10
max_age_days = 90

[history]
retention_days  = 90
retain_subjects = true   # subjects can carry personal data; off redacts them in the dashboard/API
```
Every accepted message is journalled regardless of `retain_subjects` —
envelope, client, route, listener, remote address, HELO, Message-ID,
Content-Type, size, header count, and one row per delivery attempt with its
verbatim SMTP response. The message body itself is never retained.

`service.timezone` controls how timestamps are *displayed* — the JSON log
lines' `time` field and every timestamp on the dashboard (queue, message
detail, search, bounces, route list). The history database still stores in
UTC either way, so the API's timestamps are unaffected. Leaving it unset
keeps the current behaviour: log lines in the process's own local time,
dashboard timestamps in UTC as stored. `check` rejects an unrecognised zone
name at startup rather than falling back to it silently.

## 10. Global limits

```toml
[limits]
max_message_mb   = 100   # ceiling; a client may lower it, never raise it
max_hops         = 25
max_headers      = 200
max_header_bytes = 262144
max_connections  = 200
read_timeout_sec  = 60
write_timeout_sec = 60
data_timeout_sec  = 300
spool_max_gb        = 10   # 0 = no quota; counts the live queue and spool/failed together
spool_warn_percent  = 80
```
These are the outer bounds every listener and client operates inside; see
`configs/smtprelayd.example.toml` for the full inline commentary on each
field.
