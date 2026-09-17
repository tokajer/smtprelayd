# Configuration Guide

Step-by-step recipes for every configurable part of smtprelayd. Start from
`configs/smtprelayd.example.toml` — copy it to the path in the table below and
edit in place; every recipe here assumes that starting point rather than an
empty file. For the Microsoft 365 route specifically, `docs/guides/MS365-AUTH.md` has
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
`docs/guides/MS365-AUTH.md` step 2 walks through all three in detail; that walkthrough
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

Steps. Pick **1a** or **1b**, then continue at 2.

**1a. Self-signed, generated here.** For an internal listener with no CA
behind it, this is the whole step — set `cert_file` and `key_file` above to
where you want them, then:

```
smtprelayd -config /etc/smtprelayd/smtprelayd.toml gen-cert
```

It creates the directory, writes both files, and gives them the group and
modes the service account needs. Nothing else to do; go to step 3. Details
and caveats under *Self-signed certificates* below.

**1b. From a CA.** Obtain a certificate for the relay's hostname from
whatever CA the network already trusts (internal PKI, ACME, or a purchased
cert). smtprelayd never renews certificates.

2. Place `cert_file` and `key_file` on disk. The loader does not enforce
   permissions on these two paths the way it does for `file:` secrets, so set
   them the way `gen-cert` does: on Linux `root:smtprelayd`, directory `0750`
   and key `0640`, so the service account can read it and no other local
   account can; on Windows, put it inside the data directory so it inherits
   the protected ACL `SecureDataDir` sets there (see
   `docs/guides/MS365-AUTH.md`'s `file:` option for exactly how that inheritance
   works).
3. Validate and apply (see above) — `check` fails immediately with
   `tls.LoadX509KeyPair`'s own error if the pair does not parse or does not
   match.

The same `[tls]` pair is reused for a metrics listener bound beyond loopback
(section 8).

### Self-signed certificates: `gen-cert`

For an internal listener with no CA behind it, the relay can issue its own:

```
smtprelayd -config /etc/smtprelayd/smtprelayd.toml gen-cert
```

It writes to the `cert_file` and `key_file` paths the configuration already
names — it does not invent paths, so set those two first. Both the directory
and the files are created if absent.

**Permissions are handled for you.** On a server this command runs as root
while the service runs as its own account, so a key left `0600 root:root`
would be one the service cannot open — and that surfaces as a service which
refuses to start, saying nothing about permissions. `gen-cert` therefore
gives the directory (`0750`) and the key (`0640`) the group that owns the
configuration file, which the package already set to the service's group. The
key stays unreadable to every other local account. If it cannot do that — you
ran it as a user with no rights to that group — it prints the exact `chown`
and `chmod` to run instead of failing silently.

Deliberately, it **runs on a configuration that does not validate yet**. A
listener with `tls` set and no certificate on disk is exactly what `check`
refuses, so requiring a valid configuration first would make the command
useless for its own purpose. It prints the validation error as a warning,
writes the two files, and leaves any other fault for `check` to report
afterwards.

It **refuses to overwrite** an existing certificate or key. Pass `-force`
only when you are certain: these are the paths a CA-issued key lives at, and
overwriting one is not recoverable.

The subject alternative names are derived from the configuration and printed
so you can check them: `service.hostname`, every non-wildcard listener bind
address, the `metrics.address` when the metrics endpoint is enabled (it
serves this same certificate when bound beyond loopback, so a monitoring
system would otherwise fail hostname verification), plus `localhost`,
`127.0.0.1` and `::1`. Duplicates are collapsed. A wildcard bind (`0.0.0.0`,
`::`) contributes nothing, since it is not a name any client asks for.

If you add a listener or change `metrics.address` later, re-run it with
`-force` so the new name is covered.

Two limits worth knowing before you rely on it:

- The certificate is valid for **825 days**. You are warned three ways: by
  mail thirty days ahead if `bounce.notify` is configured (see *Expiry
  warnings* below), on the dashboard's Configuration page, and as
  `smtprelayd_expiry_seconds` on the metrics endpoint.
- It is signed by no CA. A device that verifies certificates must be given
  this one explicitly, or be configured not to verify. Devices that check
  nothing — most printers and MFPs — need no further action.

### Expiry warnings

Two things in this service expire on a date nobody is watching: the
listener's TLS certificate, and a Microsoft 365 client secret
(`oauth2.secret_expires`). Both failures are total — an expired certificate
refuses every TLS submission, an expired secret fails every delivery on that
route — so the relay mails about them.

```toml
[expiry]
warn_days = 30   # lead time; 0 switches the mails off
```

That is the only setting. The warning goes to the **`bounce.notify`**
contacts, from `bounce.sender`, over `bounce.notify_route` — the same contact
details a delivery-failure digest uses, so there is no second place to keep
addresses. With no `bounce.notify` set, nothing is sent and the expiry appears
only in the log.

Both deadlines are listed at the top of the dashboard's **Configuration**
page regardless of this setting, with a state of `ok`, `soon` or `expired`, so
you can see a healthy certificate rather than only hearing about an unhealthy
one. They are also exposed as `smtprelayd_expiry_seconds` on the metrics
endpoint (`docs/guides/CHECKMK.md`) — worth alerting on independently of the
mail, since a lapsed credential is exactly what stops mail working.

- `warn_days` accepts 0 to 3650. The default is 30, matching the threshold the
  startup log already used for client secrets.
- **To trigger one deliberately** — to check the mail path works — raise
  `warn_days` above the remaining lifetime (`warn_days = 900` against a
  freshly generated 825-day certificate), restart, and the mail goes out at
  once. Put it back afterwards. This is cheaper than reissuing a short-lived
  certificate and exercises exactly the same path.
- One mail per day at most while anything is inside the window, batching
  every affected item into a single message rather than one mail each.
- An expiry that has **already passed** is still reported, with `ACTION
  REQUIRED` in the subject — that is the case you most need to hear about.
- The check runs hourly and immediately at startup, so restarting a service
  whose certificate expires next week tells you now — and so a changed
  `warn_days` takes effect on the next restart without waiting.
- A certificate that cannot be read is logged, not mailed: the listener would
  not have started on one, so it means the file changed under a running
  service.

Unlike a bounce digest, these are not subject to `bounce.max_per_hour`. That
cap exists so a delivery-failure storm cannot become a mail storm; an expiry
warning is already limited to one a day and dropping it would defeat the
point of sending it.

This affects inbound listeners only. Outbound delivery to the smarthost
verifies against the system roots as always, and no option anywhere changes
that.

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

See `docs/guides/MS365-AUTH.md` in full: Entra ID app registration, Exchange Online
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

## 7. Bounce notifications and the canary probe

### Bounce notifications

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

### Canary

```toml
[[canary]]
name             = "m365-daily"       # unique; also the bounce-digest grouping key
recipient        = "ops@example.at"
sender           = "canary@example.at"
route            = "m365"
daily_at         = "07:00"            # every day at 07:00 UTC
# daily_at       = ["07:00", "19:30"] # or several fixed times a day
# interval_minutes = 1440             # or every n minutes instead -- never both
```
A periodic synthetic message the relay composes and sends itself, so an
operator (or a monitoring system) notices a working delivery path even
without real traffic. Zero or more `[[canary]]` blocks may be configured —
one per route worth watching independently, each with its own name,
recipient, sender and schedule; no block at all disables the feature
entirely. `name` must be unique, both among canaries and against every
configured `[[client]]` name (section 2): it is the same grouping key the
bounce digest already uses, so a collision would silently route a canary's
failures to that client's own `[client.bounce] notify` override instead of
the global list.

**The schedule is exactly one of `interval_minutes` or `daily_at`**; setting
both, or neither, is a startup error. `interval_minutes` sends every n
minutes counted from service start, so a restart shifts it. `daily_at` sends
at fixed times of day and a restart does not move them — write one time as
`"07:00"` or several as `["07:00", "19:30"]`, always two digits, a colon and
two digits on a 24-hour clock (`"7:00"` is refused rather than guessed at).

`daily_at` is **UTC**, deliberately and regardless of `service.timezone`:
that setting only ever changed how a timestamp is *displayed*, while this one
decides when mail is actually sent, and a zone with daylight saving has one
day a year with no 02:30 in it and another with two. In `Europe/Vienna`,
`"07:00"` UTC is 09:00 local in summer and 08:00 local in winter.

A scheduled time the machine slept through (suspend, or a large NTP step)
sends once, late, as soon as the service notices — a late canary is a signal,
while a silently skipped one looks exactly like the failure the canary exists
to detect. The next scheduled time is written to the log (`canary scheduled`)
after every send.

A failed canary is reported through `[bounce]` above rather than a second
alerting mechanism, so **`[bounce].notify` must be configured whenever any
`[[canary]]` is** — a canary with nowhere to report a failure to would
silently do nothing useful on the one path that matters. It does not,
however, share `[bounce]`'s digest window or volume cap: each canary send is
its own message, on its own schedule.

Also exposed on `/metrics` (section 8) for automated monitoring rather than
only a human noticing a missing email, labeled by `name`:
- `smtprelayd_canary_last_delivery_time{name="..."}` — a gauge, the Unix
  timestamp of that canary's last successful delivery. Absent until its
  first one. The useful alert is "this has not advanced in longer than the
  configured schedule's period plus a margin" — `interval_minutes`, or the
  longest gap between two `daily_at` times — which catches a route silently failing
  even while the canary keeps being queued.
- `smtprelayd_canary_failures_total{name="..."}` — a counter, incremented on
  any failed or deferred delivery attempt for that canary.

Neither counts toward the sending route's own `smtprelayd_delivered_total`,
`smtprelayd_bounced_total`, `smtprelayd_deferred_total` or
`smtprelayd_auth_failures_total` — a canary is diagnostic traffic, not
client traffic, and mixing the two would make the route's own health metrics
noisier without adding anything these two do not already say more precisely.

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

It is always served as plain **HTTP**, so reach it at `http://127.0.0.1:8025`
(and the JSON API, which shares this listener, at `http://127.0.0.1:8025/api/v1/…`).
Configuring `[tls]` for the SMTP listeners does not change this: since the
address can only ever be loopback, there is no name or address a certificate
could authenticate to. Use the tunnel or the reverse proxy for transport
security beyond this host.

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

#### Managing the queue

The queue page carries a bulk form. Tick individual messages, or use the
header checkbox to take every message on the page, then **Requeue selected**
(retry now, backoff reset) or **Delete selected** (spool copy removed, the
history row kept and still searchable). Ticking a box pauses the page's
ten-second auto-refresh so a selection cannot be swapped away mid-click; the
counter next to the buttons says so.

**Requeue whole queue** and **Delete whole queue** act on every message the
view lists, not only the current page, up to 1000 per submission — the banner
says if more remain. Deleting the whole queue asks for confirmation first;
requeueing does not.

A row marked *no spool copy* is listed in the history but has no message left
on disk (files deleted by hand, or dropped by a crash-recovery sweep at
startup). There is nothing to send, so requeue reports it as missing; delete
clears the entry from the view and marks the history row removed.

### API and metrics bearer tokens

The same `[[web.token]]` list authenticates both `/api/v1/*`
(`docs/guides/API.md`) and, when the metrics listener is bound beyond
loopback, `/metrics` too.

1. Generate one:
   ```sh
   smtprelayd token new                 # scope read
   smtprelayd -scope admin token new    # additionally allows requeue and delete
   ```
   It prints the token, its SHA-256 digest, a ready-to-paste `[[web.token]]`
   block and a working `curl` line. It reads no configuration and writes
   nothing, so it can be run anywhere, including before the relay is
   configured at all.

2. **Save the token now**, in a password manager. It is printed once and
   stored nowhere: only the digest goes into the configuration, so a leaked
   configuration file does not hand over a working credential — and neither
   can you recover the token from it later. Losing it means generating a new
   one and replacing the block.

3. Paste the printed block into the configuration and rename it after whoever
   will use it:
   ```toml
   [[web.token]]
   name   = "checkmk"
   scope  = "read"
   sha256 = "<the printed digest>"
   ```

4. Validate and apply (top of this document), then use the `curl` line the
   command printed.

To rotate a token, generate a new one and replace the `sha256` of that block;
to revoke one, delete the block. Both take effect at the next restart, since
the configuration is read once at startup. Several `[[web.token]]` entries may
coexist, which is how a rotation is done without an interruption: add the new
one, move the consumer over, then remove the old.

Doing it by hand instead is possible — `openssl rand -base64 32`, then
`printf '%s' '<token>' | sha256sum` — but the digest must be the digest of
exactly the bytes the caller will send, and a stray newline from `echo` is the
usual way that goes wrong.

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
needed. See `docs/guides/CHECKMK.md` for wiring this endpoint into Checkmk.

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

**If the service fails to start** because of a configuration error (a bad
`service.timezone` value, for example), `run` writes it to
`<data_dir>/smtprelayd-error.log` in addition to stderr/journalctl/the
Windows Event Log — deliberately a separate file from `log.file`, since a
configuration that just failed to validate cannot be trusted to correctly
name its own error log. `smtprelayd -config <file> check` still gives the
fastest turnaround for that same error, printed directly to stdout.

## 10. Global limits

```toml
[limits]
max_message_mb   = 100   # ceiling; a client may lower it, never raise it
max_hops         = 25
max_headers      = 200
max_header_bytes = 262144
max_connections  = 200
read_timeout_sec  = 60     # inbound, per command
write_timeout_sec = 60     # inbound, per reply
data_timeout_sec  = 300    # inbound, the whole DATA phase
delivery_timeout_sec = 600 # outbound, one whole attempt
spool_max_gb        = 10   # 0 = no quota; counts the live queue and spool/failed together
spool_warn_percent  = 80   # 0 = no warning; logs once per threshold crossing
```
These are the outer bounds every listener and client operates inside; see
`configs/smtprelayd.example.toml` for the full inline commentary on each
field.

The first three bound an **inbound** client connection and are reset on every
command or reply. `delivery_timeout_sec` is the **outbound** budget for one
complete delivery attempt — connect, TLS, SASL and the full DATA transfer to
the smarthost — set once and not extended.

They are separate because they measure different things. Until 2026-09-17 the
outbound attempt reused `write_timeout_sec`, which meant a 100 MB message had
60 seconds to reach the smarthost — about 14 Mbit/s sustained. Anything slower
failed, and because the failure is temporary it retried until
`queue.max_lifetime_hours` expired it. The loader now refuses a
`delivery_timeout_sec` that cannot carry `max_message_mb` at 1 MB/s plus
handshake, so the pair cannot be set into that state by accident.

`spool_warn_percent` is the early warning before `spool_max_gb` starts
rejecting mail. Once the spool reaches that share of the quota the delivery
manager logs `spool is filling up` at WARN with `used_bytes`, `max_bytes` and
`percent`; when it falls back under, `spool is back below the quota warning
threshold` at INFO. Only the two crossings are logged, never the steady state,
so the line stays greppable instead of repeating every five seconds.
