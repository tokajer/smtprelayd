# Monitoring with Checkmk

`smtprelayd` exposes a Prometheus-format metrics endpoint specifically so
that Checkmk can watch it. This guide covers enabling that endpoint,
wiring it into Checkmk, and what to alert on. It assumes `docs/guides/CONFIGURATION.md`
section 8 (dashboard, API tokens, the metrics endpoint) has already been read.

## 1. What is exposed

`GET /metrics` on the address configured under `[metrics]` returns Prometheus
text exposition format:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `smtprelayd_queue_size` | gauge | `route`, `state=queued\|deferred` | Messages currently spooled |
| `smtprelayd_delivered_total` | counter | `route` | Successful deliveries |
| `smtprelayd_bounced_total` | counter | `route` | Permanent failures and expiries |
| `smtprelayd_deferred_total` | counter | `route` | Temporary failures retried |
| `smtprelayd_auth_failures_total` | counter | `route` | Delivery attempts rejected for the relay's own credentials |
| `smtprelayd_oauth_token_age_seconds` | gauge | `route` | Age of the cached OAuth2 token; absent until a token has been issued, absent entirely for non-XOAUTH2 routes |
| `smtprelayd_last_delivery_time` | gauge | `route` | Unix timestamp of the last successful delivery; absent until the first one |
| `smtprelayd_delivery_rate_per_minute` | gauge | `route` | `delivered_total` / process uptime, not a rolling window (see `internal/metrics/metrics.go`) |
| `smtprelayd_api_auth_failures_total` | counter | — | Rejected bearer tokens on `/api/v1/*` and `/metrics` itself |
| `smtprelayd_notification_failures_total` | counter | — | Bounce-digest notification messages that themselves failed to send |
| `smtprelayd_canary_last_delivery_time` | gauge | `name` | Unix timestamp of that canary's last successful delivery; absent until its first one, or if no `[[canary]]` with that name is configured. Alert on this going stale, not on the counter below — a route can stop delivering silently while its canary keeps being queued |
| `smtprelayd_canary_failures_total` | counter | `name` | That canary's delivery attempts that failed, permanently, by expiry, or deferred for retry |

Every route configured at startup is seeded with zero counters, so a route
that has never delivered still appears rather than being silently absent.

## 2. Two deployment shapes

**Loopback (the default, and the one to prefer):** `[metrics].address` bound
to `127.0.0.1` or `::1`. The endpoint is open, unencrypted and needs no
token — the Checkmk agent runs on the same host as `smtprelayd`, and the
process boundary is the access control. This is the shape the plugin in
section 3 is written for.

**Beyond loopback:** only needed if the Checkmk site polls the relay
remotely instead of through a local agent. `config.Validate` refuses such an
address unless both a `[tls]` certificate and a `[[web.token]]` with at
least `read` scope exist — see `docs/guides/CONFIGURATION.md` section 8 for
provisioning one. Point the same integration at `https://<host>:<port>/metrics`
with `Authorization: Bearer <token>`.

## 3. Recommended: a Checkmk agent local check

This is the integration the endpoint was designed around (see the
`Registry` doc comment in `internal/metrics/metrics.go`): the Checkmk agent
polling continuously on the same host `smtprelayd` runs on. It needs no
Checkmk-side configuration beyond service discovery, works identically
across Checkmk versions and editions, and keeps working if the site is ever
moved off Prometheus entirely.

Ready-to-use plugins are in `contrib/checkmk/` in this repository:

- `smtprelayd_metrics` — POSIX `sh` + `awk` + `curl`, for the Linux agent.
- `smtprelayd_metrics.ps1` — PowerShell, for the Windows agent.

Both curl/request the configured `/metrics` URL, turn the exposition into
Checkmk local-check services, and keep a small state file so that counters
(bounces, auth failures) are reported as **deltas since the previous check**
rather than as ever-growing totals — a rising total is not itself
actionable, a sudden increase is.

### Linux

```sh
sudo cp contrib/checkmk/smtprelayd_metrics /usr/lib/check_mk_agent/local/smtprelayd_metrics
sudo chmod 0755 /usr/lib/check_mk_agent/local/smtprelayd_metrics
```

Confirm the agent picks it up:

```sh
sudo check_mk_agent | grep -A20 '<<<local>>>'
```

### Windows

```powershell
Copy-Item contrib\checkmk\smtprelayd_metrics.ps1 `
  'C:\ProgramData\checkmk\agent\local\smtprelayd_metrics.ps1'
```

The Windows agent runs `.ps1` files placed there directly; no separate
registration step. Confirm with the agent's own check/debug output (Checkmk
Agent Bakery or `CheckMKAgent.exe -Debug`, depending on agent version).

### Then, in Checkmk

Run service discovery on the host (`Setup > Hosts > <host> > Service
discovery`, or `cmk -II <hostname>`). One service per route appears for
queue depth, delivery/bounces and auth/token state, plus two host-wide
services for API and notification auth failures. Accept and activate the
changes as usual.

### Configuration

Both scripts read the same set of environment variables, so behaviour stays
identical across platforms. All are optional; shown values are the built-in
defaults:

| Variable | Default | Meaning |
|---|---|---|
| `SMTPRELAYD_METRICS_URL` | `http://127.0.0.1:9025/metrics` | Must match `[metrics].address`/`.path` |
| `SMTPRELAYD_METRICS_TOKEN` | *(empty)* | Only needed for a non-loopback `[metrics].address` |
| `SMTPRELAYD_QUEUE_WARN` / `_CRIT` | 200 / 1000 | Queued message count per route |
| `SMTPRELAYD_DEFERRED_WARN` / `_CRIT` | 50 / 200 | Deferred message count per route |
| `SMTPRELAYD_BOUNCE_WARN` / `_CRIT` | 1 / 5 | New bounces since the last check, per route |
| `SMTPRELAYD_AUTHFAIL_WARN` / `_CRIT` | 1 / 3 | New auth failures since the last check, per route |
| `SMTPRELAYD_TOKEN_AGE_WARN` / `_CRIT` | 3300 / 3600 (s) | Cached OAuth2 token age; see section 4 for why |
| `SMTPRELAYD_API_AUTHFAIL_WARN` / `_CRIT` | 1 / 5 | New rejected bearer tokens since the last check |
| `SMTPRELAYD_NOTIFYFAIL_WARN` / `_CRIT` | 1 / 3 | New failed bounce-digest sends since the last check |
| `SMTPRELAYD_STATE_DIR` | `/var/lib/check_mk_agent/state` (Linux)<br>`C:\ProgramData\checkmk\agent\state` (Windows) | Where the delta-tracking state file lives |

Set them wherever this Checkmk site already manages agent plugin
environment (e.g. `/etc/check_mk/smtprelayd_metrics.env`, sourced by the
agent's plugin environment mechanism, or a machine environment variable on
Windows).

The first run after installing the plugin establishes a baseline: counters
report zero new events even if the lifetime totals are nonzero, since there
is nothing yet to compare against.

## 4. Threshold rationale

- **Queue/deferred depth** — defaults assume the load profile in `MEMORY.md`
  (roughly 0.1 msg/s average, a few thousand messages/day). Raise these for
  a busier deployment, or lower them for a route that should never
  accumulate a backlog at all.
- **Bounces and auth failures** — reported as deltas, not totals, and default
  to warning on the first occurrence: a relay's own credentials failing, or
  a message being permanently rejected, is always worth a look even if it
  is not yet an outage.
- **OAuth token age** — Microsoft Entra ID access tokens are typically valid
  60–90 minutes; `internal/authms365` refreshes roughly 5 minutes before
  expiry (`MEMORY.md` section 6). An age climbing past the warn threshold
  without resetting means the refresh itself is stuck, not that the token
  is merely old — a fresh token should never approach its own expiry.
- **`smtprelayd_last_delivery_time`** is reported as an informational age
  with no default threshold: an idle route is not necessarily a broken one,
  and how long "too quiet" is depends entirely on that route's expected
  traffic. Set `SMTPRELAYD_LAST_DELIVERY_WARN`-style thresholds yourself if
  a route has predictable traffic — this is deliberately left as a follow-up
  to the plugin scripts, per-route, rather than a global default that would
  be wrong for most deployments.

## 5. Alternative: Checkmk's built-in Prometheus special agent

If this Checkmk site already scrapes other services through a central
Prometheus server, `/metrics` can be added as another scrape target there
and picked up by Checkmk's `Prometheus` special agent (`Setup > Agents >
Other integrations`, or the equivalent path in Checkmk's monitoring-rule
tree — this has moved across Checkmk versions, follow Checkmk's own current
documentation for the exact steps). Two things to plan for if this route is
used instead:

- The special agent talks to the Prometheus server's HTTP API, not to
  `smtprelayd` directly — a Prometheus server (or the exporters-direct mode
  some Checkmk versions offer) has to already be scraping `/metrics` on a
  schedule.
- `/metrics` beyond loopback needs the TLS-and-token setup from section 2,
  since the Prometheus scraper is then a remote client from `smtprelayd`'s
  point of view.

For a deployment with no existing Prometheus server, the local check in
section 3 is simpler, has one fewer moving part, and is what this project's
own metrics endpoint design assumed.

## 6. Complementary: a plain liveness check

`GET /api/v1/health` needs no authentication and returns process status,
uptime, version and whether every route can currently authenticate
(`docs/guides/API.md`). A classic Checkmk `HTTP` service check
(`Setup > Hosts > <host> > check_http`/`check_httpx`) against that URL is a
useful, independent complement to the metrics plugin: if `smtprelayd` itself
is down, the metrics plugin already reports that (state 2, "could not
reach"), but a separate HTTP check confirms the same thing without
depending on the plugin's own correctness.
