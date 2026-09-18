# HTTP API

Read-only by default, JSON throughout, bearer token authentication. Shares a
listener with the dashboard.

## Authentication

```
Authorization: Bearer <token>
```

Tokens are defined in the configuration with a scope of `read` or `admin`.
Requeue and delete require `admin`. Comparison is constant-time; failures are
logged with the source address and counted in `/metrics`.

Generate one with:

```sh
smtprelayd token new                 # scope read
smtprelayd -scope admin token new    # requeue and delete as well
```

It prints the token, its SHA-256 digest and a `[[web.token]]` block to paste.
Only the digest is stored, so the token is shown once and cannot be recovered
from the configuration — save it before closing the terminal. See
`docs/guides/CONFIGURATION.md` section 8 for rotation and revocation.

Missing or malformed token yields `401`, valid token with insufficient scope
yields `403`.

## Endpoints

### `GET /api/v1/bounces`

Messages the relay could not hand over to a smarthost.

| Parameter | Meaning |
|---|---|
| `since`, `until` | RFC 3339 timestamps, filter on last attempt |
| `recipient` | Substring match |
| `client` | Client name |
| `route` | Route name |
| `class` | `permanent` or `expired` |
| `limit` | Default 100, maximum 1000 |
| `cursor` | Opaque cursor from the previous response |

```json
{
  "bounces": [
    {
      "queue_id": "01J8ZQ2K9F3XA7B",
      "class": "permanent",
      "client": "printers-vienna",
      "route": "m365",
      "envelope_from": "relay@example.at",
      "original_from": "kopierer@local",
      "recipients": ["someone@partner.example"],
      "subject": "Scan 2026-08-07",
      "attempts": 1,
      "first_attempt": "2026-08-07T09:14:02Z",
      "last_attempt": "2026-08-07T09:14:03Z",
      "smtp_code": 550,
      "smtp_response": "5.1.1 User unknown"
    }
  ],
  "next_cursor": null
}
```

### `GET /api/v1/messages`

Full message history. Same filters plus `status` with values `queued`,
`deferred`, `delivered`, `bounced`, `removed` (discarded from the spool by an
operator via `DELETE /messages/{id}` before it reached an outcome).

```json
{
  "messages": [
    {
      "queue_id": "01J8ZQ2K9F3XA7B",
      "client": "printers-vienna",
      "route": "m365",
      "envelope_from": "relay@example.at",
      "original_from": "kopierer@local",
      "recipients": ["someone@partner.example"],
      "subject": "Scan 2026-08-07",
      "listener": "submission",
      "remote_addr": "10.20.1.44:51022",
      "received_at": "2026-08-07T09:14:01Z",
      "expires_at": "2026-08-11T09:14:01Z",
      "tls_used": true,
      "created_at": "2026-08-07T09:14:01Z",
      "message_id": "<4711@kopierer.local>",
      "content_type": "multipart/mixed; boundary=\"x\"",
      "size_bytes": 184320,
      "header_count": 12,
      "helo": "kopierer.local",
      "status": "bounced",
      "attempt_count": 1,
      "last_smtp_code": 550,
      "last_error": "5.1.1 User unknown"
    }
  ],
  "next_cursor": null
}
```

The journal fields (`message_id`, `content_type`, `size_bytes`,
`header_count`, `helo`) describe the message as it was spooled, not as it was
announced: the headers are read from the rewritten header block and the size
is what was actually written to disk, excluding the relay's own `Received`
header. They are omitted for a message recorded before the release that added
them, and `subject` stays redacted when `retain_subjects` is off.

`attempt_count`, `last_smtp_code` and `last_error` summarise the most recent
delivery attempt so that a list response needs no per-message follow-up
request; the full per-attempt history stays on
`GET /api/v1/messages/{queue_id}`.

### `GET /api/v1/queue`

Current queue state per route. Per entry: `queued` and `deferred` (messages
in the spool right now), `oldest_queued` and `last_delivery` (both omitted
when there is none), and the counters `delivered_total`, `bounced_total`,
`deferred_total`, `auth_failures_total` and `recipients_refused_total`. The
counters are since process start — the relay keeps no history of them — and
match the `smtprelayd_*_total` series on `/metrics` exactly.

`recipients_refused_total` counts recipients a smarthost refused permanently
on a message it accepted for the rest. Such a message is **delivered**, so it
appears in no failure counter: this is the only one that reports it. See
`docs/guides/CONFIGURATION.md` section 5.

There is no per-route backoff: the retry schedule applies to an individual
message, and `next_attempt_at` on `GET /api/v1/messages/{queue_id}` is where
it is reported.

### `GET /api/v1/messages/{queue_id}`

One message including every delivery attempt with its verbatim SMTP response.

### `POST /api/v1/messages/{queue_id}/requeue`

Scope `admin`. Moves a deferred or bounced message back to `incoming` and
resets its retry counter.

### `DELETE /api/v1/messages/{queue_id}`

Scope `admin`. Removes the message from the queue. History is retained.

Answers `{"status":"deleted"}` when a spool copy was removed, and
`{"status":"cleared"}` when there was none left but the history row still
said queued or deferred — that row is marked removed, which is what stops a
message with no files behind it from being listed as active forever. A queue
ID with no history row at all is still `404`.

### `GET /api/v1/health`

No authentication. Returns process status, uptime, version and whether every
route is currently able to authenticate.

## Checkmk

Prefer `/metrics` on the metrics listener for monitoring — it needs no token
and carries queue depth, bounce counters, authentication failures and OAuth
token age. Use this API when the ticket text of an individual failure is
needed, not just its count. See `docs/guides/CHECKMK.md` for wiring `/metrics` into
Checkmk, including ready-to-use agent plugins.
