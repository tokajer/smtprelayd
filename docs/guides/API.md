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
`deferred`, `delivered`, `bounced`.

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

Current queue state per route: counts by state, oldest message age, last
successful delivery, current backoff.

### `GET /api/v1/messages/{queue_id}`

One message including every delivery attempt with its verbatim SMTP response.

### `POST /api/v1/messages/{queue_id}/requeue`

Scope `admin`. Moves a deferred or bounced message back to `incoming` and
resets its retry counter.

### `DELETE /api/v1/messages/{queue_id}`

Scope `admin`. Removes the message from the queue. History is retained.

### `GET /api/v1/health`

No authentication. Returns process status, uptime, version and whether every
route is currently able to authenticate.

## Checkmk

Prefer `/metrics` on the metrics listener for monitoring — it needs no token
and carries queue depth, bounce counters, authentication failures and OAuth
token age. Use this API when the ticket text of an individual failure is
needed, not just its count. See `docs/guides/CHECKMK.md` for wiring `/metrics` into
Checkmk, including ready-to-use agent plugins.
