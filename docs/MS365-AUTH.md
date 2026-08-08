# Microsoft 365 Authentication

Verify these steps against current Microsoft documentation before rollout —
Microsoft has changed SMTP authentication requirements repeatedly.

## Chosen approach: OAuth2 client credentials with XOAUTH2

No user interaction, no stored password, no MFA conflict. This is the only
approach Microsoft still recommends for unattended SMTP submission.

### Entra ID setup

1. Register an application in Entra ID. Record the tenant ID and client ID.
2. Create a client secret. Note its expiry — the relay must surface an alert
   before it lapses.
3. Add the **application** permission `SMTP.SendAsApp` under
   *Office 365 Exchange Online*. Not a delegated permission.
4. Grant admin consent.

### Exchange Online setup

Register the service principal and grant it access to the sending mailbox:

```powershell
Connect-ExchangeOnline

New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id>

Add-MailboxPermission -Identity "relay@example.at" `
    -User <enterprise-app-object-id> -AccessRights FullAccess
```

Ensure SMTP AUTH is enabled for the mailbox:

```powershell
Set-CASMailbox -Identity "relay@example.at" -SmtpClientAuthenticationDisabled $false
```

It may also need to be enabled tenant-wide in the Exchange admin centre.

### Token acquisition

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
grant_type=client_credentials
client_id={client_id}
client_secret={client_secret}
scope=https://outlook.office365.com/.default
```

Tokens are valid for roughly one hour. Cache in memory, refresh about five
minutes before expiry, never write to disk.

### SMTP handshake

Connect to `smtp.office365.com:587`, issue `STARTTLS`, then:

```
AUTH XOAUTH2 <base64>
```

where the decoded payload is:

```
user=relay@example.at\x01auth=Bearer <access_token>\x01\x01
```

On failure Microsoft returns a base64-encoded JSON error. Decode it before
logging — the raw blob is useless in a log file.

### Throttling

- Roughly 10 concurrent connections per mailbox.
- Roughly 30 messages per minute per connection.
- A daily recipient limit applies per mailbox; check the current tenant value.

Configure `max_concurrent` and `rate_limit_per_min` conservatively. Treat
`4.7.x` throttling responses as retryable, not as failures.

### Common errors

| Response | Cause |
|---|---|
| `5.7.57` not authenticated | AUTH not completed, or STARTTLS missing |
| `5.7.60` SendAsDenied | Sender is not the authenticated mailbox — this is what sender rewriting solves |
| `5.7.139` not allowed | SMTP AUTH disabled for the mailbox or the tenant |
| `4.7.500` server busy | Throttling — back off and retry |

## How the relay implements this

`internal/authms365` holds one `TokenSource` per route with `auth = "xoauth2"`.

- The authority is the compile-time constant `login.microsoftonline.com`. It is
  not configurable, because the client secret travels in the request body and a
  configurable host is a place to send it somewhere else. Sovereign clouds
  would need a schema decision first.
- The tenant is validated against a GUID or domain-name character set before it
  is placed in the URL path, so it cannot add or traverse a path segment.
- Redirects from the token endpoint are refused rather than followed: a
  redirect would repeat the POST body, and with it the secret.
- Tokens are cached in memory and renewed five minutes before expiry. Callers
  are serialised, so a burst of delivery workers produces one token request.
- A rejected token request is cached for thirty seconds. Without that, a
  rotated secret would turn every queued message into another request to the
  token endpoint.
- A failed refresh does not discard a token that is still inside its lifetime.
- The access token is rejected if it contains anything outside printable ASCII,
  because it is concatenated into the SASL payload around `\x01` separators.
  The mailbox is checked the same way, at configuration load time.
- An authentication failure is always retryable, whatever the SMTP code. A 535
  says something about the relay's credentials, never about the message;
  treating it as permanent would move the entire queue to `spool/failed` the
  moment a secret expires.
- `oauth2.secret_expires` is validated as `YYYY-MM-DD` and logged as a warning
  at startup within thirty days of expiry. Phase 4 turns it into a metric.

Outbound pacing is per route: `rate_limit_per_min` is enforced in
`internal/delivery` before a worker slot is taken, and a paced message is
deferred in the spool without consuming a retry attempt.

## Alternatives, not implemented

**High Volume Email** — `smtp-hve.office365.com:587`, dedicated HVE accounts,
intended for internal bulk mail. Simpler credentials but its own limits and
licensing considerations.

**Connector / direct send** — no authentication, the tenant trusts a static
public IP with a matching certificate. Removes token handling entirely but
requires a fixed external IP and careful connector scoping to avoid an open
relay path into the tenant.
