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

## Configuring the relay, step by step

Everything below is one procedure for both platforms; only paths and service
commands differ, so they are called out inline instead of duplicating the
whole section per OS. Defaults (overridden by `service.data_dir` in the
configuration, and by `-config` / `%ProgramData%` for the config file itself):

| | Linux | Windows |
|---|---|---|
| Config file | `/etc/smtprelayd/smtprelayd.toml` | `%ProgramData%\SMTPRelayd\smtprelayd.toml` |
| Data directory | `/var/lib/smtprelayd` | `%ProgramData%\SMTPRelayd` |
| Apply a change | `sudo systemctl restart smtprelayd` | `Restart-Service smtprelayd` (elevated) |

There is no live reload — the configuration is read once at startup — so every
step below ends the same way: validate, then restart.

### 1. Add the route

Edit the configuration and add a `[[route]]` with `auth = "xoauth2"` plus a
`[route.oauth2]` sub-table, using the tenant ID, client ID, mailbox and secret
expiry recorded in the Entra ID and Exchange Online steps above:

```toml
[[route]]
name    = "m365"
default = true
host    = "smtp.office365.com"
port    = 587
tls     = "starttls"
min_tls = "1.2"
auth    = "xoauth2"

  [route.oauth2]
  tenant_id      = "<tenant GUID>"
  client_id      = "<application (client) ID>"
  client_secret  = "<see step 2>"
  secret_expires = "<YYYY-MM-DD, the secret's expiry from Entra ID>"
  scope          = "https://outlook.office365.com/.default"
  mailbox        = "relay@example.at"
```

### 2. Provision the client secret

`client_secret` is never a literal value in the file — the loader rejects one
(`internal/config/config.go`). Pick exactly one of the three reference forms.

**Option A — `${ENV_VAR}`.** Practical on Linux via a systemd unit drop-in;
not recommended on Windows, where a service account has no reliable way to
pick up a machine environment variable without a reboot.

```ini
# /etc/systemd/system/smtprelayd.service.d/override.conf
[Service]
Environment=SMTPRELAYD_M365_SECRET=the-secret-value
```
```toml
client_secret = "${SMTPRELAYD_M365_SECRET}"
```
```sh
sudo systemctl daemon-reload
sudo systemctl restart smtprelayd
```

**Option B — `file:<path>`.** Works on both platforms. Plaintext at rest; the
protection is access control, not encryption — see `docs/SECURITY.md` §3.

- The file holds the secret and nothing else — no trailing label, a trailing
  newline is stripped automatically.
- Linux: must be owned by root or the service's own uid, mode with no
  group/other bits, and its containing directory must not be group- or
  world-writable (`internal/config/trust_unix.go`). Placing it in the data
  directory, already owned by the `smtprelayd` system user, is the simplest
  way to satisfy that:
  ```sh
  printf '%s' 'the-secret-value' | sudo tee /var/lib/smtprelayd/ms365.txt >/dev/null
  sudo chown smtprelayd:smtprelayd /var/lib/smtprelayd/ms365.txt
  sudo chmod 0600 /var/lib/smtprelayd/ms365.txt
  ```
  ```toml
  client_secret = "file:/var/lib/smtprelayd/ms365.txt"
  ```
- Windows: a file placed **inside** the data directory automatically inherits
  the protected DACL `SecureDataDir` sets there (SYSTEM, Administrators and
  `NT SERVICE\smtprelayd` only) — no `icacls` needed:
  ```powershell
  Set-Content -Path C:\ProgramData\SMTPRelayd\ms365.txt -Value 'the-secret-value' -NoNewline
  ```
  ```toml
  client_secret = 'file:C:\ProgramData\SMTPRelayd\ms365.txt'
  ```
  A file placed **outside** the data directory gets no automatic protection —
  `checkSecretFile` only refuses a symlink there — so it needs its own ACL:
  ```powershell
  icacls "C:\path\to\ms365.txt" /inheritance:r
  icacls "C:\path\to\ms365.txt" /grant "*S-1-5-18:F"                 # SYSTEM
  icacls "C:\path\to\ms365.txt" /grant "*S-1-5-32-544:F"              # Administrators
  icacls "C:\path\to\ms365.txt" /grant "NT SERVICE\smtprelayd:F"      # service account
  ```

**Option C — `dpapi:<path>` (Windows only).** Encrypts the secret with this
machine's DPAPI key, so a copy of the file is useless off this host; still
inside the data directory for the same inherited-ACL reason as option B.

```powershell
Get-Content C:\ProgramData\SMTPRelayd\ms365.txt -Raw |
    & "C:\Program Files\SMTPRelayd\smtprelayd.exe" `
        -out C:\ProgramData\SMTPRelayd\ms365.dpapi protect-secret
Remove-Item C:\ProgramData\SMTPRelayd\ms365.txt   # the plaintext is no longer needed
```
`-out` must precede the `protect-secret` command — flag parsing stops at the
first non-flag argument, same as `-config` on every other command.
```toml
client_secret = 'dpapi:C:\ProgramData\SMTPRelayd\ms365.dpapi'
```

### 3. Validate

```sh
smtprelayd -config <config path from the table above> check
```
Catches a bad `file:`/`dpapi:` path, an unset `${ENV_VAR}`, or an invalid
`secret_expires` before anything is restarted.

### 4. Apply

Restart the service (see the table above) — `check` only validates, it never
reloads the running process.

### 5. Verify

```sh
smtprelayd -config <config path> selftest   # fails loudly if it can relay from an unlisted address
```
Then send one real message through an allowlisted client and confirm it
leaves `spool/active` — via the dashboard's queue view, `journalctl -u
smtprelayd` / the Windows event log, or `smtprelayd.log` in the data
directory.

### 6. Rotating the secret later

Repeat step 2 with the new value under the same path (or a new one), update
`secret_expires`, then steps 3–4. `dpapi:` and `file:` both mean the new value
simply overwrites the old file; nothing else in the configuration changes.

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
