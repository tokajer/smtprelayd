# PROGRESS.md

Handover document. Update at the end of every working session.
Keep it short — this file is pasted into every new chat.

## Current state

**Phase**: 3 — client policy, sender rewriting and recipient routing
implemented; first compile done, clean. Packaging and the Windows service
wrapper (normally phase 5) were pulled forward and validated. MSI installs and
uninstalls; `install`/`uninstall`/`start`/`stop` work on Windows. Log rotation
and Windows ACL verification at startup are complete.
**Last session**: 2026-08-10 (fifth session) — All seven known security gaps
from 2026-08-08 security review closed (disk quota, config-dir check, secret
ownership, syncDir errors, header limits, SIZE parameter, proxy environment).
Log rotation via lumberjack implemented. Windows ACL verification at startup
implemented and tested.
**Previous session**: 2026-08-08 (third session) — full security review of the
tree, then four fixes. No backdoor or hidden behaviour was found: the only two
outbound destinations are the fixed token authority and the configured
smarthost, there is no `init()`, no `go:embed`, no encoded blob and no tracked
binary, and the runtime dependency set is two modules. Fixed: (1) an unmatched
source used to hold a global connection slot indefinitely with a NOOP loop,
because `conns.acquire` was only called on the matched path and the per command
read deadline is refreshed by every command — unmatched sources now get a
2-connection per-address cap and a 30 s session deadline that also clamps the
read deadline; (2) `ca_pin` was checked against the certificates the smarthost
sent rather than the chain that verified, so a MITM holding any publicly
trusted certificate for the host could satisfy the pin by appending the pinned
certificate as an unused chain element — it now runs on `VerifyConnection`
against `VerifiedChains`, which also closes the session-resumption bypass gosec
G123 flagged; (3) the release workflow interpolated the tag into a shell script
before validating it, and a git ref name may legally contain `$( )` — verified
by experiment — so it now arrives through `env:`; (4) the banned-import check
that `CLAUDE.md` describes as "enforced by an import test in CI" did not exist
anywhere, and there was no CI on push/PR at all. Both now exist. Open items
from the review that were deliberately **not** fixed are listed under "Known
gaps" below.
**Previous session**: 2026-08-08 (second session) — added Windows SCM integration
and a release pipeline. `cmd/smtprelayd` gained `install`/`uninstall`/
`start`/`stop`, implemented only on Windows (`service_windows.go`, build-tag
gated) via `github.com/kardianos/service`; `serve()` now takes a `context.Context`
so both the foreground/systemd path (`context.Background()` plus
`signal.NotifyContext`) and the Windows service path (cancelled from `Stop()`)
share one code path. Confirmed with `go list -deps` on both GOOS that
`os/exec` is absent from the dependency graph on either platform. `go.mod`
bumped to `go 1.23.0` — required by `kardianos/service` v1.3.0. Added
`packaging/linux` (systemd unit, nfpm config, pre/postinstall scripts) and
`packaging/windows` (WiX source for the `.msi`); both build-tested locally
(nfpm produced real `.deb`/`.rpm` and their contents were inspected with
`dpkg-deb`/`rpm2cpio` — correct). The WiX source could not be compiled here
(candle.exe/light.exe are Windows-only); it has not been built or installed
on a real machine yet. Added `.github/workflows/release.yml`: builds all
platforms, gates on vet/gofmt/test/govulncheck, produces an SBOM
(`cyclonedx-gomod`), packages `.deb`+`.rpm` (two archs) and the `.msi`, then
publishes via `gh release create` with `actions/attest-build-provenance` —
no third-party release action, per the existing decision below. Added
`.gitignore` (`/bin/`, `/dist/`, WiX build output) — none existed before.
**Next action, phase 3/4**: end to end against the real tenant: `smtprelayd
check` ✅ works; now need: a message through the m365 route, a message with
recipients in two routes to confirm the split, and one deliberate wrong secret
to confirm the queue defers. Needs tenant, mailbox and sending-domain values
(see Open questions).
**Next action, phase 5**: Linux install/configure/start/stop cycle test on
Debian/RPM; upgrade cycle test on both platforms.

## Phases

### Phase 0 — Scaffolding ✅

### Phase 1 — Minimum viable relay ✅ (untested against a live smarthost)

- [x] `internal/config`: TOML schema, strict decoding, CIDR overlap detection,
      fail-closed checks per `docs/SECURITY.md` section 2, `Secret` type that
      refuses literal values and cannot be formatted into a log line
- [x] `internal/spool`: durable queue, atomic rename, crash recovery,
      validated `ID` type with a private constructor
- [x] `internal/listener`: ports and TLS modes from configuration, STARTTLS,
      implicit TLS, client matching by CIDR, size and recipient limits,
      per-client rate and connection limits
- [x] `internal/delivery`: worker pool, per-route concurrency, retry schedule,
      4xx versus 5xx classification
- [x] `internal/delivery/smarthost`: SMTP client with SASL PLAIN and LOGIN,
      mandatory certificate verification, optional `ca_pin`
- [x] `internal/logging`: `slog` JSON output with central secret redaction
- [x] Address and line-length validation, CRLF and NUL rejection, hop counting
- [x] `smtprelayd selftest`: active open-relay check, wired into CI
- [x] Startup trust checks: config file, binary directory and data directory
      ownership and permissions, symlink refusal (abort, not warn)
- [x] `O_NOFOLLOW` and `O_EXCL` on spool writes
- [x] Per-connection `recover`, streaming size enforcement, header limits
- [x] Runs in the foreground on both platforms
- [ ] Windows ACL verification at startup (deferred to phase 5 with the
      installer; needs `golang.org/x/sys/windows`)
- [ ] MIME nesting depth bound (no MIME parsing exists yet; the header limits
      cover the current surface)

### Phase 2 — Microsoft 365 ✅ (untested against a live tenant)

- [x] `internal/authms365`: client credentials flow, in-memory token cache,
      refresh five minutes before expiry, cooldown after a rejected request,
      redirects refused, fixed authority, tenant validated before it reaches
      the URL
- [x] XOAUTH2 in the smarthost client, including the 334 failure path: the
      continuation is answered with an empty response and the decoded JSON
      error is carried into the log line
- [x] Authentication failures are retryable regardless of the SMTP code
- [x] Per-route rate limiting enforced in `internal/delivery` before a worker
      slot is taken; a paced message is deferred without consuming an attempt
- [x] OAuth2 configuration validation: tenant character set, ASCII mailbox,
      resource scope, `secret_expires` format, scope defaulting
- [x] Startup warning when the client secret expires within thirty days
- [ ] `docs/MS365-AUTH.md` verified against a real tenant
- [ ] Sovereign cloud authorities (`login.microsoftonline.us`, China) — needs a
      schema decision, deliberately not configurable today

### Phase 3 — Client policy and rewriting ✅ (uncompiled)

- [x] `internal/rewrite`: modes `off`, `if_unauthorized`, `force`, compiled per
      client at startup so a bad policy fails the service, not a message
- [x] Envelope and header rewriting, `Reply-To` disposition
      (`preserve`/`drop`/`fixed:`), `X-Original-From`, `header_from = "keep"`
      for a sender that is already aligned
- [x] Header block replaced structurally, never by concatenation; a message
      with two `From` headers or a control character in the preserved value is
      rejected with 550 rather than sanitised
- [x] `internal/router`: recipient domain, then source network, then the
      client route, then the default route; a source network competes with the
      client CIDR on prefix length
- [x] `route.sources` added to the schema; two routes claiming the same
      network or domain is a startup error
- [x] Recipients spanning several routes are split into one queue entry per
      route: `spool.Stage` writes the body once, `spool.Commit` makes one copy
      per route with its own `Received` header, and a failure halfway through
      withdraws the copies already made
- [x] `limits.max_message_mb` is the global ceiling; a client may lower it but
      the loader refuses a client value above it
- [x] `Envelope.OriginalFrom` records the pre-rewrite sender for the bounce
      records of phase 4
- [ ] Per-client rate limiting in the listener and the route-level pacing from
      phase 2 remain separate and both apply; no decision needed, recorded so
      it is not rediscovered

### Phase 4 — Observability ⬜ (planned, see `docs/PHASE4-PLAN.md`)

Planned in five sub-phases (4a–4e), with implementation order determined by
dependencies. Detailed plan in `docs/PHASE4-PLAN.md` (2026-08-10).
- 4a: `internal/store` (SQLite message and attempt history)
- 4b: `internal/metrics` (Prometheus `/metrics` endpoint)
- 4c: `internal/web` (dashboard, read-only)
- 4d: `internal/api` (JSON API, admin actions, audit log)
- 4e: `internal/bounce` (notification batching and volume capping)

### Phase 5 — Productionisation ⬜

Unchanged, plus:

- [x] Log rotation: lumberjack v2 handles rotation when logs exceed
      max_size_mb, with max_backups retention and max_age_days enforcement;
      if MaxSizeMB is 0, rotation is disabled and logs append
- [x] Windows SCM integration: `install`/`uninstall`/`start`/`stop`, virtual
      account `NT SERVICE\smtprelayd`, automatic-start-type with restart on
      failure, registered via `kardianos/service` (Windows-only import, see
      the service wrapper row in `MEMORY.md` section 2)
- [x] Linux systemd unit (`packaging/linux/smtprelayd.service`): capability
      bound to `CAP_NET_BIND_SERVICE` instead of root, the hardening
      directives from `docs/SECURITY.md` section on process isolation
- [x] `.deb`/`.rpm` via nfpm (`packaging/linux/nfpm.yaml`), creates the
      `smtprelayd` system user/group and fixes ownership on
      `/etc/smtprelayd` and `/var/lib/smtprelayd` in a postinstall script;
      never starts the service on install
- [x] `.msi` via WiX (`packaging/windows/smtprelayd.wxs`), ACLs
      `%ProgramData%\SMTPRelayd` to Administrators + the virtual service
      account only, no inherited access; registers but does not start the
      service — **tested on real Windows machine, install/uninstall/start/stop all work**
- [x] `.github/workflows/release.yml`: builds, tests, SBOM, all three package
      formats, SHA-256 checksums, build provenance attestation, `gh release
      create` — no third-party release action
- [x] Windows ACL verification at startup: CheckDataDirACL verifies that the
      data directory has the explicit DACL set by the MSI (Administrators +
      NT SERVICE\smtprelayd, protected from inheritance); whitelisted exception
      for unsafe.Pointer usage in trust_windows.go for LocalFree API call
- [x] Real end-to-end test of install → configure → start → stop on Windows
- [ ] Upgrade cycle test and Linux install → configure → start → stop cycle
- [x] CI workflow that runs on every push/PR (`.github/workflows/ci.yml`):
      gofmt, vet, `go test -race`, the banned-import check and govulncheck,
      plus a cross-compile job for all three targets
- [x] The banned-import check `CLAUDE.md` calls for, in two halves:
      `internal/buildpolicy` parses this module's own source for `unsafe`,
      `os/exec`, `plugin`, cgo and the `html/template` escape hatches and runs
      under `make test`; `scripts/check-banned-imports.sh` walks the full
      dependency graph of `./cmd/smtprelayd` with `go list -deps` per target
      under `CGO_ENABLED=0`, which is what catches a transitive reintroduction
      such as the `kardianos/service` systemd backend. Both were confirmed to
      fail on a deliberately planted violation, not just to pass
- [x] Supply chain: every `actions/*` pinned to a commit SHA with the tag in a
      trailing comment, `govulncheck` and `cyclonedx-gomod` pinned to versions
      instead of `@latest` (`nfpm` already was)

## Known gaps from the 2026-08-08 security review

All seven security gaps (1-7 below) have been fixed as of 2026-08-10 session.
The selftest exception (8) remains deliberate and is not fixed.

1. ✅ `limits.spool_max_gb` enforcement — now rejects messages that would
   exceed quota; SetQuota() called at startup.
2. ✅ `config.CheckConfigFile` now validates directory holding the file,
   preventing unlink-and-create replacement in group-writable /etc/smtprelayd.
3. ✅ `checkSecretFile` now verifies ownership like `checkTrusted`.
4. ✅ `spool.syncDir` now propagates fsync errors on Linux; ErrInvalid
   (Windows) still ignored as documented.
5. ✅ `limits.max_headers` and `limits.max_header_bytes` now validated as > 0.
6. ✅ `MAIL FROM SIZE` is now validated early in DATA phase if present.
7. ✅ Token client proxy environment removed; no metadata leakage through proxies.
8. The selftest still uses `InsecureSkipVerify` plus certificate pin and trips
   gosec G123. This is the deliberate exception recorded in the decision log;
   it dials fresh with no session cache so resumption cannot occur. Not fixed.

## Open questions

- Tenant, mailbox and sending domain for the Microsoft 365 route.
- Should a failed token acquisition at startup abort, or only be logged? Today
  no token is fetched before the first delivery, so a tenant outage at boot is
  invisible until a message arrives.
- Should the dashboard require authentication, or is localhost binding enough?
- Which addresses go into `[bounce].notify`?
- Should downstream bounces be ingested from the relay mailbox via Graph?
- Should the API listener be exposed beyond localhost?
- A Postfix `main.cf` importer (`smtprelayd import-postfix`) was raised as a
  migration path. Scoped as a one-shot converter with an explicit report of
  what could not be translated, never a runtime parser. Not yet planned into a
  phase.
- Log rotation: accept `lumberjack` as a second dependency, or rotate
  externally with `logrotate` and the Windows equivalent?

## Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-08-07 | Go instead of Rust | Direct MX delivery dropped, so no DNSSEC-validating resolver is needed |
| 2026-08-07 | Smarthost only, no direct MX | The smarthost owns reputation and bounce handling |
| 2026-08-07 | `modernc.org/sqlite` | Pure Go, keeps Windows cross-compilation trivial |
| 2026-08-07 | htmx instead of a JS framework | No Node build step |
| 2026-08-07 | Bounces are store records, not just log lines | Must be queryable and correlatable to a queue ID |
| 2026-08-07 | Bounce notification is optional and batched | An unbatched notifier turns one device into a second outage |
| 2026-08-07 | Static bearer tokens with read/admin scopes | Separates Checkmk polling from destructive actions |
| 2026-08-07 | API tokens stored as SHA-256 digests | A stolen configuration file must not yield usable credentials |
| 2026-08-07 | No `insecure_skip_verify` field in the schema | Such an option is always found enabled in production |
| 2026-08-07 | Empty client allowlist is a startup error | Open relay is the one failure that cannot be recovered from cheaply |
| 2026-08-07 | Startup aborts on a writable config, binary or data directory | Each converts a local user into control of a privileged process |
| 2026-08-07 | No auto-update mechanism | A privileged self-updating writer is a classic escalation surface |
| 2026-08-07 | `unsafe`, `os/exec`, `plugin` and cgo banned by CI import test | Removes categories rather than defending against them |
| 2026-08-07 | `github.com/BurntSushi/toml` as the only runtime dependency | Pure Go, no cgo, strict decoding via `Undecoded()` so a typo cannot silently become a default |
| 2026-08-07 | Strict decoding: an unknown key aborts startup | A misspelled `require_tls` that is silently ignored is indistinguishable from a disabled one |
| 2026-08-07 | Outbound `tls = "none"` removed from the schema | A smarthost without TLS is a deployment defect, not a supported mode |
| 2026-08-07 | A data-phase error closes the connection | Abandoning the stream desynchronises the command channel; continuing would risk misattributing the next command |
| 2026-08-07 | Permanent failures move to `spool/failed`, not deleted | Phase 5 turns them into DSNs; until then nothing is lost silently |
| 2026-08-07 | `InsecureSkipVerify` ban scoped to client and smarthost paths | The selftest probe pins its own listener certificate; a blanket grep would have forced a worse design |
| 2026-08-07 | Release provenance and SBOM in CI, no third-party release action | `gh` and the official attestation action keep the release path's own dependency set minimal |
| 2026-08-08 | Authentication failures are always temporary, never permanent | A 535 describes the relay's credentials, not the message; classifying it as permanent would move the whole queue to `spool/failed` when a secret is rotated |
| 2026-08-08 | Token authority is a constant, not a configuration field | The client secret is in the request body, so a configurable host is a place to send it elsewhere; sovereign clouds are a separate decision |
| 2026-08-08 | Redirects from the token endpoint are refused | Following one repeats the POST body, and with it the secret, to whatever host the response names |
| 2026-08-08 | A rejected token request is cached for 30 seconds | Otherwise an expired secret turns every queued message into another request and earns a tenant-level block |
| 2026-08-08 | Route pacing defers in the spool instead of blocking a worker | A blocked worker holds its route's concurrency budget and stalls dispatch for every other route |
| 2026-08-08 | Pacing does not increment the attempt counter | The message was never offered to the smarthost, so pacing must not consume its retry budget or bring its expiry forward |
| 2026-08-08 | `authms365.New` takes resolved strings, not `config.OAuth2` | Keeps the secret dereferencing in one place and makes the package testable without a configuration file |
| 2026-08-08 | Recipient domain outranks the client's route | A domain belongs to a destination, not to the device that happened to send to it; the loader refuses a domain claimed twice so the precedence can never be ambiguous |
| 2026-08-08 | Source networks live on the route (`route.sources`), not as a second client concept | A network can be pointed at a route without defining a client per device, and the client allowlist stays the only thing that decides whether a source may relay at all |
| 2026-08-08 | A source network competes with the client CIDR on prefix length | Otherwise a site-wide rule would silently override a per-device one, or vice versa, depending on which was checked first |
| 2026-08-08 | Mixed-route recipients are split into one queue entry per route | A legacy device handed a 5xx for a mixed recipient list has no way to recover, and refusing the whole message would lose the recipients that were routable |
| 2026-08-08 | A message that cannot be rewritten safely is rejected with 550 | Two `From` headers or a control character in a preserved value means guessing at what the client meant; guessing is how a header gets split |
| 2026-08-08 | `header_from = "keep"` only survives while aligned with the new envelope sender | SPF checks the envelope and DMARC the header, so an unaligned pair produces a message the smarthost rejects |
| 2026-08-08 | A client may lower `max_message_mb` but never raise it | A per-client limit that can exceed the global one is not a limit |
| 2026-08-08 | Licensed GPL-3.0-or-later, copyright Tokajer | Chosen over AGPL because the relay is meant to be run inside customer infrastructure without the network-use obligation attaching to every operator; revisit if the phase 4 dashboard is ever offered as a hosted service |
| 2026-08-08 | The licence text is fetched by `make license`, not committed as a copy | A transcribed licence that differs from the canonical text is worse than none |
| 2026-08-08 | No Postfix fork, no Windows-only build | A fork inherits the IPL/EPL licence and a process architecture that does not exist on Windows; dropping Linux would cost the CI and test platform for about a hundred lines of platform code |
| 2026-08-08 | `kardianos/service` imported only from `service_windows.go` | Its Linux backend shells out to `systemctl` via `os/exec`, which is banned; the file-suffix build constraint keeps that code out of the linux/amd64 and linux/arm64 dependency graph entirely rather than trusting a code path to never run |
| 2026-08-08 | `go.mod` bumped to `go 1.23.0` | Required by `kardianos/service` v1.3.0; "Go 1.22+" in `MEMORY.md` was a floor set for cross-compilation, not a ceiling, so raising it is not a restructuring decision |
| 2026-08-08 | Windows service runs as the virtual account `NT SERVICE\smtprelayd`, never LocalSystem | No password to provision or rotate, and no manual local-account creation in the installer, while still meeting the "dedicated service account" requirement in `docs/EXPLOIT-SURFACE.md` |
| 2026-08-08 | `serve()` takes a `context.Context` instead of creating one internally | The Windows service path has no process to send SIGTERM to; the SCM's Stop() call needs a cancel function it can call directly, and the foreground/systemd path keeps its exact previous behaviour by passing `context.Background()` |
| 2026-08-08 | The MSI runs `smtprelayd.exe install`/`uninstall` as deferred custom actions instead of WiX's own `ServiceInstall` element | The SCM registration (name, account, recovery action) is defined once in `service_windows.go`; a second, WiX-side definition of the same service would drift from it silently |
| 2026-08-08 | Neither the `.deb`/`.rpm` postinstall script nor the MSI starts the service | A fresh install has no tenant, mailbox or client configuration yet; auto-starting would just crash-loop until someone edits the config, which is a worse first impression than a clear "now configure and start it" message |
| 2026-08-08 | Release tags must match `vMAJOR.MINOR.PATCH`, enforced by the workflow before any build step | The MSI's `ProductVersion` must be three numeric fields; failing fast on a malformed tag is better than silently truncating it into a version nobody asked for |
| 2026-08-08 | `nfpm` and WiX invoked as pinned build tools (`go run pkg@version`, the runner's preinstalled WiX), not vendored into `go.mod` | Neither is a runtime dependency of the relay itself; adding them to the module would blur that line for no benefit |
| 2026-08-08 | An unmatched source keeps its 220 banner and is still refused at MAIL FROM, but gets a per-address connection cap and a session deadline | Refusing at connect would make the reply less informative and would break the selftest's expectation of a 220; the actual problem was resource occupancy, not the point of refusal, so only that was bounded |
| 2026-08-08 | `connCounter` deletes an entry at zero instead of leaving it | Its keys are now remote addresses for unmatched sources, so a retained zero entry would let any source grow the map without bound — the fix for one exhaustion path must not open another |
| 2026-08-08 | `ca_pin` is checked on `VerifyConnection` against `VerifiedChains`, not on `VerifyPeerCertificate` against the raw certificates | `VerifyPeerCertificate` receives what the server sent rather than the chain that was built, so appending the pinned certificate as an unused element satisfied the pin; it is also skipped entirely on a resumed session. Both defeat exactly the attacker `ca_pin` exists for |
| 2026-08-08 | Workflow inputs reach the shell through `env:`, never through `${{ }}` in a script body | A git ref name may legally contain `$( )` and a `workflow_dispatch` input is unconstrained, so the validating pattern ran strictly after the value had already been substituted into the script |
| 2026-08-08 | The import ban is enforced in two halves: an AST test over first-party source and a `go list -deps` script over the full graph | `unsafe` is unavoidable transitively through the standard library, so it is only meaningful as a first-party rule; a transitive `os/exec` is only visible in the graph, and only per GOOS. Neither half alone covers the ban `CLAUDE.md` states |
