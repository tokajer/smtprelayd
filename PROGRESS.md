# PROGRESS.md

Handover document. Update at the end of every working session.
Keep it short — this file is pasted into every new chat.

## Current state

**Phase**: 4e — `internal/bounce` (digest notification) implemented and
manually verified end to end in the eleventh session, **completing phase 4 in
full**.
4a–4d remain complete from earlier sessions. Phase 3 (client policy, sender
rewriting, recipient routing) remains complete and compiles clean. Packaging
and the Windows service wrapper (normally phase 5) were pulled forward and
validated. The MSI's **first-install path is verified on hardware**
(2026-08-12): install → configure → `check` → start → stop, with the service
running as `NT SERVICE\smtprelayd`. Its **upgrade path is now verified on
hardware too** (2026-08-18, twentieth session, after the `WIX_UPGRADE_DETECTED`
fix below): the MSI installs without error, exactly one service registration
remains (no duplicate), the on-disk binary is replaced, and the service keeps
running afterwards. Uninstall remains unverified. Log rotation and Windows ACL
verification at startup are complete.
**Last session**: 2026-08-21 (twenty-ninth session) — MSI installer UI
investigation, no code change. Reported as "der windows installer zeigt jetzt
nur mehr den admin promt und beim installieren ist kein progress zu sehen,
auch beim deinstallieren nichts zu sehen und keine Abfrage," this time on a
genuinely separate physical Windows 11 notebook, not `ATAXVM-STSC` — initially
suspected as evidence the twenty-second session's unexplained UI-level mystery
was package-related after all (the `-sice:ICE20` suppression under
`PurgeDataDlg`), since ICE20 requires the full standard dialog set once any
custom dialog is authored. Two verbose `msiexec /l*v` logs (install and
uninstall, both run with no `/qn`/`/quiet`) disproved that theory directly.
Install: `UILevel` resolves correctly to `5` (Full), `PurgeDataDlg` is
correctly skipped (`condition is false` — right, since its condition is
uninstall-only), and the entire install completes in about three seconds
start to finish; the "no progress seen" report there is almost certainly the
install just being too fast to visually register, not a suppression bug.
Uninstall: the log shows `Client-side and UI is none or basic: Running entire
install on the server` and `CLIENTUILEVEL=2` (explicitly None) set by the
client side before the package is even opened — this is `MSI_LUA`, Windows
Installer's own compatibility shim for a UAC-split-token Administrator
performing a *maintenance* operation (uninstall/repair) on an already
"admin-assigned" per-machine product; it elevates the operation itself and,
in doing so, forces `CLIENTUILEVEL=None`, suppressing both the built-in
progress dialog and `PurgeDataDlg` before `InstallUISequence` is ever
reached. Nothing in `smtprelayd.wxs` can affect this — the UI level is
decided client-side, ahead of the package being read. This corrects the
twenty-second session's framing: that session found the identical signature
(`CLIENTUILEVEL`, `RemoteAdminTS=1`, `UILevel=3`) on `ATAXVM-STSC` over RDP and
concluded, for lack of a second machine, that it was likely specific to that
VM/RDP session; a second machine is now available and shows the same
behaviour, so it is not VM- or RDP-specific — it is `MSI_LUA` reacting to a
UAC-split-token admin account, independent of host. The operator's real-world
trigger is "Apps & Features" uninstall, not a raw `msiexec` invocation or a
double-click, and it hit the same suppression, confirming the shim engages
through that path too. Functionally nothing is broken either way — both
verbose logs end "completed successfully," service correctly installed or
removed, files in the right place — only the visible feedback (progress bar,
and the interactive purge-data question) is suppressed. Practical operator
workaround, not yet tested by the operator this session: run the uninstall
from an already-elevated shell (opened via "Run as Administrator" before
typing the command) rather than letting `msiexec`/the shell elevate
on-demand, which should sidestep the shim and let the built-in progress UI
and `PurgeDataDlg` render normally. Follow-up if it recurs: confirm that
workaround, and if operators need the data-purge question reliably rather
than relying on `CLEANDATA=1` scripted on the command line, revisit whether
the pre-elevation instructions belong in `docs/guides/CONFIGURATION.md` or a
Windows-specific install guide.
**Same session, follow-up ("können wir das fixen?" then "beim install dialog
sollte wenn es fertig ist ein finish buttone oder erfolgsmeldung kommen")**:
two related MSI UI gaps addressed, one implemented, one scoped but
deliberately deferred. First, whether the `MSI_LUA`/`CLIENTUILEVEL` shim above
can be fixed from within `smtprelayd.wxs`: no — it is decided by `msiexec.exe`
client-side, before the package is even opened, so nothing in the `.wxs` can
touch it. The one real fix is a WiX Burn bootstrapper wrapping the `.msi`, so
Explorer/Apps & Features launch something that requests elevation once
(`requireAdministrator`) before `msiexec` ever runs, sidestepping the shim
entirely — but that replaces the shipped artifact (bootstrapper `.exe`
instead of a bare `.msi`), adds `burn.exe`/`insignia.exe` steps to
`release.yml`, changes what Apps & Features registers, and needs the full
install/upgrade/uninstall hardware cycle re-verified. Operator chose to go
ahead with it ("Bootstrapper bauen"); not yet started, see below.

Second, prompted separately: no Finish button or success confirmation
appeared at the end of either install or uninstall, only a silent close.
Tracing it: `smtprelayd.wxs`'s `<UI>` block has only ever authored
`PurgeDataDlg`, no `ExitDialog`/`UserExit`/`FatalError` — `InstallUISequence`
simply had nothing left to show once `ExecuteAction` finished, on
install *and* uninstall alike, independent of the `MSI_LUA` question above
(the install-side verbose log from the same session already showed `UILevel`
resolving correctly to `5`/Full, so the UI was capable of rendering — there
was just nothing authored to render at the end). Fixed by referencing
WixUIExtension's stock dialogs rather than hand-authoring them:
`-ext WixUIExtension` added to both `candle.exe` and `light.exe` in
`release.yml`, `<UIRef Id="WixUI_ErrorProgressText" />` added for the
Error/ActionText table entries those dialogs expect, and three `<Show>`
entries (`ExitDialog` on success, `UserExit` on cancel, `FatalError` on
error) added to the existing `InstallUISequence` right after `PurgeDataDlg`'s.
Deliberately not a full WixUI wizard (no Welcome/License/feature-tree pages,
matching the existing "smallest dialog that can ask one question" reasoning
for `PurgeDataDlg`) — just the three closing dialogs every WixUI wizard
already shares. `-sice:ICE20` stays suppressed and the header comment now
explains why more precisely: ICE20 additionally wants a `FilesInUse` dialog
and `AdminUISequence` entries, neither of which this package authors or
needs (no administrative/network install has ever been supported), and
suppressing a build-time lint does not change runtime behaviour the way the
missing `FilesInUse` dialog actually did on real hardware (see the
`MSIRESTARTMANAGERCONTROL` fix above) — this is a lint gap, not a functional
one. Verified with `xmllint --noout` (clean) only; **no WiX toolchain in this
environment**, same recurring gap as every other Windows packaging change
here — not build-verified, so the very next `release.yml` run (or a local
`light.exe` if the operator has WiX available) is the first real check that
`WixUI_ErrorProgressText`/`ExitDialog`/`UserExit`/`FatalError` resolve
correctly via the extension, and the next install/uninstall on hardware is
what confirms an actual Finish screen appears. Bootstrapper work (the
`MSI_LUA` fix) intentionally not started in the same pass — staged
separately so this smaller, self-contained change can be verified on its own
first before the bigger, harder-to-verify Burn/Bundle rework begins. One
caveat flagged to the operator, not yet acted on: an unsigned bootstrapper
`.exe` may draw more SmartScreen friction than the current unsigned `.msi`
does today, worth watching for once that work starts.
**Same session, real `light.exe` build failure from CI, fixed from the pasted
log rather than reasoned about**: `WixUI_ErrorProgressText` alone was not
enough. Seven ICE17/ICE31 errors, all pointing the same direction: the
`ExitDialog`/`FatalError`/`UserExit` dialogs (from
`wix\src\ext\UIExtension\wixlib\*.wxs`) reference a shared
`Binary Id="WixUI_Bmp_Dialog"` and `TextStyle Id="WixUI_Font_Bigger"` that
live in the separate `WixUI_Common` fragment, not in
`WixUI_ErrorProgressText` — the two fragments are siblings, neither pulls
the other in, and only the latter was referenced. Also, `ExitDialog`'s
`Finish` button ships with no `ControlEvent` wired at all (ICE17: "a 'Do
Nothing' button") — deliberately, since WiX leaves that wiring to whichever
top-level wizard fragment consumes `ExitDialog`, and this project isn't
using one of those. Fixed by adding `<UIRef Id="WixUI_Common" />` alongside
the existing `WixUI_ErrorProgressText` reference, and one explicit
`<Publish Dialog="ExitDialog" Control="Finish" Event="EndDialog"
Value="Return">1</Publish>` to close the dialog on click. `xmllint --noout`
clean again; still not build-verified beyond that, same gap as above — the
next CI run is what actually confirms `light.exe` links clean this time.
**Previous session**: 2026-08-21 (twenty-eighth session) — Bug fix, no phase work.
Reported as "nach /queue bleiben die gelöschten Einträge sichtbar. ist das
gewollt?" Traced to a real gap, not a misunderstanding: `/queue`'s "active"
filter (`internal/store/query.go`) derives status purely from the latest row
in the `attempts` table, and the dashboard/API delete action
(`handleDeleteAction` in `internal/web/web.go`, `handleDelete` in
`internal/api/endpoints.go`) only ever called `spool.Discard`, which removes
the spool file but writes no attempt record — so a deleted message kept
whatever status it had before deletion ("queued" or "deferred") and kept
matching `/queue`'s active filter indefinitely, until the history retention
job eventually purged the row (`history.retention_days`, default 90). The
header stat tiles were unaffected since those come from the in-memory
`metrics.Registry`, not the store, which is why only the table below them was
stale. Presented two fix options and asked before implementing, since this
touches store status vocabulary and the JSON API contract, not just a local
display bug: a live-spool cross-check scoped to `/queue`, or a new terminal
status the store itself records. Operator chose the latter. New
`Store.RecordRemoval(queueID)` (`internal/store/store.go`) computes the next
`attempt_num` and inserts one attempt row with class `"removed"`, called from
both delete handlers right after `spool.Discard` succeeds (failure only
logged, matching the existing `RecordAudit` error handling right next to it —
the spool removal already happened and is the part that must not be rolled
back). `classToStatus`/`statusClasses` (`internal/store/query.go`) gained a
`"removed"` case, so it is excluded from `active`/`queued`/`deferred` for
free and separately filterable via `/search?status=removed` and
`GET /api/v1/messages?status=removed`, without hard-deleting the history row
— `spool.Discard`'s own "retains history by design" comment stays true, this
just makes the derived status agree with reality instead of freezing at
whatever the last real delivery attempt (or lack of one) left behind.
`.pill-removed` added to `internal/web/static/style.css` (reusing `--muted`,
same as "queued") and a `removed` option added to `/search`'s status filter
dropdown; no other template changes needed since `queue.html`/`message.html`
already render whatever `.Status`/`.Class` the store returns. `docs/guides/
API.md`'s status enum for `GET /api/v1/messages` updated. Extended rather
than duplicated the existing delete tests
(`TestDeleteActionRemovesFromSpoolKeepsHistory` in `internal/web/web_test.go`,
`TestAdminScopeCanDeleteAndAudits` in `internal/api/api_test.go`) with a
status-is-"removed" assertion and an active-filter-excludes-it check; new
`internal/store/store_test.go` cases cover the status derivation itself and
`RecordRemoval` appending after a real attempt already exists (guards against
an `attempt_num` collision when a message was retried at least once before
being deleted). Verified with the Go 1.25.13 toolchain: `gofmt -l .` clean,
`go vet ./...` clean, `GOOS=windows GOARCH=amd64 go build ./...` clean,
`go test ./...` and `go test -race ./...` both green across every package,
`scripts/check-banned-imports.sh` clean for all three targets.
`govulncheck`/`gosec` not run locally, not installed in this environment,
same recurring gap as most sessions here, left for CI. Also manually verified
end to end against a running instance (temp config, real SMTP submission,
real HTTP POST through the CSRF-protected form): before the fix, the message
sat in `/queue` as "deferred" after being deleted; after, `/queue` no longer
lists it, the message page shows status "removed", `/search?status=removed`
finds it, and `/search?status=active` does not.
**Same session, immediate follow-up on a rough edge noted while fixing the
above, then requested directly ("ja bitte den fix einbauen")**: the message
detail page's Requeue/Delete buttons rendered unconditionally regardless of
`.Message.Status`, so a message already in a terminal state offered two
actions guaranteed to fail. Not new — it applied to "delivered" and "bounced"
before this session too — but the new "removed" status made a third
guaranteed-404 case, prompting the fix rather than leaving it for later.
Scoped precisely to the two statuses where the spool file is provably gone
for good: `spool.Remove` (delivered) and `spool.Discard` (removed) both
unconditionally delete the on-disk message, unlike a permanent/expired
failure, which `m.fail` moves into `spool/failed` and leaves requeueable
until `queue.failed_retention_hours` expires it — so "bounced" still shows
the actions, deliberately unchanged. `internal/web/templates/message.html`
now wraps the actions `<div>` in `{{if or (eq .Message.Status "delivered")
(eq .Message.Status "removed")}}`, showing an explanatory `<p class="empty">`
instead; `web.go`'s token generation was left as-is since generating an
unused CSRF token is cheap and duplicating the status check in Go would only
be one more place for the two conditions to drift apart. New
`TestMessagePageHidesActionsForTerminalStatus` in `internal/web/web_test.go`
covers both statuses. Verified the same way as the parent fix: full toolchain
check clean, plus a second live-instance run (fresh temp config, real SMTP
submission, real CSRF-protected delete POST) confirming the buttons are
present before delete and gone after, replaced by the explanatory text.
**Previous session**: 2026-08-21 (twenty-seventh session) — Two small features
added on request, no phase work. First, "ich möchte statt utc auch eine
andere Zeitzone verwenden können": asked the operator up front whether the
scope was the log file, the dashboard, or both, since the two draw from
different sources (log lines are `slog`'s own `time.Now()`, dashboard
timestamps come from the UTC-stored history database) — answer was both.
New `service.timezone` (`internal/config/timezone.go`, `ParseTimezone`,
IANA name or `UTC`/`Local`, empty keeps today's behaviour), validated at
`Load()` time the same way `service.log_level` already is. `_ "time/tzdata"`
is blank-imported in `cmd/smtprelayd/main.go`, caught before it became a
silent Windows-only bug: this project ships one binary and Windows carries
no on-disk IANA zoneinfo database at all, so without the embed
`time.LoadLocation` would fail on every Windows install for any real zone
name, working only on Linux hosts that happen to have `/usr/share/
zoneinfo`. `internal/logging.Options` gained `Location *time.Location`;
`newReplaceAttr` converts the `slog.TimeKey` attribute when set, then falls
through to the existing redaction, since slog only takes one `ReplaceAttr`
hook. The dashboard side went through a new `localtime` template func
(`internal/web/web.go`) rather than converting at the store layer, so the
history database and the JSON API stay in UTC exactly as before — only
`queue.html`, `search.html`, `bounces.html`, `message.html`, `sidebar.html`
and `routes.html`'s six raw `.Format` calls changed to `{{localtime ...}}`.
`localtime` accepts both `time.Time` and `*time.Time` (`Attempt.NextAt` is a
pointer, everything else is a value), since text/template calls are
reflect-typed and would refuse a pointer where a `time.Time` parameter is
declared. New test `TestLocationConvertsTheTimestamp`
(`internal/logging/logging_test.go`) uses `Pacific/Kiritimati` (UTC+14)
specifically because it can never coincide with the test host's own zone by
accident.
Second, "das logfile soll auch geschrieben werden wenn der Dienst nicht
startet": traced the actual gap in `serve()` (`cmd/smtprelayd/main.go`) —
once the logger is constructed, `spool.Open`, `store.Open`, `listener.New`,
`web.New`, `delivery.New` and the listener's own `Serve` all returned their
error bare, so a real startup failure (bind conflict, missing TLS cert,
corrupt history database) reached stderr only, never the log file an
operator actually opens. Each now gets a `log.Error(...)` before the
`return`.
**Same session, immediate follow-up from the operator hitting exactly the
remaining gap**: a typo'd `service.timezone` ("sEurope/Vienna") made `run`
fail with nothing at all in the log — `check` reported it correctly on
stdout, but that gap had just been recorded in `MEMORY.md` as "structural"
without checking whether it really had to be. It did not, for this class of
failure: `config.Load` (`internal/config/config.go`) now returns the
decoded `*Config` alongside the error for every failure past a successful
TOML decode (unknown keys, secret resolution, `Validate()`), not `nil` —
`data_dir` is already known at that point even when a later field is what
actually failed, and every existing caller already returns immediately on a
non-nil error without touching the config, so this is additive, not a
behaviour change for anyone else. New `main.logStartupFailure`
(`cmd/smtprelayd/main.go`) uses that to write the failure into
`<data_dir>/smtprelayd-error.log` — a fixed name, deliberately not
`cfg.Log.File`, since the configuration that just failed validation is
exactly the one value that cannot be trusted to name its own error log —
but only after running `checkEnvironment` itself first, since a `config.Load`
failure is precisely the case where the data directory has not been vetted
safe to write into yet; it cannot assume an earlier call already did that.
Two new tests in `cmd/smtprelayd/startup_test.go` cover the write and the
nil-config no-op. What is genuinely still unreachable, and is structural:
a config file that fails to parse at all, or fails its own trust check
(`CheckConfigFile`) — `data_dir` is never known in either case, so those stay
stderr/journald/Windows-Event-Log-only. `MEMORY.md` section 10 and
`docs/guides/CONFIGURATION.md` section 9 both updated to describe the narrower,
now-accurate gap.
Verified with the Go 1.25.13 toolchain at `~/sdk/go1.25.13` (not on `PATH` in
this environment; invoked by full path) rather than reasoned about:
`gofmt -l .` clean after one alignment fix, `go vet ./...` and
`GOOS=windows GOARCH=amd64 go build ./...` both clean, `go test -race ./...`
green across every package including both new tests, and
`scripts/check-banned-imports.sh` clean for all three targets — confirming
`time/tzdata` did not pull anything banned into the graph. `govulncheck`/
`gosec` not run locally, not installed in this environment; same recurring
gap as most sessions here, left for CI.
`docs/guides/CONFIGURATION.md` section 9 and `configs/smtprelayd.example.toml` both
document `service.timezone`; `MEMORY.md` sections 7 and 10 updated for the
timezone option and both startup-failure logging fixes.
**Same session, further follow-up: the long-open "abort or only log" question
closed.** Requested directly: "fehlerhafter Token-Abruf soll loggen und den
Start verhindern." `authms365.TokenSource` only ever fetched a token lazily,
on the first delivery attempt against a route, so a rejected M365 credential
or an unreachable tenant at boot was invisible until mail was already queued
behind it — exactly the gap the open question in this file described. New
`Manager.VerifyTokens` (`internal/delivery/delivery.go`) walks `cfg.Routes`
in configuration order and calls `Token(ctx)` on each xoauth2 route's already
constructed source, returning the first error wrapped with the route name; a
route with no cached source (`plain`/`login`/`none`) is skipped, since a
static credential has nothing to verify over the network. `serve()`
(`cmd/smtprelayd/main.go`) calls it right after `delivery.New` succeeds and
before any worker goroutine starts, `log.Error`s and returns on failure —
the same "log then abort" shape every other startup dependency in `serve()`
already uses (`spool.Open`, `store.Open`, `listener.New`, `web.New`), so this
is one more instance of an existing pattern, not a new one. Not folded into
`delivery.New` itself, deliberately: construction only validates shape
(tenant/client ID/secret non-empty), this call reaches the network, and
keeping them separate meant no existing caller of `New` — including its own
tests — needed to change. Three new tests in
`internal/delivery/delivery_test.go` cover the skip-when-not-xoauth2 case,
the success case and the abort case, against a `fakeTokenSource` stub rather
than a real token request: `authms365.New` hardcodes the token authority to
`login.microsoftonline.com` with no seam for a test server from outside its
own package, the same reason `authms365`'s own tests reach into the
unexported `endpoint` field directly instead. **Accepted tradeoff, stated
before building this rather than found afterward**: both the systemd unit
(`Restart=on-failure`, `RestartSec=5`, `StartLimitBurst=5` in
`StartLimitIntervalSec=60`) and the Windows service recovery action restart
the process automatically, so a queued message is never lost while the
tenant is unreachable — but a Microsoft 365 outage or a rejected secret
lasting longer than roughly the first 25 seconds of restart attempts
exhausts the Linux unit's restart burst and leaves the service down until an
operator intervenes (`systemctl reset-failed` and a manual start). That is
what "verhindern" was asked to do, not a side effect to soften.
`docs/guides/MS365-AUTH.md`/`docs/guides/CONFIGURATION.md` not touched: neither documents
today's lazy-fetch behaviour to begin with, so there was no stale claim to
correct.
Verified with the Go 1.25.13 toolchain: `gofmt -l .` clean, `go vet ./...`
clean, `GOOS=windows GOARCH=amd64 go build ./...` clean, `go test ./...` and
`go test -race ./...` both green across every package including the three
new tests, `scripts/check-banned-imports.sh` clean for all three targets.
`govulncheck`/`gosec` not run locally, same recurring gap, left for CI.
**Same session, a second, deeper follow-up: a bad startup was never actually
reported to Windows.** Requested directly: "auch eine falsche Konfiguration
sollte den Start auf Windows verhindern." Tracing why led past config
specifically to the real, general bug: `winProgram.Start`
(`cmd/smtprelayd/service_windows.go`) is the kardianos/service entry point
the SCM calls on Windows, and it launched `serve()` in a goroutine and
returned `nil` immediately, unconditionally — so the SCM was told "started
successfully" before `config.Load` had even run, let alone `checkEnvironment`,
`spool.Open`, `store.Open`, `listener.New`, `delivery.New`,
`dm.VerifyTokens` (the previous follow-up, same session) or the SMTP
listener's own socket bind. Every one of those already logged its failure
correctly (several sessions' worth of exactly that work), but none of it
ever reached the Windows service state: the process would exit right after,
and the SCM would carry on showing the service as running because nothing
had told it otherwise — a genuinely silent failure on the one platform this
project's own installer targets most, not merely an under-logged one.
Fixed with a ready signal rather than a fixed wait: `serve()`
(`cmd/smtprelayd/main.go`) gained a `ready chan<- error` parameter (nil on
the foreground/systemd path, where a non-zero process exit already is a
startup failure systemd's `Restart=on-failure` acts on) and a named return
value plus one `defer` that sends `err` on it exactly once, whichever return
path is taken. An explicit `notifyReady(nil)` call marks the one point past
every synchronous, fail-fast step — including the SMTP listener's own
socket bind, moved out of the old combined `listener.Set.Serve` into a new
`Set.Bind` (fails fast, e.g. an address already in use) called just before
that point, with `Set.Run` (blocks until shutdown, replaces the accepting
half of the old `Serve`) called just after. `winProgram.Start` now blocks on
that channel and returns whatever it receives, so the SCM sees a real
"failed to start" — triggering `OnFailureRestart` and showing a stopped
service with an error, not a running one doing nothing — for exactly the
class of failure this session already made sure reached the log file. A
fixed-wait heuristic (return success if `serve()` has not failed within N
seconds) was considered and rejected: `authms365`'s token request timeout is
15 seconds, so a wait short enough to feel responsive could still report
success moments before a slow-but-genuine tenant rejection arrived; the
`ready`-channel signal has no such window, at the cost that a slow init
(worst case still the same ~15s) makes the SCM wait that long for `Start` to
return, comfortably inside its default ~30s patience but named here as the
accepted tradeoff rather than found later.
**Same session, a real bug found by the new test for the above, not part of
what was asked**: splitting listener bind from run needed a `Set`-level test
that had never existed, and the first version of it — dial, close, cancel —
failed `go test -race` on the very first run. `Set.Close` closed every
listener socket, then called `wg.Wait()` per server; `Server.accept`'s loop
could have already had `Accept` return a real connection in the instant
before the socket closed, and would then call `wg.Add(1)` concurrently with
that `Wait()` — exactly the ordering `sync.WaitGroup`'s own documentation
calls out as undefined: an `Add` with a positive delta on a counter that
could be zero must happen before the matching `Wait`, and closing a socket
provides no such ordering by itself. This is not new in this session — the
same two calls existed in the previous combined `Serve` — it had simply
never been exercised by a `-race` test at the `Set` level before. Fixed with
a `closeMu sync.Mutex` plus `closed bool` on `Server`: `stopAccepting` sets
`closed` under the lock before closing the socket, and `accept` checks
`closed` under the same lock immediately before every `wg.Add`, refusing and
closing the connection instead if shutdown has already begun. That
serialisation is what gives `sync.WaitGroup` the ordering it requires,
regardless of how the two goroutines happen to interleave. `Set.Close` keeps
its original two-phase shape (stop every server accepting first, then wait
for all of them) rather than closing-and-waiting one server at a time, so
one slow listener's sessions still cannot delay the others from being told
to stop. Two tests in the new `internal/listener/listener_test.go` cover
`Bind` failing on an address already in use and `Bind`+`Run` actually
accepting a connection; a third, `TestCloseDoesNotRaceAcceptedConnections`,
dials continuously from four goroutines while cancelling to give `-race` a
real chance at the window that caught this, and is the regression test —
run eight times in a row under `-race` with no failure once the fix landed,
after reliably failing before it.
Verified with the Go 1.25.13 toolchain: `gofmt -l .` clean, `go vet ./...`
clean on both `GOOS`, `GOOS=windows GOARCH=amd64 go build ./...` clean
(exercises the changed `service_windows.go` directly), `go test ./...` and
`go test -race ./...` both green across every package including the three
new listener tests, `scripts/check-banned-imports.sh` clean for all three
targets. Not verified: an actual Windows service start against a broken
configuration — no Windows machine in this environment — so the next
deployment session should deliberately break `smtprelayd.toml` (or block the
configured port) before starting the service and confirm the SCM now shows
a failed start rather than a silently dead "running" one.
**Same session, docs reorganised, no code changed.** Requested directly:
"bitte noch die docs soweit aufräumen das anleitungen für enduser getrennt
von den Findings usw sind." `docs/` had eleven files in one flat directory
mixing operator-facing guides with this project's own working documents.
Split into `docs/guides/` (`CONFIGURATION.md`, `MS365-AUTH.md`, `CHECKMK.md`,
`API.md`, `SECURITY.md`, `img/`) and `docs/dev/` (`EXPLOIT-SURFACE.md`,
`Findings.md`, `PHASE4-PLAN.md`, `PHASE5-CHECKLIST.md`,
`SESSION-BOOTSTRAP.md`) via `git mv`, so history follows each file. The two
judgement calls: `SECURITY.md` went to `guides/` rather than `dev/` — it is
"binding" for whoever touches the code per `CLAUDE.md`, but README already
framed it as a "deployment checklist" for whoever is running the relay, and
that operator-facing framing is what a customer doing security due diligence
before deploying actually wants; `EXPLOIT-SURFACE.md` went to `dev/` instead
— it is explicitly the "code-level attack surface," addressed to whoever is
about to edit `internal/listener` or `internal/rewrite`, not to an operator.
Every reference to a moved file was then updated in one pass: README's
Documentation section (split into the same two groups, operator guides
first), `CLAUDE.md`'s security paragraph, `MEMORY.md`, this file's own
current-state prose and its still-living Phases/Decision-log sections, and
eleven Go source comments plus `scripts/check-banned-imports.sh` — all of
these cite `docs/SECURITY.md`/`docs/API.md`/`docs/EXPLOIT-SURFACE.md` etc. as
navigational pointers a reader is meant to follow right now, so a stale path
left behind would be a real dead link, not a preserved historical fact.
Verified with `grep` across the tree that no bare pre-move path survived
anywhere. Verified with the Go 1.25.13 toolchain, since eleven `.go` files
had a comment string changed: `gofmt -l .` clean, `go vet ./...` clean on
both `GOOS`, `GOOS=windows GOARCH=amd64 go build ./...` clean, `go test ./...`
green, `scripts/check-banned-imports.sh` clean for all three targets.
**Previous session**: 2026-08-21 (twenty-sixth session) — Deployment support only,
no phase work, no code changed. Walked an operator through configuring the
`m365` route's `oauth2.client_secret` on a live Windows install, starting
from "wie mach ich in der config eine ms365 auth". Covered, in order: the
`[route.oauth2]` block and the three `Secret` reference forms; where in Entra
ID the client secret value comes from; that a `file:` secret outside
`data_dir` needs a manual ACL, while one placed inside `data_dir` inherits
`SecureDataDir`'s protected DACL automatically (no `icacls` needed there);
that the configuration has no live reload, so a change needs `smtprelayd
check` then a service restart to take effect. The operator then confirmed
they are in fact on the DPAPI-capable build (after first believing
otherwise), ran `protect-secret` against their existing plaintext
`ms365.txt`, switched the route to
`dpapi:C:\ProgramData\SMTPRelayd\ms365.dpapi`, and confirmed mail delivery
through the M365 route actually works — both with the earlier `file:`
reference and now with `dpapi:`. **This closes the twenty-fourth session's one
outstanding item**: "the real test, still outstanding: `protect-secret` →
`dpapi:<path>` in the configuration → service starts and delivers, on real
Windows hardware" is now observed, not just reasoned from documented DPAPI
semantics.
**Same session, documentation follow-up.** First request: "bitte passe alle
Dokus so an das es für alle eventualitäten eine Step by Step anleitung gibt
... nicht für linux und Windows verschiedene." `docs/guides/MS365-AUTH.md` gained a
new "Configuring the relay, step by step" section — the route block, all
three secret forms with Linux/Windows paths and commands inline rather than
duplicated per OS, validate/apply/verify, and rotation — placed after
"Common errors" rather than between the existing `### Entra ID setup` /
`### Exchange Online setup` subsections, where a first draft had broken the
`## Chosen approach` heading hierarchy (caught and fixed before reporting the
edit done, by re-grepping the heading list). Second request, immediately
after: the same treatment for every other configurable part, not only
Microsoft 365 — "SMTPmit Auth + Zertifiket, Metriks bearer generiern usw.
alles was unser tooll kann." New `docs/guides/CONFIGURATION.md`: inbound
listeners/the relay's own TLS certificate, client CIDR matching and all three
sender-rewrite modes (reusing the example configuration's one-client-per-mode
as the worked examples rather than inventing new ones), a generic smarthost
route with `plain`/`login` SMTP AUTH and an `openssl`-based `ca_pin` recipe,
a pointer to `docs/guides/MS365-AUTH.md` for the Microsoft 365 route rather than
repeating it, multi-route recipient splitting, queue/bounce tuning, the
dashboard and its theme, and — the concrete gap this closes, since
`docs/guides/API.md` documents the token contract but never how to provision one —
step-by-step bearer token generation (`openssl rand` → `sha256sum` →
`[[web.token]]`) shared by the API and the metrics endpoint, plus the
metrics endpoint's dual requirement (`[tls]` cert **and** a read-scope token
once bound beyond loopback). Grounded in `internal/config/validate.go` and
`internal/metrics/http.go`, not only the already-well-commented example
config, for the parts not obvious from it: the listener/route TLS state
machine, rewrite mode validation rules, and exactly which secret-and-token
plumbing is shared between the API and metrics. `README.md`'s Configuration
and Documentation sections both updated to point at the new guide. Docs only,
no code changed.
**Previous session**: 2026-08-21 (twenty-fifth session) — Deployment
troubleshooting on a live install, no phase work and no code changed. Started
with a status question ("was ist noch was müssen wir noch machen / testen"),
answered from this file's own open items. The real work followed from "bei
deb startet das noch wie kan ich es troubleshooting": a `.deb` install on
`ATAXVM-STSC` — the same Windows test VM the MSI work uses — reached through a
WSL shell (`administrator@ATAXVM-STSC:/mnt/c/Users/Administrator/Downloads$`),
not a standalone Debian/Ubuntu host or VM. Three real, sequential faults
turned up rather than one:
1. `.../smtprelayd.toml is writable by group or others` — `checkTrusted`'s
   write-bit refusal ([trust_unix.go:94-96](internal/config/trust_unix.go#L94-L96))
   tripped because a `cp` + editor workflow left the copied config at a
   permissive mode (reported truncated as `076x`) instead of the packaged
   `0640`; fixed with `chmod 0600`.
2. `open /etc/smtprelayd/smtprelayd.log: permission denied` — `data_dir` was
   set to `/etc/smtprelayd` instead of `/var/lib/smtprelayd`. `log.file`
   resolves relative to `data_dir` ([logpath.go](internal/config/logpath.go)),
   and `/etc/smtprelayd` is deliberately not writable by the `smtprelayd`
   group (`0750`, [postinstall.sh:8-11](packaging/linux/postinstall.sh#L8-L11))
   so a compromised service cannot rewrite its own configuration. Fixed by
   pointing `data_dir` at `/var/lib/smtprelayd`, as the example ships it.
3. `550 5.7.1 relay access denied` — expected fail-closed behaviour
   ([session.go:244-247](internal/listener/session.go#L244-L247)): the test
   client's source address had no matching `[[client]]` CIDR. Fixed by adding
   one.
None of the three needed a code change; each was an operator/deployment-config
mismatch, diagnosed from `journalctl -u smtprelayd` output pasted back
verbatim at each step. Confirmed working end to end after all three fixes
("ok somit passt das").
Flagged directly afterward, unprompted: "bei fedora hatte ich keine Probleme
mit der toml unter /etc/smtprelayd/" — explained that `checkTrusted` is
identical on both platforms (`//go:build !windows`), so the difference is
almost certainly `cp`-plus-editor versus a `mv` of the packaged file (which
would have kept the shipped `0640` exactly), not a Fedora/Debian difference in
the code. Also named, and agreed to record: this WSL session on the MSI test
VM is a useful smoke test but is **not** the standalone Debian/Ubuntu
verification the phase 5 checklist item asks for, since WSL2's systemd
support has its own cgroup/namespace quirks that can differ from a bare-metal
or VM install. The checklist below is updated to say so explicitly rather
than silently counting this as the missing verification.
**Previous session**: 2026-08-20 (twenty-fourth session) — Small feature added on
request, no phase work. The session started as a question, "wie wird das
passwort gespeichert wenn ich mich authentifizieren muss", answered by
walking through `config.Secret.resolve()`'s existing `${ENV_VAR}`/`file:`
options; the follow-up, "wie mache ich das auf windows", surfaced that a
Windows service account has no reliable way to receive a machine-level
environment variable without a reboot, so `file:` (readable-only-by-owner)
was the practical answer there. Pushed back on directly: "ok dann liegt das
file aber immer noch im klartext irgendwo... können wir das irgendwie
beheben" — explained honestly rather than building blind that no unattended
service can be fully proof against an attacker who already has
Administrator/SYSTEM on the box, since the decryption capability must live
on the same machine with no human to prompt for a passphrase at boot; DPAPI
still raises a real, specific bar (the file becomes useless if copied off
the machine) even though it cannot clear that bar. Confirmed wanted
("mir geht es nur darum das ich die passwörter nicht im klartext irgendwo
stehen haben will") and implemented: a new `dpapi:<path>` secret reference,
Windows only, alongside the existing two. `internal/config/dpapi_windows.go`
hand-rolls `CryptProtectData`/`CryptUnprotectData` via `crypt32.dll`
(`golang.org/x/sys/windows.NewLazySystemDLL`/`NewProc`, no wrapper for DPAPI
exists in that module), machine-scoped
(`CRYPTPROTECT_LOCAL_MACHINE`) rather than user-scoped, because the virtual
service account `NT SERVICE\smtprelayd` has no ordinary profile to hold a
per-user DPAPI master key and machine scope is also what lets an elevated
operator's own account encrypt a file the service account can later decrypt;
`CRYPTPROTECT_UI_FORBIDDEN` on both directions so a service context can never
block on a credential prompt it has no console to show. `dpapi_other.go`
stubs the same function on non-Windows with a clear error rather than a
silent empty secret. New CLI subcommand `smtprelayd -out <file> protect-secret`
(Windows only, `verify_windows.go`) reads the plaintext as one line from
stdin — deliberately not a flag, to keep it out of the process list and shell
history — and writes the ciphertext; the header comment documents the
intended PowerShell invocation piping a masked `Read-Host -AsSecureString`
prompt into it. Caught while writing that same doc comment, before reporting
anything done: the first draft showed `protect-secret -out <file>`, but
`flag.FlagSet.Parse` stops at the first non-flag argument, so `-out` would
never be parsed once it followed the command — `-out` has to precede the
command, exactly like the existing `-config` already does. Fixed in both the
top-level usage text and the doc comment before either was ever run, the
same category of self-caught mistake as the recurring XML-comment
double-hyphen one, just in a different file type this time.
`resolveDPAPISecret` runs the same `checkSecretFile`
symlink/reparse-point and containing-directory check the `file:` path
already runs, since a secret file is a secret file whether or not it is
encrypted at rest. This is the first *active* use of `unsafe` anywhere in
the tree — `internal/buildpolicy`'s `allowedBannedImports` already had a
dormant entry for `trust_windows.go` (a "LocalFree" exception that, on
reading the actual file, is not currently exercised — `CheckDataDirACL` uses
`golang.org/x/sys/windows`'s higher-level `SECURITY_DESCRIPTOR` methods
instead) — a second entry for `dpapi_windows.go` was added next to it, named
with its reason, so the CI import-policy test still fails on any *other*
file reaching for `unsafe`. `MEMORY.md` section 9 updated in both directions
this touches: the secrets bullet now names `dpapi:` and states plainly what
security property it does and does not add, and the "No dynamic behaviour"
bullet — which claimed flatly "No `unsafe`" — is corrected to describe the
real, narrow, explicitly-allowlisted exception instead, since that claim was
already slightly stale before this session (the dormant trust_windows.go
entry) and would have been actively false after it without the fix.
`docs/guides/SECURITY.md` §3 and `README.md`'s Configuration section both updated
to list all three secret forms; `configs/smtprelayd.example.toml`'s
`client_secret` comment now mentions `dpapi:`.
**Build-verified same session, once a toolchain became available.** No Go
toolchain existed in this environment when the feature was written; the
operator installed one on request (`go1.25.13`, user-local under `~/sdk`, no
root — this machine is an ostree-immutable Fedora derivative, so a system
package would have meant `rpm-ostree` layering and a reboot for no reason).
With it, every check `CLAUDE.md`'s definition of done and `ci.yml`'s `check`
job require came back clean against the full tree, including the new files:
`gofmt -l .` (empty), `go vet ./...`, `go test -race ./...` (all packages,
including the new `internal/config/dpapi_other_test.go`),
`scripts/check-banned-imports.sh` (all three targets, confirming the new
`dpapi_windows.go` allowlist entry is both necessary and sufficient),
`govulncheck` v1.6.0 (no vulnerabilities) and `gosec` v2.28.0 `-severity=medium`
(0 issues, 15 pre-existing `#nosec` lines, 52 files). `make build-all`
compiled all three release targets, including `windows/amd64` — the one CI
job that had never touched `dpapi_windows.go`/the `verify_windows.go`
additions before this. Two checks beyond what `ci.yml` itself runs, done
because this change's actual risk is Windows-specific and `ci.yml`'s vet/test
job never sets `GOOS=windows`: `GOOS=windows GOARCH=amd64 go vet ./...` came
back clean, which specifically exercises vet's `unsafeptr` analysis over the
hand-marshalled `DATA_BLOB` pointers — the exact class of mistake this file
was written most worried about. `gosec` could not be run the same way: `go
run` builds the tool itself for the GOOS in the environment, so setting
`GOOS=windows` produced a `gosec.exe` this Linux host cannot execute
(`exec format error`) rather than a Windows-flavoured analysis — a tooling
limitation, not a finding, and not resolved this session.
**What is still not verified, and cannot be from this environment**: actual
execution on Windows. Compiling and vetting prove the DPAPI struct
marshalling is well-typed and passes vet's pointer-safety analysis; they
cannot prove `CryptProtectData`/`CryptUnprotectData` behave as documented at
runtime, and specifically cannot prove `CRYPTPROTECT_LOCAL_MACHINE` really
does let the service account (`NT SERVICE\smtprelayd`) decrypt a blob a
different, elevated, interactive operator account encrypted — that claim is
still reasoned from documented DPAPI semantics, not observed. The real test,
still outstanding: `protect-secret` → `dpapi:<path>` in the configuration →
service starts and delivers, on real Windows hardware.
**Previous session**: 2026-08-19 (twenty-third session) — Targeted security
review, no phase work. Requested as "prüfe das Projekt auf Sicherheit und
eventuelle Schwachstellen bzw Sicherheitslücken." Not a full-tree pass:
scoped to everything changed since the second review's fixes landed
(`fa2432c`, 2026-08-12) — the htmx dashboard, the Windows uninstall
`purge-datadir` feature, the lumberjack swap and the Go toolchain pin — plus a
re-check that the eleven previously closed findings and the banned-import
rules had not regressed; none had. One finding, written up in full in
`docs/dev/Findings.md` under "targeted review, 2026-08-19": `purgeDataDir`
(`cmd/smtprelayd/verify_windows.go`), the deferred custom action behind the
uninstaller's opt-in ProgramData purge, validated the resolved directory only
by its basename and then recursed into it with `os.RemoveAll` as SYSTEM,
skipping the `config.CheckDir` symlink/reparse-point refusal every other
function touching that directory already runs. Fixed by calling `CheckDir`
before `RemoveAll`, same as `secureDataDir` already does; a missing directory
is treated as already-purged rather than an error. Whether the gap was
independently exploitable was not established — Go's `RemoveAll` tries a
direct `Remove` on every path first, and `RemoveDirectory` on a Windows
reparse point is generally understood to delete only the link rather than
recurse into its target — but the fix closes the question either way at no
cost. Not build-verified — no Go toolchain in this environment, same
recurring gap as most Windows-only work in this project, and the function has
no existing test file — so this should be exercised on real hardware (a
fresh uninstall with "Yes, delete it") together with the rest of the
not-yet-hardware-verified half of this feature, see Open defects.
**Same session, follow-up from a pasted `msiexec /L*v` upgrade log** (0.2.15
→ 0.2.16, `ATAXVM-STSC`): reported as getting "2803" on an install-over.
Confirmed harmless and unrelated to the fix above: `PurgeDataDirCA` is
`Skipping action ... (condition is false)` both times it is evaluated in the
log (`CLEANDATA` stayed `0`), so `purgeDataDir` never ran in this test at
all, and the install finished with "Installation completed successfully" /
success status `0`. The `DEBUG: Error 2803: Dialog View did not find a
record for the dialog` / `Error 2867: The error dialog property is not set`
pairs each appear immediately after a `RESTART MANAGER: Session opened`
line — Restart Manager detects the running service's locked
`smtprelayd-windows-amd64.exe` before `StopServiceCA` runs later in the
sequence and tries to show its standard "files in use" prompt, which this
MSI has no `Dialog` table entry for. This is the twenty-second session's
`-sice:ICE20` suppression (added when `PurgeDataDlg` made ICE20 demand the
full standard dialog set) showing up at runtime rather than link time: the
engine's own fallback still triggers here, fails to find a dialog to show,
logs 2803/2867, and proceeds anyway (`InstallValidate` returns 1).
**Corrected immediately after**: reported back as "es kommt aber eine
Fehlermeldung mit 2803" — right, and wrong to have called it log-noise
first: `The installer has encountered an unexpected error installing this
package... error code is 2803` is the verbatim text Windows Installer's
generic fallback message box shows, not just a verbose-log artifact, so an
operator running the upgrade interactively sees it appear, several times,
during an otherwise-successful run. Fixed properly this time instead of
left open: `<Property Id="MSIRESTARTMANAGERCONTROL" Value="Disable" />`
added next to `CLEANDATA`, since `StopServiceCA` already stops the service
deterministically before `RemoveFiles` — which is what actually unlocks the
binary for an upgrade — making Restart Manager's own detection (and its
attempt to show a dialog this MSI has never authored) redundant rather than
something to build a `FilesInUse` dialog to satisfy. Smaller and more
targeted than the alternative of adopting more of WixUI's standard dialog
set. The header comment's ICE20 paragraph and the new property both got the
`xmllint --noout` check before reporting this done — the exact mistake the
twentieth and twenty-second sessions each made once already (a bare `--`
inside a prose XML comment) was caught and fixed at draft time this
session, in both new comment blocks, before it could repeat a third time.
Not yet re-verified against an actual upgrade — no WiX/Windows toolchain in
this environment — so the next upgrade test on `ATAXVM-STSC` is what
confirms the message box is actually gone.
**Previous session**: 2026-08-18 (twenty-second session) — Two open Phase 5
checklist items field-verified, plus a small feature added on request. First,
the field report: a non-admin Windows install triggers a UAC elevation
prompt and proceeds correctly (rather than installing unelevated or failing
silently — the behaviour the checklist item was asking for), and plain
uninstall completes. Both checklist items above are now closed.
Then, requested directly ("bitte noch einbauen, damit optional per Abfrage
auch das ProgramData bereinigt wird"): an interactive uninstall now asks
whether to also delete `%ProgramData%\SMTPRelayd`. `PurgeDataDlg` is a small,
hand-authored WiX `<Dialog>` (Yes/No, no WixUI — nothing else in this MSI
uses a wizard either, and pulling one in for a single question would have
been a much bigger change than asked for), sequenced only for a genuine
top-level interactive uninstall (`REMOVE="ALL" AND NOT
UPGRADINGPRODUCTCODE`; `InstallUISequence` does not run at all under
`msiexec /qn`, so a silent uninstall never shows it and never deletes data
unless `CLEANDATA=1` is passed explicitly on the command line). "Yes" sets
`CLEANDATA=1`, gating a new deferred custom action `PurgeDataDirCA`
(`smtprelayd.exe purge-datadir`, new in `cmd/smtprelayd/verify_windows.go`)
in `InstallExecuteSequence`, scheduled after `UninstallServiceCA`. Built as a
Go subcommand rather than WiX's `util:RemoveFolderEx`, deliberately: an
earlier design pass considered `RemoveFolderEx` gated by a Component
`Condition`, but that pattern only fires reliably when the component was
*unconditionally* installed in the first place (so it has a real
Present→Absent transition to hang the removal off); conditioning the
component itself on `CLEANDATA` would very likely have made the deletion
silently never run, since the component would never have been recorded as
installed to begin with. A plain `<CustomAction Execute="deferred">` gated by
an `InstallExecuteSequence` condition sidesteps that entirely and is exactly
the pattern `InstallServiceCA`/`UninstallServiceCA`/`SecureDataDirCA` already
use successfully. `purgeDataDir` resolves the directory exactly like
`secureDataDir` (configured `data_dir` when the configuration still loads,
the config file's own directory otherwise) but adds a guard `secureDataDir`
does not need: it refuses to act unless the resolved directory's last path
element is literally `SMTPRelayd`, because this deletes recursively via
`os.RemoveAll` and runs unattended with no further confirmation once
scheduled, so a wrong resolution must fail closed rather than delete
whatever it computed. `MEMORY.md`'s deployment section updated: the "MSI
does not remove ProgramData on uninstall" line now says "by default," with
the mechanism recorded. Not yet verified on hardware — no Go toolchain and
no Windows/WiX available in this environment (same recurring gap as several
earlier sessions); before this is trusted, run an actual uninstall both ways
(clicking "Yes, delete it" and confirming the directory is gone; clicking
"No" and confirming it survives) and confirm the dialog does **not** appear
mid-upgrade (install version B over a running version A and watch that no
dialog shows and the data directory survives, since `UPGRADINGPRODUCTCODE`
is set in exactly that nested removal).
**Same session, CI build failure and fix**: the very next `release.yml` run
after the above failed at `light.exe` with `error LGHT0204`, three separate
ICE violations, from a screenshot of the Actions log (not reasoned about —
the exact codes made the cause unambiguous): ICE20 ("Standard Dialog
'FilesInUse' not found in Dialog table", "ErrorDialog Property not
specified", and `FatalError`/`UserExit`/`Exit` missing from both
`InstallUISequence` and `AdminUISequence`) and ICE31 ("the 'DefaultUIFont'
Property must be set to a valid TextStyle"). Root cause: the moment a
`<UI>`/`<Dialog>` exists anywhere in a WiX source, ICE20 requires the
*complete* standard dialog set an MSI project normally gets for free from
`WixUIExtension`'s prebuilt wizard fragments — building all of that by hand
for one yes/no question would mean adopting a full install wizard this MSI
has deliberately never had. Fixed two ways: ICE31 properly, by adding a
`TextStyle`/`DefaultUIFont` property (two lines, no reason not to have a
real font); ICE20 by suppressing it with `-sice:ICE20` on the `light.exe`
invocation in `release.yml`, since not having `FatalError`/`UserExit`/`Exit`
dialogs regresses nothing — a fatal error or Cancel during setup already
fell back to the Windows Installer engine's own default handling before
`PurgeDataDlg` existed, because there was no custom UI at all then either.
Caught and fixed before it reached CI a second time: the header comment
explaining `-sice:ICE20` itself contained a bare `--` inside an XML
comment, the identical class of mistake the twentieth session's
`WIX_UPGRADE_DETECTED` fix made in the same file — caught this time by
running `xmllint --noout` locally before reporting the fix as done, rather
than after a second failed CI run. Not yet re-verified against an actual
`light.exe` run — no WiX toolchain in this environment — so the CI run
after this fix lands is the first real confirmation and should be watched.
**Same session, `light.exe` fix confirmed, then a second symptom diagnosed
from two verbose `/l*v` logs**: the rebuilt MSI links clean (ICE20/ICE31
gone) and `msiexec /x` completes, but `PurgeDataDlg` still never appears —
"Nur ein Uninstall yes or no, kein Auswahlfeld" (the generic Windows
Installer confirmation, not the custom one). Both logs, from two separate
runs against `C:\SERVICE\smtprelayd-0.2.15-amd64.msi` on host `ATAXVM-STSC`,
show the identical signature: `Client-side and UI is none or basic: Running
entire install on the server.`, `CLIENTUILEVEL=2`, `RemoteAdminTS = 1`, and
the resolved `UILevel = 3` (Basic) rather than 5 (Full) — this despite
`msiexec /x` being run with no `/q` flag at all, from an elevated prompt.
`PurgeDataDirCA`'s own log line each time: `Skipping action: PurgeDataDirCA
(condition is false)`, i.e. the WiX-side condition logic is proven correct
in both runs — `CLEANDATA` simply never became `1`, because `PurgeDataDlg`
never got a chance to render at Basic UI level (Windows Installer suppresses
package-authored `Show`-sequenced dialogs at Basic, showing only its own
built-in progress/confirmation UI). `RemoteAdminTS = 1` plus the negotiated
Basic level strongly points at the RDP session to `ATAXVM-STSC` itself,
not the package: Windows Installer is known to fall back the client/server
UI negotiation to Basic when the elevated service (Session 0) and the
calling process are on different Terminal Services sessions, independent of
requested flags. Not yet resolved either way — the requested next step is
testing from the VM's actual console (hypervisor console connection, not
RDP) to conclusively separate "environment artifact" from "WiX bug"; that
result is still outstanding. If console testing confirms the dialog does
render there, no code change is needed at all — the feature already works
correctly, this session just could not observe it working from the RDP
session used for testing.
**Same session, resolution**: console testing did not change the symptom —
`UILevel = 3` reproduced identically on `ATAXVM-STSC` whether invoked over
RDP or typed directly at the console. Four further candidate causes were
checked and each ruled out in turn, all against this same VM: ARP/"Apps &
Features" was never the path used (direct `msiexec /x` already showed it, so
this was really ruled out earlier), a Group Policy restricting the Installer
UI level (`gpresult` showed none), the two local-policy registry locations
Windows Installer itself reads (`HKLM\SOFTWARE\Policies\Microsoft\Windows\
Installer` and the legacy `...\CurrentVersion\Policies\Installer`, both
absent), and a non-interactive window station from a remote-execution
channel (confirmed the command was typed directly into the console window,
keyboard focus on the VM itself). None explain `CLIENTUILEVEL=2` being
computed client-side on this image before the server is ever involved; the
actual cause is still unknown and is now out of scope to keep chasing
without a second machine to compare against, which is not available.
**What is confirmed instead, decisively**: the destructive half of the
feature — the half that actually matters for safety — works correctly,
independent of the dialog. Reinstalling and then running `msiexec /x
smtprelayd-0.2.15-amd64.msi CLEANDATA=1` (the scripted path the header
comment already documented as the alternative to the dialog) produced
`Doing action: PurgeDataDirCA` in the log rather than `Skipping`, and
`C:\ProgramData\SMTPRelayd` was confirmed gone afterward. Combined with
every earlier run's `Skipping action: PurgeDataDirCA (condition is false)`
whenever `CLEANDATA` stayed at its default `0`, this is now verified on real
hardware in both directions: opt in and the directory is removed, don't and
it survives untouched — which is the property that actually matters for an
irreversible delete. The only unresolved piece is cosmetic: whatever is
special about this one VM image that stops `PurgeDataDlg` itself from
rendering. Left open rather than guessed at further; worth revisiting only
if a second Windows machine becomes available to compare against, or if a
future operator reports the same missing dialog elsewhere, giving something
to correlate.
**Previous session**: 2026-08-18 (twenty-first session) — Dashboard fix, no phase
work. Reported as "Das Dashboard aktualisiert sich nicht konstant wenn sich
der Status ändert": the dashboard never had any auto-refresh mechanism at
all — no htmx, no `meta http-equiv="refresh"`, no SSE/WebSocket — a fact
`MEMORY.md` already documented as a deliberate 2026-08-07/4c decision
("htmx was never added and the dashboard carries no JavaScript at all.
Adding it later is still open, and the CSP would have to allow it"). Asked
the operator to pick between the three ways to close that gap
(`meta`-refresh, htmx polling, SSE); "htmx besser bitte" reopened the
2026-08-07 decision explicitly rather than by drift. htmx 2.0.4 is vendored
as a static asset (`internal/web/static/htmx.min.js`, `embed.FS`), fetched
from the upstream GitHub release tag and cross-checked byte-for-byte
(`sha256 e209dda5…`) against the npm/unpkg mirror before being committed —
not pulled from a CDN at runtime, since a page that only ever answers on
loopback should not gain a dependency on an outside host being reachable.
The live queue, bounces, routes and per-message views, plus the header stat
tiles, now poll `hx-get="{{.CurrentURL}}"` (the request's own path and
query — `baseData` gained this field, and `base()` now takes the `*http.
Request` it is read from) every 10s and swap themselves in place via
`hx-select`/`hx-target`/`hx-swap="outerHTML"`, so sort order, pagination and
active search filters survive a refresh unchanged. Deliberately excluded
from polling: `/search` entirely (an ad hoc lookup, not a live view) and the
filter `<form>` on `/bounces` (scoped outside the polling `<div>`) — either
one being swapped on a timer would silently overwrite text the operator is
still typing, which is the standard htmx-polling footgun. CSP tightened from
bare `default-src 'self'` to `default-src 'self'; script-src 'self'` to say
explicitly that scripts load only from the dashboard's own origin; htmx's
polling needs neither inline script nor `eval`, so nothing beyond that
needed relaxing, and `docs/guides/SECURITY.md`'s "no inline scripts" line stays
true. Not build-verified — no Go toolchain is installed on this machine (a
recurring gap in earlier sessions too, e.g. the fourteenth); `go build`,
`go vet`, `go test ./...`, `gofmt`, `govulncheck` and `gosec` are all still
outstanding for this change and should run in CI or a session with a
toolchain before this is considered done. Reviewed by hand instead: every
edited template file re-read after editing for balanced `{{}}`/HTML tags,
`base()`'s new `for _, rt := range routes` loop variable renamed off `r` to
avoid shadowing the newly added `*http.Request` parameter of the same name
(caught before commit, not a live bug — Go's block scoping meant the shadow
was confined to the loop and `r.URL.RequestURI()` afterwards was always
correct, but the name reuse was confusing enough to fix), and the existing
`TestSecurityHeadersOnEveryPage` CSP-string assertion in `web_test.go`
updated to match.
**Same session, follow-up**: reported back as "refreshed nicht" — the
operator's test was specifically on `/search`, which the first pass had
excluded from polling entirely rather than only excluding its filter form,
on the reasoning (wrongly applied uniformly) that an "ad hoc lookup" page
should stay static. `/search`'s results table now polls exactly like
`/bounces` already did: scoped to a `#search-live` `<div>` around the table
and pager, outside the `<form>`, so submitted filters keep being re-run on
refresh and unsubmitted keystrokes are never touched. Also dropped the
`{{if ne .Page "search"}}` guard on the header stat tiles — that exclusion
never had a reason to exist, since the stats block sits in `layout.html`
entirely outside any page's filter form and polling it was always safe on
all four pages that show it.
**Previous session**: 2026-08-18 (twentieth session) — Field fix, no phase work.
Reported as "der windows installer bricht ab beim aktualisieren", this time
with a verbose MSI log (`msiexec /L*v`) from an actual upgrade attempt
(0.2.6 → 0.2.8) rather than reasoning alone. A second, independent defect
from the one the nineteenth session fixed: `InstallServiceCA` is conditioned
on `NOT Installed AND NOT UPGRADINGPRODUCTCODE`, meant to run only on a
genuinely fresh install and never during an upgrade. But `UPGRADINGPRODUCTCODE`
is only ever set by the engine in the *nested* `RemoveExistingProducts` call
that removes the old product — never in the new product's own execute
sequence — so `NOT UPGRADINGPRODUCTCODE` was unconditionally true there, and
`InstallServiceCA` ran on every upgrade, not only fresh installs. Since the
old product's `UninstallServiceCA` deliberately leaves the SCM registration
in place across an upgrade (correct, existing behaviour), the new product's
`InstallServiceCA` then tried to register a service that already existed;
`smtprelayd.exe install` returned exit code 1, which MSI surfaces as
Error 1722 on `InstallFinalize`, rolling the whole transaction back to
Error 1603. Confirmed directly from the pasted log: `StopServiceCA` and
`UninstallServiceCA` correctly skipped in the old product's nested removal,
files replaced cleanly, then `InstallServiceCA` executed regardless and
failed. Fixed by conditioning on `WIX_UPGRADE_DETECTED` instead — the
property WiX's `MajorUpgrade`/`FindRelatedProducts` sets (and propagates as
a secure property) in the *new* product's own sequence when an earlier
version is present, unlike `UPGRADINGPRODUCTCODE`. A second bug was
introduced fixing the first: the explanatory `<!-- -->` comment contained a
bare `--`, which is invalid inside an XML comment and broke `candle.exe` in
CI ("candle.exe failed (WiX Toolset)"); caught immediately from the CI report
and fixed by rewording, verified with `xmllint --noout`. With both fixed, the
rebuilt MSI was installed as an upgrade on real hardware and verified: no
error, exactly one service registration (no duplicate), binary on disk
replaced, service running afterwards. The Windows upgrade item in the phase 5
checklist below is now closed; uninstall and the non-admin-refusal item stay
open.
**Previous session**: 2026-08-17 (nineteenth session) — Two field-triggered fixes,
no phase work. First: "auf windows bricht das drüber installieren mit einem
Fehler ab" — the MSI's `StopServiceCA` was conditioned on `REMOVE="ALL" AND
NOT UPGRADINGPRODUCTCODE`, meant only to skip *unregistering* the service
during a major upgrade, but that same condition also skipped *stopping* it.
`UPGRADINGPRODUCTCODE` is true for the whole `RemoveExistingProducts` run, so
on every upgrade the old service kept running, held its lock on
`smtprelayd.exe`, and `RemoveFiles`/`InstallFiles` failed to replace it —
exactly the reported install-over-existing failure. Split the two actions:
`StopServiceCA` now runs on any `REMOVE="ALL"` (plain uninstall and the old
side of an upgrade alike); `UninstallServiceCA` keeps the
`NOT UPGRADINGPRODUCTCODE` guard, so the SCM registration still survives an
upgrade. Not yet verified on real hardware — reasoned from the WiX/MSI
execute-sequence semantics and the existing (verified) first-install
behaviour, not from a build-and-install cycle; the Windows upgrade cycle in
the phase 5 checklist below stays open until that happens.
Second, from a pasted CI log: `govulncheck` reported six stdlib
vulnerabilities (`net/url` quadratic complexity, `html/template` JS context
tracking, `crypto/tls` post-handshake message limits, `net/http` H2C
timeout, `encoding/asn1` recursion depth, `x/net/idna` punycode), all fixed
in `go1.25.13`; CI was still resolving `GO_VERSION: "1.25"` to `1.25.12`.
No application code was implicated. Per the existing note in `ci.yml` that a
pin must not describe a toolchain that never ran, bumped `go.mod`'s `go`
directive and both workflows' `GO_VERSION` to the exact `1.25.13`, rather
than leave the pin floating on the minor version. Verified locally:
`GOTOOLCHAIN=go1.25.13 go build ./...` and `go vet ./...` both clean.
**Previous session**: 2026-08-12 (eighteenth session) — **All eleven findings of the
second security review closed**, and separately the **Windows MSI was installed
on hardware and works**, which closes the 2026-08-11 installer defect that had
made every fresh Windows install unstartable. Details of the MSI run are under
Open defects and in `docs/dev/PHASE5-CHECKLIST.md`; the rest of this entry is the
security work, requested as "alles umsetzen". Two findings needed a
decision first and got one: `queue.failed_retention_hours` as a new key
(finding 3, both halves — count *and* sweep, since counting alone turns a full
`spool/failed` into a relay that refuses mail and sweeping alone leaves the
quota lying between sweeps), and raising both workflows to Go 1.25 rather than
lowering `go.mod` (finding 9 — `golang.org/x/sys` v0.47.0 itself declares
`go 1.25.0`, and that is the module the Windows DACL check needs, so lowering
would have forced a dependency downgrade in the wrong place).
The full write-up per finding, with the reasoning and the verification, is in
`docs/dev/Findings.md`; only what a later session needs to know is repeated here.
Two things worth carrying forward. **The smuggling fix is broader than the
finding described**: `<LF>.<CRLF>` smuggles just as well as `<LF>.<LF>`, so
`dotReader` tracks the *preceding* line's terminator as well as the dot line's
own. The Postfix shape was taken — queue the message, acknowledge it, then
close the session instead of returning the stream to the command loop —
because refusing a bare-LF end-of-data would hang every message from exactly
the legacy devices this relay exists for. **The Host-header fix covers the
metrics endpoint too**, which the finding mentioned in passing: a loopback
listener has no credential to check, so `Host` is the whole boundary there as
well. It is applied only to a loopback bind; a public metrics listener is
reached by its real name and authenticates with a token instead.
Verified live against a running relay, and — for the smuggling fix — against a
binary built from the pre-fix `HEAD` to prove the test can fail: the same
script queued two messages before the fix, the second carrying
`forged@evil.example` in its spooled envelope, and queues one after it. Also
verified live: a bare-LF legacy device still delivers, a conforming CRLF
client still sends two messages over one connection, DNS-rebinding `Host`
values get 421 on both the dashboard and metrics while `/api/v1/*` is
unchanged, `/bounces?class=` returns 200 for the first time, and a planted
two-week-old failed message was swept at startup, freeing exactly the
300589 bytes it occupied.
**gosec now runs in CI and the tree is at zero findings**, which `CLAUDE.md`
has required all along and nothing enforced. No rule is excluded and no
directory skipped: fifteen `#nosec` annotations sit on the lines they apply
to, each naming the property that makes it an exception, so a later change
that breaks that property fails the build. One gosec finding was a real
simplification rather than an exception (`baseBackoff << shift` in
`internal/api/auth.go`). Note for whoever bumps it: gosec v2.21.4 does not
build under Go 1.26; v2.28.0 is pinned.
`gofmt`, `go vet` (both GOOS), `go test ./...`, `go test -race ./...`, all
three cross-builds, `scripts/check-banned-imports.sh`, `govulncheck` v1.6.0
and `gosec` v2.28.0 all clean.
**Same session, three deferred decisions taken**, all small, none blocking:
- **Logging stays file-only on Linux**; `MEMORY.md` section 10 claimed
  "journald plus file" and was wrong. `-console` is now documented in the
  packaged unit as the way to mirror into journald, deliberately not the
  default: journald rate limits (1000 messages per 30 s) and drops the excess,
  so under a mail burst the copy an operator reads first would be the
  incomplete one. Startup failures reach journald regardless — they are
  written to stderr before the file logger exists.
- **WAL is on**, via `_pragma=journal_mode(WAL)`, the spelling modernc's
  driver actually reads. A test reads `PRAGMA journal_mode` back from the
  database, and was confirmed to fail against the old DSN spelling before
  being trusted. Verified live: `history.db-wal` and `history.db-shm` now
  appear, both 0600 — the sidecar permission handling in `Store.Open` had been
  written speculatively and had never once run.
- **`internal/logging` moved to `gopkg.in/natefinch/lumberjack.v2` v2.2.1**
  from `github.com/natefinch/lumberjack v2.0.0+incompatible`. The API is
  field-identical, so it is one import line; the win is a properly versioned
  module with its own `go.mod` and the removal of three entries from the graph
  (`+incompatible` plus the two test-only indirects the previous tidy pulled
  in). `internal/logging` had no tests at all, which is how the module could
  have been swapped for a stub and still passed CI — it now has four, covering
  0600 on creation, restricting a pre-existing 0644 file, that rotation
  actually produces a backup file, and that secret redaction survives the
  writer setup.
**Previous session**: 2026-08-11 (seventeenth session) — Second full-tree security
review, no phase work and **no code changed**. Requested as "prüfe mir das
ganze auf Schwachstellen und Sicherheit". Eleven findings, all open, written
up in `docs/dev/Findings.md` with a checklist so they can be worked one at a time;
this file carries only the pointer under "Open security findings". Three were
reproduced against the tree rather than reasoned about: a bare `<LF>.<LF>`
ends DATA and the remainder is executed as SMTP commands (the smuggling shape
— an attacker who controls only a message body on an allowlisted host gains
control of the envelope), the dashboard serves a full page for any `Host`
header, which makes the loopback-is-the-authentication decision reachable by
DNS rebinding from a page the operator visits, and `/bounces?class=` has never
worked because `FindBounces` filters on a column its own derived table does
not select. The third Medium is that `limits.spool_max_gb` does not bound disk
usage at all: `Fail()` drops a message from the index that `spoolSize()` sums,
so a permanently failing message frees quota while still occupying the disk,
and nothing ever prunes `spool/failed`. Baseline was clean: `gofmt`, `go vet`,
`go test ./...` and `govulncheck` v1.1.4 (run locally this time, no
vulnerabilities). What the review confirmed solid is recorded in
`docs/dev/Findings.md` too, so the next review starts from it instead of
repeating it.
**Previous session**: 2026-08-11 (sixteenth session) — Dashboard visual redesign
plus a configurable colour theme, no phase work. Requested as "make the
dashboard fancy, and let the colours be customised in the config file".
`internal/web/static/style.css` was rewritten around the design tokens it
already had: sticky header with an accent gradient, nav pills marking the
current page (new `baseData.Page`, `s.base(page)`), stat tiles summing the
per-route counters the metrics registry already holds — no query was added for
them — status pills instead of coloured text, card surfaces, a filter bar,
hover and focus states, a byte formatter (`bytes` template func), and a dark
scheme. The dark scheme is `prefers-color-scheme` plus a `data-theme`
attribute on `<html>`, so `mode = "light"|"dark"` pins a scheme with no
JavaScript, which the CSP would forbid anyway. New `[web.theme]` section:
`mode` and ten colours (`accent`, `accent_text`, `background`, `surface`,
`border`, `text`, `muted`, `ok`, `warn`, `danger`), each optional.
**The security-relevant part**: these values are written into a CSS
declaration, where there is no contextual escaper — so they are restricted to
literal `#rgb`/`#rrggbb`, rejected at load time in `internal/config` and
dropped again in `internal/web.themeOverrides`, the same doubled check the
config view uses for secrets; the property names are a fixed set in the code
and never come from the file. `#fff; } body { display: none` and four other
injection-shaped values are regression-tested. The override block is emitted
with the same selector list as the dark scheme so it wins in both schemes,
which is why an override applies to light and dark alike (documented in the
example config and the README). `--surface-2` is derived with `color-mix()`
from the configured surface and text rather than being a fixed neutral, so a
warm palette does not get blue-grey table headers. Verified by rendering the
real handler headless in Chrome across all six pages, in light, in dark, and
under a custom amber palette, and the README screenshot
(`docs/guides/img/dashboard-queue.png`) was regenerated from the new dashboard.
`gofmt`, `go vet` (both GOOS), `go test ./...` and both cross-builds clean;
`scripts/check-banned-imports.sh` clean for all three targets.
**Previous session**: 2026-08-11 (fifteenth session) — Message metadata journal, no
phase work. Developed in parallel with the fourteenth session and merged into
it (`34077ac`); its own commit is `a63b216`. Requested as "logging of all
mails", scoped after checking what already existed: every accepted message was
already journalled (a row in `messages` plus a `message accepted` log line) and
every attempt recorded with its verbatim SMTP response, so the gap was in
*what* a row carried, not in whether one existed. `messages` gained
`message_id`, `content_type`, `size_bytes`, `header_count` and `helo`; all five
are read from what was actually spooled (the rewritten header block via a new
`rewrite.HeaderCount` alongside the existing `HeaderValue`, and
`spool.Staged.Size()`), never from what the client announced, and all five go
through `sanitizeHeaderMeta` — the generalised `sanitizeSubject`, which now
also truncates on a rune boundary instead of mid-rune. Since `CREATE TABLE IF
NOT EXISTS` never touches an existing table, `Store.migrate` adds missing
columns via `PRAGMA table_info` plus `ALTER TABLE`; they are nullable with no
default, so a pre-migration row reads back as unknown rather than as a
fabricated zero. `RecordMessage` became `RecordMessage(MessageRecord)`: with
the new fields it would otherwise have been eleven consecutive string
parameters, where two transposed at a call site still compile. Second half,
from the follow-up ask ("is this enough for troubleshooting? add the SMTP
code"): `Message` now carries `AttemptCount`, `LastCode` and `LastErr` from the
latest attempt in the list queries too, so the queue, search and bounce views
show *why* something is deferred without opening each message. That surfaced a
real bug — `bounces.html` has always rendered `{{.LastErr}}` but `FindBounces`
never selected an attempt row, so the dashboard's "Last response" column was
silently empty for every bounce ever shown. Verified against a running
instance, not only by unit test: a message sent through the real listener
recorded HELO, Message-ID, Content-Type, 512 bytes and 7 headers; a deliberate
`550` from a fake smarthost showed as `550 5.1.1 User unknown...` on the
bounces page and as `last_smtp_code` in the API; the journal columns were then
dropped from the live database with `ALTER TABLE DROP COLUMN` and re-added on
the next start ("store: schema migrated" ×5), with the pre-migration row still
readable and its journal fields absent from the JSON rather than zeroed.
**This session also cleared the toolchain debt the thirteenth and fourteenth
sessions left open**: on the merged tree `gofmt`, `go vet` (linux *and*
`GOOS=windows`), `go test ./...` and both cross-builds are clean, so the
Windows `syncDir`/`Chmod` split and `config.SecureDataDir` are now
compile-checked. An MSI build and an install on hardware are still outstanding.
`govulncheck`/`gosec` were not run locally (not installed on this machine; CI
covers them).
Same session, a documentation-hygiene pass, each item checked against the tree
rather than against the session notes: `docs/dev/PHASE5-CHECKLIST.md`'s
"Follow-up implementation work" listed the Windows ACL check, the CI workflow
and the log-rotation decision as open although all three shipped, and still
said phase 4 had not started; phase 1's own Windows-ACL box contradicted
phase 5's in this file. Both fixed. `MEMORY.md` §2 named
`emersion/go-smtp`, `emersion/go-sasl`, `emersion/go-message` and
`golang.org/x/oauth2` as technology decisions — a pre-phase-1 plan that was
never how the code was written; none has ever been in `go.mod`, the SMTP
server, client, SASL, header parsing and the OAuth2 flow are all first-party
over `net/smtp` and `net/http`. The table now describes the tree, which
matters because the small runtime dependency set is what section 9's posture
rests on. Two smaller drifts in the same table: the logging row named the
`gopkg.in/...v2` module while the code imports `github.com/natefinch/
lumberjack`, and the dashboard row named htmx, which phase 4c never needed and
never added — the dashboard carries no JavaScript at all.
Then finding 3 of the 2026-08-11 security review, on request: `log.file` was
joined to `service.data_dir` with no validation. The traversal was reproduced
against a binary built from `HEAD` before fixing it — `check` passed and the
daemon wrote its log to `/tmp/escaped.log` — so the fix is against a
demonstrated defect, not a suspected one. `config.LogPath` is now the only
place the two values meet, called by `Validate()` and by the code that opens
the file, so the validation cannot be refactored away from the construction.
It rejects an absolute path, a Windows volume name, a NUL byte and any `..`
element split on *both* separators (a configuration written on Windows is
routinely deployed on Linux, where `..\..` survives `Clean` as one long file
name), then re-checks containment on the result rather than trusting the
element scan. The check is deliberately lexical and says so: it proves the
configured value cannot name a location outside the data directory, not that
the path is safe to open — a symlink inside the data directory is
`CheckDir`/`CheckDataDirACL`'s job. The six findings now have a section of
their own under "Known gaps"; they had never been recorded in this file.
**Found and not fixed then; fixed 2026-08-12** as finding 9 of the second
review: `go.mod` declared `go 1.25.0` (raised in `47fe229` with no note
anywhere), while `.github/workflows/ci.yml` and `release.yml` pinned
`GO_VERSION: "1.23"`. The build only worked because the default
`GOTOOLCHAIN=auto` silently downloaded a newer toolchain than the workflow
pinned, so the pinned version was not what CI ran. Both workflows now pin
1.25.

**Previous session**: 2026-08-11 (fourteenth session) — Installer fix, no phase
work. The MSI never produced a data directory that `CheckDataDirACL` accepts,
so no fresh Windows install could start; `util:PermissionEx` adds ACEs but
leaves the DACL inheriting from `%ProgramData%`. Replaced by
`config.SecureDataDir`, invoked as `smtprelayd secure-datadir` from a deferred
custom action after the service registration, and named as the remediation in
`CheckDataDirACL`'s own error message. Not compile-checked and no MSI built in
that session — no Go toolchain or WiX available; `gofmt`, `go vet` (both GOOS)
and `go test ./...` were run in the fifteenth session and are clean, so only
the MSI build and an install on hardware remain outstanding. See Open defects
for the full write-up.
**Previous session**: 2026-08-11 (thirteenth session) — Field fix, no phase work.
A Windows deployment accepted mail but failed every enqueue and every delivered
message's cleanup with `sync ...\spool\queue: Access is denied`. `syncDir`'s
comment already said directory fsync "is not supported on Windows and fails
with EACCES or similar", but the code only filtered `os.ErrInvalid`, so the
EACCES it predicted was returned to the caller and aborted the operation.
`FlushFileBuffers` needs a handle opened with `GENERIC_WRITE`, which cannot be
obtained for a directory, so the call could never have succeeded there — it is
now a no-op on Windows via a build-tag split (`dirsync_windows.go` /
`dirsync_unix.go`) rather than an error class the caller tries to recognise.
Durability is unaffected: the metadata and body files are individually fsynced
before the rename, and NTFS journals the rename. On Unix a directory fsync
failure is still fatal, unchanged. Same split applied to the `os.Chmod(d,
0o700)` in `Open` — the second symptom of the same deployment, `chmod
...\spool\tmp: Access is denied`. Mode bits do not govern access on Windows
(`os.Chmod` only toggles the read-only attribute); the data directory's
explicit DACL does, which the installer sets and `CheckDataDirACL` already
verifies at startup. Not compile-checked in that session — no Go toolchain was
available; `gofmt`, `go vet` (both GOOS) and `go test ./...` were run in the
fifteenth session and are clean.
Field-verified on the reporting host the same day: with the patched binary and
a corrected DACL the relay logs `message accepted` and delivers, where before
it accepted and relayed the message but then failed both the enqueue and the
delivered-message cleanup. Separately found in that session and fixed in the next: the
Windows installer never set that DACL, so no fresh install started at all.
**Previous session**: 2026-08-11 (twelfth session) — Field fix, no phase work. A
deployed instance passed `check` and then failed every start with
`listen tcp 10.0.0.10:25: bind: cannot assign requested address`: the example
config's placeholder address had been kept and is not assignable on that host.
Validation could not have caught it — `net.SplitHostPort` proves an address is
well formed, and nothing short of an actual bind proves it is assignable — so
`check` now binds and immediately releases every listener, dashboard and
metrics address (`cmd/smtprelayd/bind.go`). Two error classes are notes rather
than failures, because treating them as failures would make `check` lie in the
common case: address-in-use (the normal result when validating the config of a
running instance) and permission-denied (the service reaches ports below 1024
through `CAP_NET_BIND_SERVICE`, which a shell user invoking `check` does not
have). In-use detection needs a per-OS file: Winsock's `WSAEADDRINUSE` is a
different number from the syscall package's `EADDRINUSE` and does not compare
equal to it. Second half of the same failure: the packaged unit has
`RestartSec=5`, so systemd's default start limit of 5 starts per 10 s can
never trip, and the instance restarted 87 times with the cause buried in the
journal; `StartLimitIntervalSec=60` / `StartLimitBurst=5` now put the unit into
`failed` instead. Verified against the reported configuration: `check` exits 1
with the daemon's own bind error, and reports the `0.0.0.0:587` listener as an
unverified note. The example config's placeholder is now marked as one.

**Previous session**: 2026-08-11 (eleventh session) — Implemented phase 4e per
`docs/dev/PHASE4-PLAN.md` and `MEMORY.md` §8. `internal/bounce.Notifier` batches
permanently-failed and expired messages (recorded via a new `RecordFail`
call from `delivery.Manager.fail()` — the single choke point every "moved to
spool/failed" path already went through, so no call site needed to change
individually) into a digest mail per client every `[bounce].digest_minutes`,
sent through the configured `notify_route`. Composed from the store's own
`FindMessageByID` at dispatch time, not from data threaded through
`RecordFail`, so the digest is never more than one lookup away from the
authoritative record and automatically respects `retain_subjects`
redaction the same way the dashboard and API do. The three loop-prevention
properties: an empty envelope sender (`net/smtp`'s `Mail("")` already
renders `MAIL FROM:<>`, so no special-casing was needed there), never
passing through the listener at all — which is what actually keeps a
notification out of sender rewriting, since rewriting is architecturally a
listener-only concern — and a new `spool.Envelope.Notification` bool
(persisted, so it survives a restart) that `delivery.Manager` checks before
ever calling `RecordFail` again, which is exactly how a notification loop
would start. A notification's own delivery outcome is kept out of the
relay's own delivered/bounced/deferred/auth-failure counters (would
otherwise conflate postmaster mail with client traffic) and instead
increments a new unlabelled `smtprelayd_notification_failures_total`.
The volume cap (`[bounce].max_per_hour`) suppresses sending once reached but
carries the suppressed client's failures into the next hour's digest rather
than dropping them, per the plan's "records them for the next hour."
Extended `[bounce]`/`[client.bounce]` validation: a client may only override
`.notify` (matching what the notifier actually reads), so a client setting
`.sender`, `.notify_route`, `.digest_minutes` or `.max_per_hour` — which
would silently do nothing — is now a startup error instead of the "looks
configured but does nothing" trap `CLAUDE.md`'s strict-decoding philosophy
otherwise closes; `.sender` is now required (not previously validated)
since an RFC 5322 message without a From header is a red flag to most mail
systems. Manually verified end to end against a running instance with a
fake SMTP server that permanently rejects every recipient: the original
message bounced, a digest was queued on schedule (`digest_minutes = 1`),
the digest itself bounced against the same fake server, and — checked
across multiple further digest cycles — no second notification was ever
generated; exactly one digest and the original message ended up in
`spool/failed`, both with their history retained. `GOOS=windows`/
`GOOS=linux` build clean, `gofmt`/`go vet` clean, `go test ./...` green (no
`-race` locally, this machine's `CGO_ENABLED=0`; unaffected on the CI
runner).
**Previous session**: 2026-08-10 (tenth session) — Implemented phase 4d per
`docs/dev/PHASE4-PLAN.md` and `docs/guides/API.md`. `internal/api` serves the bearer-
token-authenticated JSON API: `GET /health` (no auth), `GET /bounces`,
`GET /messages`, `GET /messages/{id}`, `GET /queue` (read scope), and
`POST /messages/{id}/requeue` / `DELETE /messages/{id}` (admin scope).
Bearer tokens are compared constant-time against `Web.Tokens[].SHA256`
(every candidate compared, not just until the first match, so timing cannot
reveal how many were tried); failed attempts are logged with the source
address, counted in a new unlabelled `smtprelayd_api_auth_failures_total`
metric (deliberately unlabelled — a source-address label would let an
attacker grow the exposition without bound), and rate-limited per source
address with exponential backoff (5 failures/minute before a 30s-to-10min
backoff, pruned opportunistically so cycling source addresses cannot grow
the tracker without bound). Pagination is cursor-based
(base64 JSON `{offset,limit}`) via a new `internal/api/cursor.go`.
Realised partway through that the dashboard's requeue/delete forms
*cannot* authenticate to a bearer-token-protected endpoint: the server
process never holds a token's plaintext, only its SHA-256 digest, by
design. Resolved by giving the dashboard its own POST
`/messages/{id}/requeue` and `/messages/{id}/delete` handlers directly in
`internal/web`, protected by a new per-process HMAC CSRF token
(`internal/web/csrf.go`) instead of a bearer token — matching
`docs/dev/PHASE4-PLAN.md`'s own text ("REST API calls... do not use CSRF") more
faithfully than its file-list suggestion of putting CSRF logic under
`internal/api`. Both entry points call the same underlying `spool.Requeue`/
`spool.Discard` (new methods — 4a/4b never gave the spool a way to act on a
message once `Fail` had moved it to `spool/failed`, which requeue/delete
both need for a bounced message) and `store.RecordAudit`, with
`token_name` set to the bearer token's configured name for the API path and
the fixed string `"dashboard"` for the web path. Both `Requeue` and
`Discard` refuse a message currently leased to a delivery worker
(`spool.ErrBusy`, mapped to 409) rather than racing the worker's own
`Release`/`Remove` call, which could otherwise resurrect a message `Discard`
just deleted. `internal/web` and `internal/api` are now mounted on the
single `[web].address` listener the plan calls for, `/api/v1/` stripped
before dispatch. Added `store.FindBounceSummaries` to match `docs/guides/API.md`'s
flattened bounce JSON shape (final class, attempt count, first/last attempt
timestamp) — different from the dashboard's full-attempts-list shape. While
building it, **found and fixed a real bug** in three existing "latest
attempt" queries (`FindMessages`, `CountQueue`, and the new
`FindBounceSummaries`): the tiebreak was `MAX(at_time)`, but `at_time` has
only second precision, so two attempts landing in the same wall-clock second
both matched and fanned the join out into duplicate rows for one message.
Fixed by tiebreaking on the attempts table's autoincrement `id` instead,
which is unique by construction. Also found and fixed a latent bug in three
test helpers (`store`, `web`, and the new `api` package) that construct a
`*slog.Logger` via `slog.NewTextHandler(nil, nil)`: the nil writer panics
the instant a log call actually fires, which none of the existing tests had
done — this session's tests do, since auth failures and query errors both
log. Manually verified end to end against a running instance: `/api/v1/health`
with no token, a 401 on a missing/wrong token, a 403 on read-scope trying an
admin action, requeue and delete both succeeding with an admin token and
recording an audit row, delete leaving the history row intact while removing
it from `/api/v1/queue`'s counts, the rate limiter returning 429 with
`Retry-After` after 5 failures from one source and recovering after the
backoff, a different source unaffected by another's failures, and the
dashboard's own CSRF-protected requeue form succeeding with no bearer token
at all while a missing or garbage CSRF token gets 403. `GOOS=windows`/
`GOOS=linux` build clean, `gofmt`/`go vet` clean, `go test ./...` green (no
`-race` locally, this machine's `CGO_ENABLED=0`; unaffected on the CI
runner).
**Previous session**: 2026-08-10 (ninth session) — Implemented phase 4c per
`docs/dev/PHASE4-PLAN.md`: `internal/web` is a server-rendered, JavaScript-free
dashboard (`html/template` with strict auto-escaping, `embed.FS` for
templates and CSS) with six pages — live queue (`/queue`, sortable by
sent/status/client/route, showing only messages still in the spool), search
(`/search`, filters on sender/recipient/subject/status/client/route/time
range), bounces (`/bounces`, same filter set plus failure class), per-message
detail (`/messages/{id}`, full envelope and every delivery attempt),
route status (`/routes`, reuses `metrics.Registry.Status()` so the dashboard
and `/metrics` can never disagree about a route's state), and a read-only
config view (`/config`, listener/client/route/bounce sections, secrets always
rendered as a literal `"[redacted]"` string, never by relying solely on
`Secret.String()`'s own redaction). Security headers
(CSP/X-Content-Type-Options/X-Frame-Options/Referrer-Policy) are applied to
every response via middleware. The `{id}` path parameter is validated through
`spool.ParseID` before it ever reaches a query, per the rule that a queue ID
is a validated type, never a raw string. `internal/store` gained the pieces
this needed that 4a hadn't: `MessageFilter.Sender`/`.Subject` and
`BounceFilter.Sender`/`.Subject` (substring filters the plan's search/bounce
views require but the schema didn't yet expose), `MessageFilter.Sort`/
`.Order` with a column allowlist (including a `status` sort backed by a `CASE`
expression over the derived attempt class, since "sortable by status" has no
real column to sort on), and a `Status: "active"` shorthand for "queued or
deferred" so the live queue view doesn't need two queries merged in Go. Also
discovered and fixed that `MessageFilter.Status` existed in the 4a struct but
was never actually applied in `FindMessages`'s WHERE clause — status
filtering silently did nothing before this session. Added `metrics.Serve`'s
sibling `web.Serve`, which additionally serves HTTPS with `cfg.TLS`'s
certificate when `[web].address` is non-loopback, since `internal/config`
already refuses to start such a configuration without one — a validation
that would otherwise have had no effect on what the listener actually spoke.
Verified manually against a live instance: dashboard loads with all four
security headers present, a message sent through the real SMTP listener with
subject `<img src=x onerror=alert(1)>` renders HTML-escaped everywhere
(queue, search, per-message), search-by-subject-substring finds it, the
route status page reflects the same queued/deferred counts `/metrics` would
report, the config view never shows a resolved OAuth2 client secret (also
covered by a unit test using a real environment-variable-resolved secret,
not just a literal string), an invalid queue ID returns 400, and `POST
/queue` returns 405. `GOOS=windows`/`GOOS=linux` build clean, `gofmt`/`go
vet` clean, `go test ./...` green (no `-race` locally, this machine's
`CGO_ENABLED=0`; unaffected on the CI runner).
**Previous session**: 2026-08-10 (eighth session) — Implemented phase 4b per
`docs/dev/PHASE4-PLAN.md`: `internal/metrics.Registry` (hand-written Prometheus
text exposition, no `prometheus/client_golang` dependency per the existing
decision) exposes `smtprelayd_queue_size{route,state}` (read live from a new
`spool.QueueDepth`, which classifies each spooled message as queued or
deferred by comparing `NextAttempt` to now — a leased, in-flight message
counts as queued rather than vanishing from the gauge mid-attempt),
`smtprelayd_delivered_total`, `smtprelayd_bounced_total` (covers both
permanent failures and expiry, matching `store`'s bounced classification),
`smtprelayd_deferred_total`, `smtprelayd_auth_failures_total`,
`smtprelayd_oauth_token_age_seconds` (needed a new `authms365.TokenSource.
TokenAge`, which required adding an `issued` timestamp the type did not
previously track), `smtprelayd_last_delivery_time`, and
`smtprelayd_delivery_rate_per_minute` (delivered_total / uptime, the
approximation the plan calls for rather than a true rolling window). Counters
are seeded at zero for every configured route at startup so a route with no
events yet is still present in the exposition. To make `auth_failures_total`
possible at all, `internal/delivery/smarthost` gained a new `AuthError` type
— credential-related temporary failures (a rejected secret, an expired
token, a rejected XOAUTH2 challenge) previously used the same `TempError` as
every other retryable failure, which is correct for retry behaviour but made
them indistinguishable from a dead smarthost for the metric the plan asks
for; `AuthError` retries identically, it only adds a type `errors.As` can
match on. `delivery.Manager` now owns the registry (built in `New` from the
same route list and token sources it already assembles) and exposes it via
`Manager.Metrics()`; `cmd/smtprelayd/main.go` starts `metrics.Serve` as a
goroutine when `[metrics].enabled`, sharing the same shutdown context as
everything else. Added `metrics.path` must-start-with-`/` validation
(`address` was already validated). Verified manually against a live instance,
not just unit tests: sent a message through the SMTP listener, watched
`queue_size{state="queued"}` go to 1, watched the delivery worker fail against
a deliberately dead port, and watched it move to `state="deferred"` with
`deferred_total` incrementing and `auth_failures_total` correctly staying at 0
(a connection refusal is not a credentials failure); confirmed `POST
/metrics` returns 405 and an unconfigured path returns 404. `GOOS=windows`/
`GOOS=linux` build clean, `gofmt`/`go vet` clean, `go test ./...` green (no
`-race` locally, this machine's `CGO_ENABLED=0`; unaffected on the CI
runner).
**Previous session**: 2026-08-10 (seventh session) — Verified phase 4a end to end
against `docs/dev/PHASE4-PLAN.md`'s definition of done; most of it (schema, `Open`/
`RecordMessage`/`RecordAttempt`/`RecordAudit`, `FindMessages`/`FindBounces`/
`FindMessageByID`/`CountQueue`, `[history]` validation, wiring into
`internal/listener/session.go` and `internal/delivery/delivery.go`,
`modernc.org/sqlite` in `go.mod`) was already in place from an earlier,
unlogged session. Found and fixed two real gaps while verifying: (1) the
schema declared `ON DELETE CASCADE` on `attempts`/`audit` but SQLite never
enforces foreign keys unless a connection turns it on, and nothing did —
`Store.Open`'s DSN now carries `_pragma=foreign_keys(1)`, which
`modernc.org/sqlite` applies per connection, so retention cleanup on
`messages` now actually cascades instead of leaving orphaned `attempts`/
`audit` rows forever; this also turns `RecordAttempt` for an unknown queue ID
into a rejected write instead of a silent orphan. (2) `subject` was wired
through the schema and `RecordMessage`'s redaction but the listener never
extracted it — it always stored the empty string regardless of
`retain_subjects`. Added `rewrite.HeaderValue` (reuses the package's own
header-block parser, best-effort: a block that fails to parse yields "" rather
than an error) and a `sanitizeSubject` helper in `internal/listener`
(strips control characters, caps at 500 runes — display metadata, not a
header written back onto the wire, so stripping instead of rejecting the
message is the right call here, unlike the From-rewriting path). Added
regression tests for both fixes plus a SQL-injection-shaped recipient filter
test per the phase 4a test plan (already parameterized, confirmed safe).
`GOOS=windows`/`GOOS=linux` build clean, `gofmt`/`go vet` clean, `go test
./...` green (no `-race` locally, this machine's `CGO_ENABLED=0`; unaffected
on the CI runner). Manual end-to-end test against a live tenant (send →
history row → attempt row) still outstanding, same blocker as phase 3.
**Previous session**: 2026-08-10 (sixth session) — CI's windows/amd64 cross-build
was broken: `golang.org/x/sys/windows` had moved `GetNamedSecurityInfo` to a
string-based, two-return signature and replaced `SECURITY_DESCRIPTOR.DACL`'s
4-value return and the nonexistent `ControlBits`/`AccessEntryCount` helpers
with `Control()` and the exported `ACL.AceCount` field since
`CheckDataDirACL` (`internal/config/trust_windows.go`) was written. Fixed to
the current API; also dropped an unused `fmt` import in
`cmd/smtprelayd/verify_windows.go` that surfaced once the config package
compiled again. Confirmed `GOOS=windows` and `GOOS=linux` both build clean,
`gofmt`/`go vet` clean, `go test ./...` green (no `-race` locally — this
machine's `CGO_ENABLED=0`, `-race` needs cgo; unaffected on the CI runner).
Also corrected two stale entries found while cross-checking `MEMORY.md`/
`PROGRESS.md` against the code: `internal/api` and `internal/bounce` were
missing from `MEMORY.md` §3, and its Go version pin still said 1.22 after the
1.23.0 bump on 2026-08-08.
**Previous session**: 2026-08-10 (fifth session) — All seven known security gaps
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
**Next action, phase 5**: the `.rpm` path is **fully verified** on a live
Fedora host (2026-08-11) — 11 of 12 checklist items, the whole cycle: first
install with the unit registered but neither started nor enabled, configure,
`check`, start with port 25 bound by uid 963 rather than root (which is what
proves `AmbientCapabilities=CAP_NET_BIND_SERVICE` works), stop, an `rpm -U`
upgrade that restarts the running service into the new binary, `dnf remove`
that keeps the data and the service account, and a reinstall onto the
surviving data directory. Two things were found and fixed along the way: the
missing restart on upgrade (see Open defects) and the misleading first-install
text on an upgrade. That left one open decision, **answered 2026-08-12**: the relay's own
startup line goes to the log file and never to journald, while `MEMORY.md`
section 10 claimed both. The documentation was wrong, not the unit — the file
stays authoritative and `-console` is documented in the unit as the way to
mirror into journald, deliberately not enabled by default because journald
rate limits and drops the excess.
The **Windows MSI was installed on hardware on 2026-08-12** and the
first-install path works end to end — install, service registered as
`NT SERVICE\smtprelayd` and not running, configure, `check`, start, log line,
stop. That closes the 2026-08-11 installer defect, which had made every fresh
Windows install unstartable, and it is the last thing that was blocking a
release.
Still open for phase 5, none of it blocking: the `.deb` sequence on
Debian/Ubuntu (verified on nothing so far, unlike the `.rpm`), and on Windows
the upgrade cycle, the uninstall path and a non-admin install being refused.
The Windows upgrade is the one worth doing first — its Linux equivalent found
a real defect, and the MSI's `secure-datadir` custom action is sequenced to
run on upgrade and repair without anything having exercised it.

## Phases

### Phase 0 — Scaffolding ✅

### Phase 1 — Minimum viable relay ✅ (untested against a live smarthost)

- [x] `internal/config`: TOML schema, strict decoding, CIDR overlap detection,
      fail-closed checks per `docs/guides/SECURITY.md` section 2, `Secret` type that
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
- [x] Windows ACL verification at startup — deferred to phase 5 with the
      installer and done there (`config.CheckDataDirACL`); listed again under
      phase 5 rather than only here
- [ ] MIME nesting depth bound (no MIME parsing exists yet; the header limits
      cover the current surface). **Deprioritised 2026-08-21**: "Mime-Nesting
      auch [hinten anstellen]" — no current pressure since there is no MIME
      parsing to bound yet; revisit if MIME parsing is ever added.

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
- [x] `docs/guides/MS365-AUTH.md` verified against a real tenant — closed
      2026-08-21 ("ms schaut gut aus"), on the substance rather than a fresh
      re-read of the doc: the twenty-sixth session already confirmed live
      mail delivery through the M365 route, with both a `file:` and a
      `dpapi:` client secret, against the operator's real tenant
- [ ] Sovereign cloud authorities (`login.microsoftonline.us`, China) — needs a
      schema decision, deliberately not configurable today. **Deprioritised
      2026-08-21**: "US/china stellen wir auch hinten an, das MS365
      funktioniert!" — the standard commercial cloud authority is what is
      actually deployed and working; revisit only if a sovereign-cloud tenant
      is ever needed.

### Phase 3 — Client policy and rewriting ✅ (compiles clean, untested against a live tenant)

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
Note, not an open item: per-client rate limiting in the listener and the
route-level pacing from phase 2 remain separate and both apply. No decision
needed; recorded so it is not rediscovered. It was written as an unticked
checkbox until 2026-08-11, which made settled behaviour read as pending work.

### Phase 4 — Observability ✅ (all of 4a–4e done, see `docs/dev/PHASE4-PLAN.md`)

Planned in five sub-phases (4a–4e), with implementation order determined by
dependencies. Detailed plan in `docs/dev/PHASE4-PLAN.md` (2026-08-10).
- [x] 4a: `internal/store` (SQLite message and attempt history) — schema,
      `RecordMessage`/`RecordAttempt`/`RecordAudit`, retention cleanup with
      working FK cascade, `FindMessages`/`FindBounces`/`FindMessageByID`/
      `CountQueue`, `[history]` validation, wired into the listener and
      delivery manager, subject extraction. Manual end-to-end test against a
      live tenant still outstanding. Extended in the fifteenth session into a
      per-message metadata journal (`message_id`, `content_type`, `size_bytes`,
      `header_count`, `helo`, plus the latest attempt's code, response and
      count on the message row), with `Store.migrate` for existing databases.
- [x] 4b: `internal/metrics` (Prometheus `/metrics` endpoint) — queue size,
      delivered/bounced/deferred/auth-failure counters, OAuth token age, last
      delivery time, approximate delivery rate; all seeded at zero per route;
      manually verified against a running instance (accept → queue_size,
      fail → deferred, 405/404 on bad requests).
- [x] 4c: `internal/web` (dashboard, read-only) — queue/search/bounces/
      per-message/routes/config pages, security headers, subject redaction
      display, secrets never rendered; manually verified against a running
      instance including an XSS-shaped subject and a real resolved OAuth2
      secret.
- [x] 4d: `internal/api` (JSON API, admin actions, audit log) — bearer-token
      auth (read/admin scope) with constant-time comparison, per-source
      rate limiting with backoff, cursor-based pagination, `spool.Requeue`/
      `.Discard` shared by both the API and the dashboard's own
      CSRF-protected requeue/delete forms (the dashboard cannot use bearer
      tokens: the process never holds their plaintext). Manually verified
      end to end, including the rate limiter and the dashboard action
      forms with no bearer token at all.
- [x] 4e: `internal/bounce` (notification batching and volume capping) —
      digest per client every `digest_minutes`, hourly volume cap that
      carries suppressed failures into the next hour rather than dropping
      them, three independent loop-prevention properties (null envelope
      sender, never through the listener, a persisted `Notification` flag
      the delivery manager checks). Manually verified end to end against a
      fake SMTP server that permanently rejects everything, including that
      the digest's own bounce never produced a second notification across
      several digest cycles.

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
      directives from `docs/guides/SECURITY.md` section on process isolation
- [x] `.deb`/`.rpm` via nfpm (`packaging/linux/nfpm.yaml`), creates the
      `smtprelayd` system user/group and fixes ownership on
      `/etc/smtprelayd` and `/var/lib/smtprelayd` in a postinstall script;
      never starts the service on install
- [x] `.msi` via WiX (`packaging/windows/smtprelayd.wxs`), ACLs
      `%ProgramData%\SMTPRelayd` to Administrators + the virtual service
      account only, no inherited access; registers but does not start the
      service — **first install verified on real Windows hardware 2026-08-12**:
      install, files in place, service registered as `NT SERVICE\smtprelayd`
      and not running, configure, `check`, start, log line, stop. Uninstall and
      the upgrade path are **not** verified; this line claimed both until
      2026-08-12 and never had evidence for either. The upgrade path had a
      defect fixed 2026-08-17 (a running service locked `smtprelayd.exe`,
      failing every install-over-existing) but the fix itself is reasoned
      from MSI semantics, not yet run on hardware — see the nineteenth
      session above
- [x] `.github/workflows/release.yml`: builds, tests, SBOM, all three package
      formats, SHA-256 checksums, build provenance attestation, `gh release
      create` — no third-party release action
- [x] Windows ACL verification at startup: CheckDataDirACL verifies that the
      data directory has the explicit DACL set by the MSI (Administrators +
      NT SERVICE\smtprelayd, protected from inheritance); whitelisted exception
      for unsafe.Pointer usage in trust_windows.go for LocalFree API call
- [x] Real end-to-end test of install → configure → start → stop on Windows
      (2026-08-12, from an MSI built after the `secure-datadir` fix)
- [x] Windows upgrade cycle (version B's MSI over a running version A) —
      verified on hardware 2026-08-18 (twentieth session, the
      `WIX_UPGRADE_DETECTED` fix); this line was left unchecked when that
      session closed the item in prose but never came back to the checklist
- [x] Uninstall path and a non-admin install being refused rather than
      silently degraded — both field-verified 2026-08-18 (twenty-second
      session): a non-admin install triggers a UAC elevation prompt rather
      than installing unelevated or failing silently, and plain uninstall
      completes. Uninstall optionally purging `%ProgramData%\SMTPRelayd` is
      new the same session (see below): the destructive logic itself is now
      hardware-verified via the scripted path (`CLEANDATA=1` on the command
      line — directory confirmed removed, and left untouched whenever
      `CLEANDATA` stays at its default `0`); the interactive `PurgeDataDlg`
      prompt does not render on the one test VM available at the time, cause
      unresolved then, tracked below rather than blocking this item.
      **Root cause identified 2026-08-21 (twenty-ninth session)**, on a
      second, genuinely separate physical Windows 11 machine showing the
      identical signature: not VM/RDP-specific after all, but Windows
      Installer's own `MSI_LUA` compatibility shim forcing
      `CLIENTUILEVEL=None` for a UAC-split-token Administrator running a
      maintenance operation (uninstall) on an already admin-assigned
      per-machine product — decided client-side before the package is even
      opened, so nothing in `smtprelayd.wxs` can affect it. See that
      session's entry above for the verbose-log evidence
- [ ] Linux `.deb` install → configure → start → stop cycle on Debian/Ubuntu
      (the `.rpm` path is fully verified on Fedora; the `.deb` has a smoke
      test only, 2026-08-21, run inside WSL on the MSI test VM `ATAXVM-STSC`
      rather than a standalone Debian/Ubuntu host or VM — three
      deployment-config faults found and fixed with no code change (config
      file mode, `data_dir` pointed at `/etc/smtprelayd` instead of
      `/var/lib/smtprelayd`, missing client CIDR), see the twenty-fifth
      session above; still not the verification this item asks for)
- [ ] Windows service start failure actually reported to the SCM — added
      2026-08-21, reasoned from the kardianos/service contract and verified
      by unit/race tests only, never against a real Windows service: break
      `smtprelayd.toml` (or occupy a configured listener port) on
      `ATAXVM-STSC`, start the service, and confirm `services.msc`/
      `Get-Service` shows it stopped with an error — not silently "running" —
      and that the reason is in `smtprelayd.log`/`smtprelayd-error.log`.
      **Deprioritised 2026-08-21**: "das windows startup verhalten passt auch"
      — accepted on the reasoning/test-level evidence above, not on a
      hardware run; still genuinely unverified on real hardware, revisit if
      it becomes relevant again rather than treated as confirmed working.
- [ ] MSI Finish/success dialog — added 2026-08-21 (twenty-ninth session),
      `WixUIExtension`'s stock `ExitDialog`/`UserExit`/`FatalError` referenced
      via `<UIRef Id="WixUI_ErrorProgressText" />` and three new `<Show>`
      entries in `InstallUISequence` (`smtprelayd.wxs`), so both install and
      uninstall end with a Finish screen instead of silently closing. No WiX
      toolchain in this environment; only `xmllint --noout` clean, not
      build-verified. Next release build and next install/uninstall on
      hardware confirm it.
- [ ] WiX Burn bootstrapper wrapping the `.msi` — scoped 2026-08-21 (twenty-
      ninth session) to fix the `MSI_LUA`/`CLIENTUILEVEL` UI suppression
      documented above: requests elevation once before `msiexec` runs, so
      Apps & Features uninstall (the operator's real trigger) is no longer
      silently downgraded to no UI. Not started — deliberately staged after
      the Finish-dialog change above so that smaller, self-contained change
      can be verified on its own first. Will replace the shipped `.msi` with
      a bootstrapper `.exe` registered in Apps & Features, add
      `burn.exe`/`insignia.exe` steps to `release.yml`, and needs the full
      install/upgrade/uninstall hardware cycle re-verified once built. Watch
      for SmartScreen friction on the new unsigned `.exe` — flagged as a
      possible regression versus today's unsigned `.msi`, not yet observed
      either way.
- [x] CI workflow that runs on every push/PR (`.github/workflows/ci.yml`):
      gofmt, vet, `go test -race`, the banned-import check and govulncheck,
      plus a cross-compile job for all three targets
- [x] The banned-import check `CLAUDE.md` calls for, in two halves:
      `internal/buildpolicy` parses this module's own source for `unsafe`,
      `os/exec`, `plugin`, cgo and the `html/template` escape hatches and runs
      under `make test`; `scripts/check-banned-imports.sh` walks the full
      dependency graph of `./cmd/smtprelayd` with `go list -deps` per target
      under `CGO_ENABLED=0`, which is what catches a transitive reintroduction
      such as the `kardianos/service` systemd backend. The script matches
      importer/banned pairs against an allowlist whose only entry is
      `modernc.org/libc os/exec` (see the decision log). Both were confirmed to
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
4. ✅ `spool.syncDir` now propagates fsync errors on Linux. The Windows half
   of this was wrong until 2026-08-11: it filtered `ErrInvalid` but the actual
   error is EACCES, so every rename-completing sync failed. Windows is now a
   build-tag no-op, not an error class the caller tries to recognise.
5. ✅ `limits.max_headers` and `limits.max_header_bytes` now validated as > 0.
6. ✅ `MAIL FROM SIZE` is now validated early in DATA phase if present.
7. ✅ Token client proxy environment removed; no metadata leakage through proxies.
8. The selftest still uses `InsecureSkipVerify` plus certificate pin and trips
   gosec G123. This is the deliberate exception recorded in the decision log;
   it dials fresh with no session cache so resumption cannot occur. Not fixed.

## Known gaps from the 2026-08-11 security review

A full-tree review on 2026-08-11 produced six findings, **all six now fixed**
(1 and 2 on 2026-08-11 after a policy decision, 3-6 the same day). The review
itself changed no code, and the findings were not recorded here at the time — this section was added on the same
date, one finding later. The baseline was clean: gofmt, `go vet`, `go test
./...`, both cross-builds, `govulncheck` and `scripts/check-banned-imports.sh`
all passed. Re-verify each against the tree before acting; the descriptions
below date from that review.

1. ✅ **High — the dashboard had no authentication and could be bound
   publicly.** Closed by refusing a non-loopback `[web].address` at startup,
   the option chosen over adding a login now: loopback is what
   `internal/web/csrf.go` already assumed, and the refusal costs no new
   authentication code that would itself need reviewing. The error names the
   way out (SSH tunnel or an authenticating reverse proxy) rather than only
   the invariant. A token login for the dashboard — verifying a pasted token
   against the stored digests, which is possible where a stored password is
   not — remains open as its own phase. The original finding text follows.

   **High — the dashboard has no authentication and may be bound publicly.**
   `Validate()` requires only a TLS certificate for a non-loopback
   `[web].address`, not tokens and not loopback. Verified live: `0.0.0.0:8443`
   with zero tokens served `/queue` and `/config` over the LAN address, and
   the requeue/delete forms are reachable — their CSRF token is fetched from
   the page, so it is not authentication. The JSON API on the *same* listener
   correctly returns 401: the same data behind two doors. `internal/web/csrf.go`
   assumes loopback is the trust boundary and nothing enforces that. Not
   insecure by default (`web.enabled` is false, the default address is
   loopback). **Not fixed.**
2. ✅ **Medium — the metrics endpoint** had no loopback enforcement, no TLS
   and no authentication; the decision log said the listener "is expected to
   bind to loopback", which is an expectation, not an enforcement. Fixed the
   opposite way round from the dashboard, because the situation is the
   opposite: a monitoring system *can* present a credential, so a public bind
   is allowed but authenticated. Beyond loopback the endpoint now requires a
   read-scope bearer token and a TLS certificate — a token in the clear on a
   LAN is a credential handed to whoever is listening — and `Validate()`
   refuses the address unless both exist. On loopback nothing changed. The
   check lives in the handler as well as in validation, since a validation
   with no enforcing handler behind it is the same expectation this finding
   was about. Deliberately no rate limiting on failures here, unlike the API:
   the endpoint exists to be polled continuously, and locking a monitoring
   system out after five bad requests turns a credential mistake into an
   alerting outage. Failures are logged with the source address.
   Verified live against a public bind: 401 without a token, 401 with a wrong
   one, 200 with a valid read token, and plaintext HTTP rejected by the TLS
   listener.
3. ✅ **Medium — `log.file` path traversal.** `main.go` joined `Log.File` to
   `DataDir` with no validation anywhere, which is exactly the "path built by
   joining an unvalidated string" `CLAUDE.md` bans. Reproduced against the
   pre-fix binary on 2026-08-11: `file = "../../../../../../tmp/escaped.log"`
   passed `check` and the daemon then wrote its log to `/tmp/escaped.log`.
   Fixed by `config.LogPath` (`internal/config/logpath.go`), the single place
   the two values are joined, called both by `Validate()` and by the code that
   opens the file. Same input now fails `check` and `run` with
   `log.file "..." must not contain a ".." path element`, and no file appears
   outside the data directory.
4. ✅ **Medium/Low — `history.db` and the log file were created 0644**
   (field-confirmed on 2026-08-11: on the live Fedora host the log file dates
   from 01:05 that morning, written by a version that still created it 0644,
   and reads `0600 smtprelayd:smtprelayd` after the upgrade — so the
   restrict-an-existing-file path is not just a unit test) while
   every spool file is correctly 0600. Both are created by code that does not
   let the caller choose a mode (the SQLite driver, lumberjack), so the fix is
   a post-creation restrict: `fsmode.RestrictFile`, a no-op on Windows for the
   same reason `spool.ensureMode` is. For the log it runs *before* lumberjack
   opens the file, because lumberjack copies the current file's mode onto
   every rotation — creating it 0600 is therefore what makes each generation
   0600. A file left at 0644 by an earlier version is restricted on the next
   start, verified by chmod'ing both back to 0644 and restarting. The
   underlying weakness that made this reachable is untouched and still true:
   `config.CheckDir` rejects only group/other *write*, not *read*, so a 0755
   data directory still passes startup validation.
5. ✅ **Low — `checkSecretFile` did not check the containing directory**,
   unlike `CheckConfigFile`, which was fixed for exactly this
   unlink-and-replace attack on 2026-08-10. It now does, on both platforms.
   Unchanged and deliberate: both stop at the immediate parent, not the full
   ancestor chain — an attacker controlling a higher ancestor can rename the
   whole subtree, which is not defended against here.
6. ✅ **Low — a bare CR survived inside header values.** `readLineLimited`
   strips only the line's own terminator, so a CR inside the line was carried
   into the spooled header block, where the next parser decides for itself
   whether it ends a line. Now rejected — but through a new
   `readStructuredLine` used by the command loop and the header scanner only,
   *not* by `dotReader`. The first attempt put the check in the shared reader,
   which would silently have started rejecting message bodies containing a
   lone CR: legacy devices are exactly this relay's users, and a body CR
   cannot split a header. Verified live on all three paths: header CR → 500,
   command CR → 500, body CR → queued with the byte intact. The overstating
   comment on `receivedHeader` now says CR/LF/NUL rather than "control
   character", which is what is actually verified.

**Found while fixing 4, not part of the review; resolved 2026-08-12**:
`Store.Open`'s DSN carried `_journal_mode=WAL`, but modernc's driver only
reads `_pragma=`, so the history database had always run in the default
rollback-journal mode. It was the same "looks configured but does nothing"
class the strict TOML decoding exists to prevent, one layer below where that
decoding can see. WAL is now actually on, via `_pragma=journal_mode(WAL)`, and
a test reads `PRAGMA journal_mode` back from the database rather than trusting
the DSN — the point being that the old spelling compiled, connected and did
nothing, so only the database itself can say which of the two is in effect.
Confirmed the test fails against the old spelling before trusting it.

Confirmed solid in that review and not worth re-auditing: `ca_pin` on
`VerifyConnection`/`VerifiedChains`, the `authms365` token endpoint, fully
parameterised SQL (the one `ORDER BY` interpolation is an allowlist lookup),
validated queue-ID path joins, fail-closed client matching, and the dotReader
un-stuffing correctly paired with `net/smtp`'s re-stuffing `DotWriter`.

## Known gaps from the 2026-08-11 security review, second pass

A second full-tree review on 2026-08-11 produced eleven findings. **All eleven
were fixed on 2026-08-12** and the work is recorded in `docs/dev/Findings.md`,
which keeps each original finding verbatim with the fix, the reasoning and the
verification above it. Nothing from that review is open.

Two of the eleven changed something an operator can see, so they are named
here rather than only in that file:

- `queue.failed_retention_hours` is a new configuration key, default 168
  (7 days). `spool/failed` now counts towards `limits.spool_max_gb` and is
  swept by age; only the spool copy goes, the history row survives under
  `history.retention_days`.
- The dashboard and a loopback metrics listener refuse a request whose `Host`
  header is not loopback, with `421 Misdirected Request`. A reverse proxy
  placed in front — the deployment the config error already points at — must
  set `Host` to the configured address.

## Open defects

### An upgraded package leaves the old binary running (2026-08-11)

**Fixed 2026-08-11**, same day. `postinstall.sh` now distinguishes an install
from an upgrade — reading both conventions, rpm's instance count in `$1` and
dpkg's `configure` with the old version in `$2` — prints the first-install
instructions only on a first install, and on an upgrade runs
`systemctl try-restart`, which restarts the unit only if it was running and so
keeps the standing rule that a package never *starts* the service.

One deliberate reversal while building it: validating the configuration with
`check` before restarting looks like the safer order and is not. A
`${ENV_VAR}` secret resolves from the service's own environment, supplied by a
unit drop-in that a package script does not see, so `check` would fail with
"environment variable is unset" on a perfectly good configuration and refuse
to restart on essentially every real installation. The restart is therefore
attempted and its *outcome* reported: if the unit does not come back within
five seconds, the script says so, names the journal, and warns that `check`
needs the service's environment. A relay that is down and says so is better
than one silently running the binary the operator just replaced.

Verified by building both packages with nfpm and running every branch of the
script against stubbed `systemctl`/`chown`: first install (both conventions),
upgrade with the unit running, upgrade with the unit stopped, upgrade with no
configuration file yet, and an upgrade where the unit fails to come back.
Then verified for real: an `rpm -U` 0.2.5 → 0.2.6 over a running service
printed `smtprelayd upgraded and restarted.`, and the journal shows the
`Stopping … Stopped … Starting … Started` pair at the RPM's own install
timestamp, with the process back up a second later.

The original report follows.

**Found during the first live Linux install**, an `rpm -U` from
0.2.5 over 0.2.0 on Fedora. `preremove.sh` correctly distinguishes an upgrade
from a removal and only stops the service on a real removal — which is right —
but nothing then restarts it, so the service keeps executing the replaced
binary until an operator restarts it by hand. On the host where this was
found the operator did restart (package written 21:48, process started 21:54),
so the upgrade *looked* fine; nothing in the package made it so.

Second, smaller half: `postinstall.sh` prints its first-install text
unconditionally, so an upgrade of a configured, running relay ends with
"The service was not started automatically because it has no usable
configuration yet", which is false and points the operator at steps they
completed long ago. RPM passes `1` on install and `2` on upgrade; dpkg passes
`configure` with the old version in `$2`. The script reads neither, although
`preremove.sh` already reads exactly that argument.

Restarting a mail relay unattended drops in-flight SMTP sessions; the spool is
durable and recovers `active/` on startup, so nothing accepted is lost, but a
device mid-DATA sees a dropped connection and retries. That was accepted as
the lesser cost when the fix above was authorised.

### The Windows installer does not set the data directory DACL (2026-08-11)

**Fixed 2026-08-11.** Found during the first field deployment on Windows. A
fresh install refused to start with:

```
smtprelayd: data directory ACL: C:\ProgramData\SMTPRelayd: DACL is not
protected against inheritance
```

`CheckDataDirACL` was correct to refuse. The directory as the installer left
it inherited from `C:\ProgramData`, which carries
`BUILTIN\Users:(OI)(CI)(RX)` — every interactive user on the host could read
the spool, and the spool holds message bodies.

Cause: the `util:PermissionEx` elements in `smtprelayd.wxs` add ACEs but do
not set `PROTECTED_DACL_SECURITY_INFORMATION`, so the two explicit grants were
appended on top of the inherited ones instead of replacing them. That answers
the untriaged question — the MSI never produced a passing directory, and no
Windows install has passed the check since it landed.

Fix: `config.SecureDataDir` (`internal/config/secure_windows.go`) writes the
DACL with `SetNamedSecurityInfo` and `PROTECTED_DACL_SECURITY_INFORMATION`,
exposed as `smtprelayd secure-datadir` and invoked by the MSI as a deferred
custom action sequenced after the service registration, since the ACE for the
virtual account cannot be resolved before the service exists. It runs on
repair and upgrade too. The well-known SIDs are constructed rather than looked
up by name: `icacls ... /grant "Administrators:..."` fails on a localised
Windows (`No mapping between account names and security IDs was done`), and
`LookupAccountName` fails there for the same reason.

The owner is reset to `BUILTIN\Administrators` along with the DACL. Without
that, `icacls /inheritance:r` fails with *Access is denied*, so the first
workaround anyone reaches for is `takeown` — which succeeds and takes the ACE
for the service account with it, leaving the service unable to create its own
log file. That looks like a second, unrelated fault; recovering from it took
several rounds in the field and is what made the deployment expensive.

The equivalent by hand, if it is ever needed without the binary:

```powershell
icacls "C:\ProgramData\SMTPRelayd" /inheritance:r
icacls "C:\ProgramData\SMTPRelayd" /grant "*S-1-5-18:(OI)(CI)F" /T /C
icacls "C:\ProgramData\SMTPRelayd" /grant "*S-1-5-32-544:(OI)(CI)F" /T /C
icacls "C:\ProgramData\SMTPRelayd" /grant "NT SERVICE\smtprelayd:(OI)(CI)F" /T /C
```

`(OI)(CI)` matters and is easy to omit: without the inheritance flags the
grant covers the directory itself but not files created in it later, so the
service still cannot write its log despite appearing to own the directory.

**Verified on hardware 2026-08-12.** An MSI built after this fix installs and
the service reaches RUNNING, which is the proof that matters: `CheckDataDirACL`
aborts startup on a DACL still inheriting from `%ProgramData%`, so a service
that starts is a directory that passed. Before the fix, no fresh install ever
did. Also confirmed on that machine: the service runs as
`NT SERVICE\smtprelayd`, not Local System.

What the start does *not* prove is that nothing else was granted alongside the
two expected ACEs — the check verifies the DACL is protected and carries the
service account, not that it is minimal. Reading the `icacls` output once is
still worth doing next time someone is at that machine.

The `secure-datadir` custom action is sequenced to run on repair and upgrade
as well, and neither has been exercised. That is the open half of this defect,
tracked in the phase 5 checklist rather than here.

## Open questions

- Tenant, mailbox and sending domain for the Microsoft 365 route.
- ~~Should a failed token acquisition at startup abort, or only be logged?~~
  **Answered 2026-08-21**: abort, and log. `delivery.Manager.VerifyTokens`
  eagerly fetches a token for every xoauth2 route right after `delivery.New`,
  before any worker starts; `serve()` logs and returns on failure, the same
  shape every other startup dependency already uses. Accepted tradeoff: an
  outage or rejected secret outlasting the restart-on-failure burst window
  (Linux: `StartLimitBurst=5` in 60s) leaves the service down until an
  operator intervenes, which is what "prevent the start" was asked to do.
- ~~Should the dashboard require authentication, or is localhost binding
  enough?~~ **Answered 2026-08-11**: loopback binding is the authentication and
  is now enforced — a non-loopback `[web].address` fails startup. A token login
  for the dashboard is wanted eventually but is its own phase, not a blocker.
- ~~Which addresses go into `[bounce].notify`?~~ **Answered 2026-08-21**:
  `smtprelay@mydomain.local`, set as the global recipient in
  `configs/smtprelayd.example.toml`. `bounce.sender`, `notify_route`,
  `digest_minutes` and `max_per_hour` were already filled with working
  defaults (`postmaster@example.at`, `m365`, 15, 12); nothing else is
  required for notifications to be enabled once this is carried into the
  live configuration and `notify_route` is confirmed to name an actual
  configured route there.
- ~~Should downstream bounces be ingested from the relay mailbox via Graph?~~
  **Decided 2026-08-21**: keep as a possible future feature, not a current
  priority — "als mögliches feature planen, aber nicht Hauptfokus." Effort was
  scoped in conversation and judged comparable to a full phase (Phase 2 or
  4e), not a session task: a new `Mail.Read` Graph consent beyond the
  existing `SMTP.SendAsApp`, DSN detection and Message-ID correlation back to
  a queue ID, a new attack surface (the relay would parse inbound mail
  content for the first time, likely warranting its own security review),
  a config schema change needing sign-off, and new store/dashboard support
  for a distinct failure class. Revisit only if a concrete operational need
  shows up (e.g. recurring reports of mail operators cannot see failed in
  the dashboard).
- ~~Should the API listener be exposed beyond localhost?~~ **Answered
  2026-08-11 by implication**: the API shares the dashboard's listener, which
  is now loopback-only, so the API is too until that login exists. The API
  itself is token-authenticated and would be safe to expose; the dashboard on
  the same listener is what is not.
- ~~Should the history database be switched to WAL journal mode?~~
  **Answered 2026-08-12**: yes, and it is on. Readers no longer block the
  writer, which matters because the dashboard and the API query this database
  while the listener and the delivery manager record into it. The cost is that
  the `-wal` sidecar carries committed rows the `.db` alone does not, so a
  backup copying only the main file loses the most recent ones — acceptable
  for a metadata journal, and it would not be for the spool.
- ~~A Postfix `main.cf` importer (`smtprelayd import-postfix`)~~ **Declined
  2026-08-21**: "das postfix thema lassen wir sein." Not pursued; revisit
  only if raised again. Originally scoped as a one-shot converter with an
  explicit report of what could not be translated, never a runtime parser.
  Was never planned into a
  phase.

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
| 2026-08-08 | Windows service runs as the virtual account `NT SERVICE\smtprelayd`, never LocalSystem | No password to provision or rotate, and no manual local-account creation in the installer, while still meeting the "dedicated service account" requirement in `docs/dev/EXPLOIT-SURFACE.md` |
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
| 2026-08-10 | `Store.Open` sets `_pragma=foreign_keys(1)` on the SQLite DSN | SQLite does not enforce `ON DELETE CASCADE` unless a connection turns foreign keys on; without it the schema's declared cascade was a no-op and retention cleanup left `attempts`/`audit` rows orphaned forever instead of deleting them with their message |
| 2026-08-10 | Subject extraction reuses `rewrite`'s own header-block parser (`rewrite.HeaderValue`) rather than a second parser in `internal/listener` | The block parser is already the hardened, tested implementation for exactly this format; a second one would be a second place to get folding or quoting wrong for no benefit |
| 2026-08-10 | A subject that fails to parse or contains control characters is sanitised (stripped, truncated), not rejected | Unlike the From header, the stored subject is display metadata that never goes back onto the wire, so failing the whole message over a stray control character in an unrelated header would be a worse outcome than a slightly mangled history record |
| 2026-08-10 | Queue depth, token age and last-delivery-time gauges are read live at scrape time (from `spool.QueueDepth` and `authms365.TokenSource.TokenAge`) rather than maintained as incrementally-updated state | A gauge derived from the spool's own source of truth cannot drift from it; an incrementally maintained counter could, and nothing here is hot enough to make that reads-vs-writes tradeoff pay for itself |
| 2026-08-10 | A credential-related retryable failure gets its own `smarthost.AuthError` type instead of reusing `TempError` | The retry behaviour must stay identical to any other temporary failure, but `smtprelayd_auth_failures_total` cannot tell a rejected secret from a dead smarthost without a distinct type to match on |
| 2026-08-10 | Metrics counters are seeded at zero for every configured route at startup | A counter that only appears in the exposition after its first event is indistinguishable, to a scraper, from a route that does not exist yet |
| 2026-08-10 | The metrics endpoint has no authentication and no TLS | Matches the existing decision for Checkmk polling recorded in `MEMORY.md` section 7; the listener is expected to bind to loopback like the dashboard, the same boundary `docs/guides/SECURITY.md` already relies on |
| 2026-08-10 | The read-only config view writes `"[redacted]"` as a literal string for every secret field, never relying on `Secret.String()`'s own redaction | Two independent reasons a secret cannot leak survive a mistake in either one; the view also never calls `.Value()` at all, so there is no code path that even holds the plaintext in scope |
| 2026-08-10 | `metrics.Registry.Status()` is the single source both `/metrics` and the dashboard's route status page read from | The two must never disagree about whether a route has delivered, is deferred, or has a cached token; a second, independently-computed snapshot is how that drifts |
| 2026-08-10 | `web.Serve` serves HTTPS with `cfg.TLS`'s certificate when `[web].address` is non-loopback, mirroring the existing listener's own certificate loading | `internal/config` already refuses to start a non-loopback `[web]` address without a certificate configured; a validation that guards a setting the server then ignores is worse than not validating it at all |
| 2026-08-10 | `MessageFilter.Sort`'s `status` column sorts on a `CASE` expression over the derived attempt class, not a stored column | Status is derived, not stored, so "sortable by status" only has a real column to point at if one is synthesised; the mapping (queued, then deferred, then delivered, then bounced) is fixed by the allowlist, never influenced by request input |
| 2026-08-10 | The "latest attempt" join in `FindMessages`, `CountQueue` and `FindBounceSummaries` tiebreaks on the attempts table's autoincrement `id`, not `MAX(at_time)` | `at_time` has only second precision; two attempts landing in the same wall-clock second both matched `MAX(at_time)` and fanned the join out into duplicate rows for one message. `id` is unique by construction, so it cannot tie |
| 2026-08-10 | The dashboard's requeue and delete actions are separate handlers in `internal/web`, protected by a per-process HMAC CSRF token, not a second consumer of the bearer-token-protected `/api/v1/*` endpoints | The running process holds only a token's SHA-256 digest, never its plaintext, so the dashboard cannot construct an `Authorization: Bearer` header for itself even in principle. Both entry points still call the same `spool.Requeue`/`spool.Discard`/`store.RecordAudit` |
| 2026-08-10 | `spool.Requeue` and `spool.Discard` return `ErrBusy` for a leased message rather than acting on it | The delivery worker holding the lease will call `Release`, `Remove` or `Fail` on it when the attempt finishes; racing that could resurrect a message `Discard` just deleted, or overwrite a `Requeue`'s reset attempt counter |
| 2026-08-10 | `smtprelayd_api_auth_failures_total` has no source-address label | Route names are a small, fixed, config-time set; a source address chosen by whoever is failing to authenticate is not, and labelling it would let an attacker grow the exposition without bound. The source address is still logged, per docs/guides/API.md, on the line itself rather than as a metric label |
| 2026-08-10 | The API's per-source rate limiter tracks failures in memory with opportunistic eviction, not a fixed-size cache or an external store | The load profile (an internal API surface, loopback by default) does not justify a dependency; eviction on write bounds memory against the one attack this exists to slow down (many failed attempts from a small number of sources) without bounding it against an unrelated one (many distinct sources), which is a cost accepted rather than solved here |
| 2026-08-11 | A client may override only `bounce.notify`; setting `bounce.sender`, `.notify_route`, `.digest_minutes` or `.max_per_hour` on a client is a startup error | The notifier never reads those fields per client — the digest window, volume cap and notify route are shared — so accepting them there would silently do nothing, exactly the "looks configured but does nothing" trap strict decoding otherwise closes |
| 2026-08-11 | `bounce.sender` is required whenever notifications are enabled, which no prior validation checked | A digest with no From header is a red flag to most receiving mail systems; better to fail at startup than to find out from a spam-filtered notification nobody saw |
| 2026-08-11 | The bounce digest is composed from `store.FindMessageByID` at dispatch time, not from fields threaded through `RecordFail` | `RecordFail` only ever needs to remember a client name and a queue ID; composing from the store's own authoritative record at send time means the digest can never drift from history, and automatically inherits the same `retain_subjects` redaction the dashboard and API already apply |
| 2026-08-11 | The volume cap carries a suppressed client's failures into the next hour's digest instead of dropping them | "Records them for the next hour" in the plan means the underlying event survives being capped; only the act of sending is suppressed, not the fact that a failure happened |
| 2026-08-11 | A notification message's own delivery outcome updates a dedicated `smtprelayd_notification_failures_total` counter, never the triggering route's own delivered/bounced/deferred/auth-failure counters | Those describe the relay's client-facing traffic; folding postmaster mail into them would make a notify-route outage indistinguishable from a real production delivery problem on that route |
| 2026-08-11 | Loop prevention is a persisted `spool.Envelope.Notification` bool, not an in-memory set of queue IDs the notifier created | An in-memory set is lost on restart while the notification message can still be sitting in the queue; a persisted flag survives exactly the case (crash or restart mid-retry) where losing the distinction would let a notification's own failure start a real loop |
| 2026-08-11 | The data directory DACL is the installer's responsibility, not the daemon's | `CheckDataDirACL` refuses to start on an inherited DACL, which is right — `C:\ProgramData` grants `Users:(RX)` and the spool holds message bodies. Having the daemon repair the ACL itself would mean a service that widens or narrows its own permissions at startup, and would defeat the check. The MSI must produce a directory that already passes |
| 2026-08-11 | The MSI writes the DACL by calling `smtprelayd secure-datadir`, not with WiX `util:PermissionEx` | `util:PermissionEx` does not protect the DACL against inheritance, which is the whole point of the check; and the ACL that `CheckDataDirACL` verifies and the ACL the installer writes are one contract, so they belong in one place, exactly as the SCM registration already does |
| 2026-08-11 | `secure-datadir` is a subcommand, not something `install` does | It has to run on repair and upgrade, not only on first registration, and it is the only remediation an operator has when an ACL was lost — `CheckDataDirACL`'s error message now names it |
| 2026-08-11 | The uninstaller leaves the data directory in place | The spool can still hold accepted, acknowledged, undelivered mail at uninstall time, plus the history database. Deleting it silently would lose mail the relay took responsibility for |
| 2026-08-11 | Directory fsync is a build-tag no-op on Windows rather than an error the caller filters | `FlushFileBuffers` requires a handle opened with `GENERIC_WRITE`, which a directory handle cannot have, so the call can only ever fail there. Recognising its error class was the wrong shape of fix — it had already been attempted, against `ErrInvalid` when the real error is EACCES, and every enqueue on Windows failed for it. The durability it buys on Unix is provided by NTFS's own rename journalling |
| 2026-08-11 | `os.Chmod` on the spool directories is skipped on Windows | Mode bits are not the access-control mechanism there — `os.Chmod` only toggles the read-only attribute — so the call enforced nothing while being able to fail on a directory whose DACL denies WRITE_ATTRIBUTES. The explicit DACL the installer sets and `CheckDataDirACL` verifies is what actually restricts the data directory |
| 2026-08-11 | `scripts/check-banned-imports.sh` matches importer/banned pairs against a named allowlist instead of asserting the banned package is absent from the graph | `modernc.org/sqlite`, which the no-cgo rule forces, pulls `os/exec` in through `modernc.org/libc` on every GOOS, so the absence assertion could no longer hold. Allowing the package outright would have retired the rule; naming the single importer keeps `kardianos/service` — the regression the script exists for — a failure, and reports who imports what when it fires |
| 2026-08-11 | The history store journals message metadata, never the message body | An archive of message content is a different feature with a different legal footprint (retention, access control, subject access requests); the journal answers "what came in, from where, how big, and what did the smarthost say about it" without ever holding the content itself |
| 2026-08-11 | Journal values are read from the rewritten header block and the staged size, not from what the client announced | `MAIL FROM SIZE` is a claim and the pre-rewrite headers are not what was queued; a journal that records the announcement rather than the artefact is misleading in exactly the case someone is troubleshooting |
| 2026-08-11 | Journal columns are added by `Store.migrate` and are nullable with no default | `CREATE TABLE IF NOT EXISTS` silently leaves an existing table alone, so an upgraded installation would otherwise keep the old column set forever. NULL for a pre-migration row says "unknown", which is true; a `DEFAULT 0` would say "a zero-byte message", which is not |
| 2026-08-11 | `RecordMessage` takes a `MessageRecord` struct instead of a parameter list | With the journal fields it would be eleven consecutive string parameters; two transposed at a call site would still compile and would store a sender as a recipient list |
| 2026-08-11 | The latest attempt's code, response and count are carried on the message row in list queries | The dashboard's queue, search and bounce views must show why a message is deferred without a per-row follow-up query. This is also how the long-standing empty "Last response" column on the bounce view was found: `FindBounces` never selected an attempt row at all |
| 2026-08-11 | `log.file` is resolved by `config.LogPath`, the only place it is joined to `service.data_dir` | A path built from a configuration string is what `CLAUDE.md` bans building without validation. Keeping the check in the same function as the join means a later refactor cannot separate them; a `..` element, an absolute path, a Windows volume name or a NUL now fails startup instead of relocating the log |
| 2026-08-11 | The `log.file` containment check is lexical and says so | It proves the configured value cannot name a location outside the data directory. It does not prove the path is safe to open — a symlink planted inside the data directory still points wherever it points, which is `CheckDir`/`CheckDataDirACL`'s job. A check that promised more than it delivers would be worse than none |
| 2026-08-11 | Files created by dependencies are restricted after creation (`internal/fsmode`), not left at their default 0644 | The SQLite driver and lumberjack both create 0644 and neither lets the caller choose. For the log this must happen before lumberjack opens it, because lumberjack copies the current file's mode onto every rotation — so creating it 0600 is what makes each generation 0600 |
| 2026-08-11 | The bare-CR rejection is in `readStructuredLine`, used for commands and headers but not for the body | A CR inside a line that gets interpreted or re-emitted into a header block is a header-splitting risk; the same byte in a message body is content that cannot split anything. The first attempt put the check in the shared reader and would have started rejecting bodies from exactly the legacy devices this relay exists for |
| 2026-08-11 | A non-loopback `[web].address` is refused outright rather than served with TLS and no credential | The dashboard has no credential it could present: the process holds only SHA-256 digests, so it cannot construct a bearer header for itself, and its CSRF token is fetched from the page and therefore is not authentication. Loopback is the authentication, which `internal/web/csrf.go` already assumed and nothing enforced. A login that verifies a pasted token against the digests is possible and deferred to its own phase |
| 2026-08-11 | A non-loopback `[metrics].address` is allowed but requires a read-scope token and TLS, superseding "no authentication and no TLS" | The 2026-08-10 decision rested on the listener being expected to bind to loopback, which nothing enforced. Unlike the dashboard, a monitoring system can send a header, so the answer is a credential rather than a refusal; the certificate is required with it because a bearer token crossing a LAN in the clear is a credential given away. Loopback behaviour is unchanged |
| 2026-08-11 | The metrics endpoint does not rate limit failed authentication, unlike the API | It exists to be polled continuously by one or two known systems. Backing off after five failures would convert a mistyped token into an alerting outage, which is a worse failure than the guessing this would slow down against an endpoint that exposes counters rather than message content |
| 2026-08-11 | The constant-time token comparison lives once, in `config.MatchToken` | The API and the metrics endpoint authenticate against the same digests. Two implementations of one constant-time comparison is how one of them eventually stops being constant-time |
| 2026-08-11 | The postinstall script restarts the service on an upgrade with `systemctl try-restart`, having never started it on a first install | `preremove.sh` correctly declines to stop the service on an upgrade, but nothing restarted it afterwards, so an operator who upgraded for a fix kept running the binary they had just replaced. `try-restart` acts only on a unit that is already running, so a service deliberately left stopped stays stopped and the "a package never starts this service" rule survives intact |
| 2026-08-11 | The upgrade path restarts first and reports the outcome, rather than validating the configuration with `check` beforehand | A `${ENV_VAR}` secret resolves from the service's environment, supplied by a unit drop-in that a package script cannot see, so a pre-flight `check` would report "environment variable is unset" for a perfectly good configuration and refuse to restart on essentially every real installation. Attempting the restart and reporting a unit that does not come back is honest in both directions; a relay that is down and says so beats one silently running the old code |
| 2026-08-11 | `postinstall.sh` reads both the rpm and the dpkg upgrade convention | rpm passes an instance count in `$1`, dpkg passes `configure` with the old version in `$2`. nfpm installs the same script as both, and `preremove.sh` already had to make this distinction — printing first-install instructions to someone who has run the relay for a year is the visible half of getting it wrong; not restarting is the half that matters |
| 2026-08-12 | Only `<CRLF>.<CRLF>` ends the data phase; a bare-LF dot still delivers the message but then closes the session | Handing the stream back to the command loop after a non-conforming end-of-data turns "controls the message body" into "controls the envelope". Strict RFC enforcement would have hung every message from a bare-LF legacy device — this relay's actual users — until the data timeout, so the Postfix shape was taken instead: the message is queued and acknowledged, the injection never executes. Checking the dot line's own terminator is not enough, since `<LF>.<CRLF>` smuggles equally well, so the preceding line's terminator is tracked with it |
| 2026-08-12 | The dashboard and a loopback metrics listener refuse a non-loopback `Host` header with 421 | A loopback bind keeps out everything except a browser, which resolves names on someone else's behalf; DNS rebinding therefore reaches the dashboard same-origin from a page the operator visits, which is the 2026-08-11 loopback-is-the-authentication decision undone. Not applied to a public metrics listener, which is reached by its real name and authenticates with a token, nor to `/api/v1/*`, which wants a bearer token a rebound page cannot obtain. 421 with the remedy named rather than 404, because the authenticating reverse proxy the config error points operators at forwards the original `Host` by default |
| 2026-08-12 | `spool/failed` counts towards `limits.spool_max_gb` **and** is swept by the new `queue.failed_retention_hours` (default 168) | Either half alone is wrong in a different direction: counting without a sweep turns a full `spool/failed` into a relay that permanently refuses new mail, and a sweep without counting leaves the quota lying between sweeps. Before this, `Fail()` dropped a message from the only index `spoolSize()` summed, so a client producing nothing but permanent failures freed its own quota on every message while continuing to fill the disk |
| 2026-08-12 | The failed-message sweep deletes the spool copy only, never the history row | What failed and what the smarthost said about it is the record an operator troubleshoots from, and it belongs to `history.retention_days`. Deleting the body bounds the disk; deleting the record would bound the wrong thing. The cost is that a swept message can no longer be requeued, which is what a retention is for |
| 2026-08-12 | The failure timestamp is the metadata file's mtime, not a new persisted field | `Fail` writes the metadata immediately before renaming it into `spool/failed`, so the mtime already *is* the failure time. A new JSON field would have needed a migration and would still have been absent on every message that failed under an earlier version — exactly the population the first sweep has to handle |
| 2026-08-12 | A negative value for any limit that reads zero as "unlimited" is a startup error | `rateLimiter.allow`, `connCounter.acquire` and `Spool.SetQuota` all treat a non-positive limit as no limit, so a mistyped minus sign switched the control off while reading as though it were configured — the same trap strict TOML decoding exists to close, one layer below where decoding can see it. Zero stays legal so "no limit" is still sayable, just not reachable by accident |
| 2026-08-12 | Both workflows raised to Go 1.25 rather than lowering `go.mod` | `golang.org/x/sys` v0.47.0 declares `go 1.25.0` itself, and that is the module `internal/config/trust_windows.go` needs for the Windows DACL check, so lowering `go.mod` would have forced a dependency downgrade in precisely the wrong place. A pin below the `go` directive never lowered the toolchain anyway — `GOTOOLCHAIN=auto` downloaded a newer one — it only stopped describing what produced the release binaries |
| 2026-08-12 | gosec runs with no excluded rule and no skipped directory; the fifteen exceptions are `#nosec` annotations at the line they apply to | An excluded rule keeps passing silently when a later change breaks the property that justified excluding it. An annotation at the line names that property — a validated queue ID, an `O_NOFOLLOW` open, a bound SQL value — and fails the build when the line moves out from under it. The one gosec finding that was not an exception was fixed as a simplification instead |
| 2026-08-12 | Linux logs to the rotated file only; `-console` is documented in the unit rather than enabled | `MEMORY.md` section 10 claimed "journald plus file" and the packaged unit never passed `-console`, so the documentation was the thing that was wrong. Mirroring into journald was rejected as a default because journald rate limits and *drops* the excess — under a mail burst the copy an operator reaches for first would be the incomplete one, and a relay's log is an audit trail. Startup failures reach journald anyway, on stderr before the file logger exists, so a unit that will not come up is still diagnosable with `journalctl` alone |
| 2026-08-12 | The history database runs in WAL journal mode, spelled `_pragma=journal_mode(WAL)` | Readers do not block the writer under WAL, and reading while writing is this database's normal state: the dashboard and API query it while the listener and delivery manager record into it. The cost is a `-wal` sidecar holding committed rows the `.db` alone does not, so a backup copying only the main file loses the most recent — acceptable for a metadata journal and not for the spool, which is where mail the relay took responsibility for actually lives |
| 2026-08-12 | The journal mode is asserted by reading `PRAGMA journal_mode` back from the database, not by inspecting the DSN | The DSN said `_journal_mode=WAL` for months while the database ran in rollback mode, because modernc's driver reads only `_pragma=`. That spelling compiled, connected and did nothing, so only the database itself can distinguish the two. The test was confirmed to fail against the old spelling before being trusted |
| 2026-08-12 | `internal/logging` imports `gopkg.in/natefinch/lumberjack.v2`, not `github.com/natefinch/lumberjack v2.0.0+incompatible` | Same library, field-identical API, one import line. The `gopkg.in` path is the properly versioned module with its own `go.mod`; `+incompatible` also dragged two test-only modules into the graph, since `go mod tidy` covers the tests of imported packages. Net three entries removed from `go.mod` |
| 2026-08-12 | `internal/logging` got its first tests as part of that swap | The package had none, so the rotation dependency could have been replaced with a stub and CI would still have passed. The four now cover what the package is actually responsible for: 0600 on creation, restricting a file an earlier version left 0644, rotation producing a real backup file, and secret redaction surviving the writer setup |
| 2026-08-20 | Added `dpapi:<path>`, Windows only, alongside `${ENV_VAR}` and `file:` | `file:` still leaves a secret in plaintext on disk, and the operator asked directly for it not to be. DPAPI is machine-scoped (`CRYPTPROTECT_LOCAL_MACHINE`), not user-scoped: the virtual service account has no ordinary profile to hold a per-user master key. It defends against the ciphertext being copied off the machine; it cannot and does not defend against an attacker who already has Administrator/SYSTEM on the machine the service runs on, since an unattended service must be able to decrypt at boot with no human to prompt for a passphrase — that limit was stated to the operator before building this, not discovered after |
| 2026-08-20 | `unsafe` is allowlisted per file in `internal/buildpolicy`, not banned with zero exceptions | DPAPI (`crypt32.dll`'s `CryptProtectData`/`CryptUnprotectData`) has no safe wrapper in `golang.org/x/sys/windows`. The ban stays a CI-enforced default; `dpapi_windows.go` joins the previously dormant `trust_windows.go` entry as the only two files permitted to import it, each named with its reason, so a third file reaching for `unsafe` anywhere else in the tree still fails the build |
| 2026-08-21 | A failed OAuth2 token acquisition at startup aborts the service instead of only being logged | Requested directly. Without an eager fetch, a rejected M365 credential or an unreachable tenant was invisible until the first message was already queued behind it. Accepted cost: an outage longer than the restart-on-failure burst window leaves the service down until an operator intervenes, which is the literal ask, not a side effect to soften |
| 2026-08-21 | `winProgram.Start` blocks on a `ready` channel from `serve()` instead of returning `nil` unconditionally | The SCM was told "started successfully" before `config.Load` or any other startup check had even run, so every startup-failure log line this project has added over many sessions never actually stopped Windows from showing the service as running. A `ready` signal at the one point past every synchronous check, rather than a fixed wait, was chosen because `authms365`'s 15s request timeout means a short wait could still report success moments before a genuine, slow tenant rejection |
| 2026-08-21 | `listener.Set.Serve` split into `Bind` (fails fast) and `Run` (blocks until shutdown) | The SMTP listener's own socket bind was the last startup step that could still fail after the `ready` signal above; splitting it out lets that failure also reach the SCM instead of only the log |
| 2026-08-21 | `Server.accept`'s `wg.Add` and `Set.Close`'s `wg.Wait` are serialised through a `closeMu`/`closed` pair, not left to rely on the listener socket being closed first | `sync.WaitGroup` requires every `Add` with a positive delta on a counter that could be zero to happen before the matching `Wait`; closing the socket does not guarantee that ordering against a connection `Accept` had already returned. Found by `-race` in the new `Set`-level test the `Bind`/`Run` split needed, not something this session set out to fix — pre-existing in the previous combined `Serve`, simply never exercised by a test at that level before |
