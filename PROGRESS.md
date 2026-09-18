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
**Last session**: 2026-09-18 (forty-sixth session) — The first review to look
at the dispatcher under load rather than at its correctness, and the numbers
were the finding.

**`Spool.Claim` sorted the whole due queue to return one message.** The
dispatcher calls it once per message until the queue drains, so a tick cost
O(n^2 log n) in queue depth. Measured: one call over 10 000 due messages took
1.50ms, which makes a full tick about 15 seconds of CPU against a 5 second
poll interval -- the dispatcher would never catch up. A one-pass minimum is
the same selection: 157us, and a test now pins the ordering, which nothing did
before.

**The dispatcher fsynced a decision that only mattered for five seconds.**
The non-blocking path (no worker slot free) and the rate-limit path both went
through `Release`, which writes metadata and calls `f.Sync()`. Every message
queued behind a saturated smarthost therefore cost one fsync per poll. New
`Spool.Defer` reschedules in the index alone; a restart makes the message due
again, which is correct, because the reason it was held did not survive either.
`Release` stays for deferrals that record something real, such as a failed
attempt and its backoff.

**Three sibling queries, three pagination contracts.** `FindMessages` and
`FindBounces` returned `Limit+1` rows and left the caller to cut the extra one
off, undocumented; `FindBounceSummaries` cut it itself and returned `hasMore`.
All four callers happened to be right. The contract is now one: `splitPage`,
and the extra row never leaves the store.

**`FindBouncesSince` had no caller anywhere in the tree**, not even a test,
while its comment claimed it fed the bounce digest -- which uses `RecordFail`
instead. It also asked for `Limit: 10000` against a clamp of 1000, so wiring
it up would have silently produced a partial digest. Removed, and the
superseded line in `docs/dev/PHASE4-PLAN.md` says so.

**`gen-cert` never said which group it widened the private key to.** The group
comes from whatever owns the configuration file; on a packaged install that is
the service's own, on a hand-made one it can be a group every local account is
in. The success message read the same either way. `ShareWithGroupOf` now
returns the group and the command prints it.

**A dead size check and the field feeding it** are gone from the listener:
`s.declared` was only ever set after the identical comparison had already
refused the message, so the second one at the DATA stage could not fire. The
live check at MAIL FROM is covered and was mutation-verified before the
duplicate went.

**Two listener tests were racing the server, not testing it.** Both sent lines
after the point where the server replies and stops reading, so under full-suite
load the write hit a closed socket: the suite failed in 2 of 3 consecutive
runs. The hop-limit test now stops at the blank line, which is where
`scanHeaders` returns and the refusal is decided; the smuggling test reads the
carrier's 250 before writing into a closing socket, because a close with unread
client data sends an RST that can discard the reply. 12 consecutive full-suite
runs clean afterwards, and both still fail when their guard is removed.

**Also deduplicated**: `handleSearch` and `handleBounces` shared 36 of about 60
lines. `templates/pager.html` was already shared between them; `listPage` and
`pageLinks` are the Go half of that. The pager arithmetic had no test at all --
`pageLinks` survived its first mutation -- so `TestPagerOffersTheNextPageAndThenBack`
now covers it for both views.

**Previous session**: 2026-09-18 (forty-fifth session) — The Windows-only code was
opened for the first time in twenty reviews. It held the most dangerous
finding of the campaign, and it is not a vulnerability — it is a typo.

**`secure-datadir` re-ACLed whatever `data_dir` resolved to.** `SecureDataDir`
writes a protected DACL with `SUB_CONTAINERS_AND_OBJECTS_INHERIT` and resets
the owner, and its own comment states the consequence: Windows recomputes the
inherited ACEs of everything below. `secureDataDir` passed it the configured
path with no check at all, while `service.data_dir` was validated only for
being non-empty. `data_dir = "C:\ProgramData"` — one missing path element —
would have taken every non-administrator's access to every installed
application's data; a volume root would have taken the machine.

Reachable by ordinary use, not by attack: every ACL error this binary prints
ends by telling the operator to run `secure-datadir` from an elevated prompt,
so the command is reached exactly when something about the configured path
has just gone wrong. `purgeDataDir` forty lines below has guarded its own
resolution since it was written, with the reasoning spelled out — the
neighbour with comparable blast radius had nothing.

New `refuseSystemDir` rejects a volume root and the system directories read
from the environment (`%SystemRoot%`, `%ProgramData%`, `%ProgramFiles%`, …,
never by localised name). Deliberately **not** `purgeDataDir`'s rule: that one
insists on the exact basename, which is right for a recursive delete and
would break a legitimately relocated directory for an ACL write. Both now
share `resolveDataDir` so the resolution cannot drift, and keep separate
safety predicates because the two risks differ.

**`service.data_dir` must now be absolute.** This can reject a configuration
that previously loaded, which is the one behaviour change here. A relative
value resolved against the process working directory — whatever the init
system or the SCM set — so it was already broken, just later and somewhere
different each time. The error names the field and carries a platform-correct
example (single-quoted on Windows, since a backslash in a TOML basic string
is an escape). The shipped example configuration still validates.

**Linux got the other half of the same root cause, in documentation.** The
unit hard-codes `ReadWritePaths=/var/lib/smtprelayd` under
`ProtectSystem=strict`, so a relocated `data_dir` fails with `read-only file
system` — naming the path but not the reason. `CONFIGURATION.md` now gives
the drop-in beside the path table, with the Windows counterpart next to it.

**First Windows tests in the tree.** Five for the ACL trustee check and five
for the new guard; before this session, 632 lines of Windows code had none.
`aclGrantsOnly` takes its expected SIDs as a parameter so a test need not look
up `NT SERVICE\smtprelayd`, which does not exist until the MSI has run — that
is what makes it runnable in CI at all.

**`dataDirTarget` was split out of `secureDataDir` for one reason: the call
site was untestable.** Every test could pass with the guard deleted from
`secureDataDir`, because `secureDataDir` goes on to write a real DACL to a
real directory and so cannot be called to find out whether the refusal is
still wired up. Resolution plus refusal now live in a function that returns a
path, and two tests cover it — including the install-time path, where no
configuration exists yet and `resolveDataDir` falls back to the config file's
own directory, so a config path directly under `%ProgramData%` resolves to
`%ProgramData%` itself. That is the shape of the accident, not a contrived
input.

**Mutation evidence.** The `service.data_dir` absolute check was verified in
both directions on Linux: deleting it, four relative values are accepted;
inverting it, the base configuration stops loading. So neither the guard nor
its counter-test is vacuous.

**Verified on Windows Server 2022, and it found a defect I had introduced.**
The suite ran in the VM against this tree: stage 1 green, stage 3 green, and
all five guards mutation-tested there — `refuseSystemDir`'s three checks,
`dataDirTarget`'s call site and `aclGrantsOnly`'s trustee comparison — each
reported *killed*. So the Windows tests do not merely pass; they fail when the
code they cover is broken.

The first run of that sweep failed 23 tests in `internal/config`. The fixture
had written `data_dir = "/tmp/smtprelayd-test"` since it was created, and that
path is **not absolute on Windows**: without a volume it resolves against
whatever the current drive happens to be, which is precisely the ambiguity the
new check refuses. The check was right and the fixture was wrong. `testDataDir`
now derives from `os.TempDir()` with forward slashes (a backslash in a TOML
basic string is an escape), and the literal exists once, as `dataDirLine`,
which the three tests that rewrite the line share. Same idiom
`internal/web/web_test.go` and `cmd/smtprelayd/gencert_test.go` already used.

**This is the class of defect Linux cannot show.** `go vet` for
`GOOS=windows`, `staticcheck`, and `go test -c` for Windows were all clean --
it is not a compile error but a runtime assertion that resolves differently on
the other platform. Without the VM run it would have shipped green and taken
out half the config suite on the first Windows CI.

**Running the VM, for the next session.** The OEM stage fires only during
Windows setup, so an interrupted install never runs it and the guest sits at
an idle desktop looking exactly like "still installing" -- a screendump
through the QEMU monitor settles that in a minute:
`printf 'screendump /tmp/s.ppm\n' | nc -U /dev/shm/monitor.sock`. There is no
guest agent, so the run is started by typing `\\host.lan\data\g.bat` into the
Run dialog with HMP `sendkey`. Two rules learned the hard way: send the whole
key sequence in **one** monitor session (one connection per key arrives out of
order) and never leave a second typing job running (its trailing `ret` submits
whatever is in the field). Confirm the field with a screendump before Enter,
then `alt-r` for the "Open File - Security Warning" prompt.

`g.bat` and `run.ps1` write to **different** files on the share: `g.bat` holds
its own output file open for the whole PowerShell call, so both logging to one
path costs the entire transcript to `because it is being used by another
process`.

**Previous session**: 2026-09-18 (forty-fourth session) — Two findings, both on
`/api/v1/queue`, found by counting the display surfaces exhaustively instead
of from memory.

**`API.md` documented a "current backoff" field the endpoint never returned.**
Verified against a running instance: the response carries `route`, `queued`,
`deferred`, `delivered_total`, `bounced_total` and nothing else. There is no
per-route backoff to report — the retry schedule belongs to a message, and
`next_attempt_at` on `GET /api/v1/messages/{id}` is where it already is
(checked: the field exists on `store.Attempt`). The section now lists the
real fields and points at that one.

**`/api/v1/queue` reported a narrower route view than `/metrics`.**
`auth_failures` had been missing from the start and `recipients_refused_total`
was added to the exposition without being added here. The second matters
most: a message with a refused recipient is *delivered*, so it appears in no
failure counter, and a caller polling the API instead of `/metrics` — which
`API.md` presents as equally valid — could not see a dead address anywhere.
`routeState` now mirrors `metrics.RouteStatus`, minus the cached-token state
`/api/v1/health` already answers.

**The surface checklist, counted in full** for the partial-delivery outcome,
so the next behaviour change can start from it rather than rediscover it:
`/metrics`, dashboard routes page, dashboard message detail, dashboard search
list (the "Last response" column shows the refusals beside a "delivered"
pill, which is the view an operator reaches first), history and
`GET /messages/{id}`, `/api/v1/queue`, the docs. The bounce digest stays
deliberately out: "could not be delivered" does not describe a delivered
message.

**Two packages opened for the first time, both clean.** `internal/canary`:
`nextDaily` needs an ascending schedule and `DailyAt.Minutes()` sorts and
de-duplicates with that stated as the reason; UTC over `service.timezone` is
argued from daylight saving; `runDaily` re-derives its wait in steps because
a Go timer rides the monotonic clock, which stops on suspend. `internal/
certgen` and `gencert.go`: random 128-bit serial, backdated `NotBefore`,
`IsCA: false`, and `RestrictFile` after `os.WriteFile` because WriteFile
applies its mode only when it creates the file — the `-force` trap, already
seen.

**Assessment**: this is the first round in five where the previous session's
change did not produce the main finding, and the two it did produce are
small and on one surface. Further reviews of this shape look exhausted until
the code changes substantially; the next worthwhile trigger is a real feature
change, not the next turn.

**Previous session**: 2026-09-18 (forty-third session) — Three findings. **Two of
them were in the previous two sessions' own changes**, which is the result
worth carrying forward: a new outcome was introduced without pulling along
every place that displays outcomes.

**Only the first refused recipient was recorded.** `attempt` wrote
`extractSMTPError(partial.Rejected[0].Err)` into the attempt row while
`smtprelayd_recipients_refused_total` counted them all. Measured with four
recipients, three dead: the metric said 3, the detail page named one. An
operator following that alert found less than the alert claimed, which is
worse than having no metric. Now `describeRefusals` renders every refusal,
bounded at 500 bytes and truncated on **whole entries** — half an address
still looks like an address — stating how many were dropped so the count
still agrees with the metric. `Rejection.String()` is now the single
definition of the format, used by both the error text and the recorded copy.

**The dashboard route page did not show the new counter**, while
`metrics.RouteStatus`'s doc comment says it backs both that page and the text
exposition "so the two never disagree about what a route's state is". Column
added, `colspan` corrected, and the test asserts header and cell counts match
so a later column cannot shift everything under the wrong heading.

**The dashboard's paging offset was unbounded above.** `internal/api`
clamped its cursor for this reason; `web.parseOffset` bounded below only, and
`FindMessages` clamped `Limit` but not `Offset`. Measured on 20,000 messages:
7.5ms at offset 0 against 31ms past the end — bounded by table size, not by
the offset value, so roughly 4x per crafted request rather than unbounded.
Reachable despite the loopback bind: `requireLoopbackHost` checks the Host
header, and a page the operator visits can issue
`http://127.0.0.1:8025/queue?offset=...` with a legitimate one. Fixed at the
store, the choke point all three list queries pass through, rather than at
the one caller that lacked it. New `clampPaging` also closes a latent one:
`FindBounces` tested `Limit == 0`, so a negative limit passed through, and
SQLite reads `LIMIT -1` as no limit at all.

**Verified clean**: a partial delivery does not appear in the bounce view —
the join is on `class IN ('permanent','expired')`, not on the SMTP code, so
the 550 now recorded against a `delivered` attempt does not leak in; measured
as 0 rows. `message.html` renders `SMTPResp` for every attempt regardless of
class, so the doc claim that a refusal is visible on the detail page holds.
`api/cursor.go` bounds offset and limit at both ends.

**The in-tree doc-comment test earned its place again.** Inserting two new
declarations above existing functions orphaned `extractSMTPError`'s and
`FindMessages`' doc comments onto them; `TestDocCommentsNameTheirSymbol`
named both, with file and line, before the suite finished.

**Previous session**: 2026-09-18 (forty-second session) — Two findings, the first
of them a regression the previous session introduced.

**Partial delivery was invisible to monitoring.** Making a refused recipient
stop bouncing the whole message also moved that outcome out of
`smtprelayd_bounced_total` and the bounce digest, and into
`smtprelayd_delivered_total` — where it is indistinguishable from a full
success. `docs/guides/API.md` points monitoring at `/metrics`, and `/metrics`
had nothing: no counter in `internal/metrics` knows about recipients at all.
So the fix that stopped losing mail removed the only signal that an address
had gone dead. New `smtprelayd_recipients_refused_total{route}`, seeded at
zero like the other route counters, incremented by `len(partial.Rejected)`.
Verified on a live endpoint, not only in `text()`. Documented in
`CHECKMK.md` and cross-referenced from `CONFIGURATION.md` section 5.

Deliberately counted for notification and canary traffic too: unlike
delivered/bounced it is not a tally of relay volume that diagnostic mail
would distort — it says an address is dead, which is worth hearing about
whichever message found it.

**`bucket.limit` was written twice and never read** (`internal/listener/
match.go`). Removed, with a comment saying why no copy is kept: the limit
comes from the configuration on every call and cannot change while the
process runs. Note for anyone relying on the new staticcheck gate: `U1000`
reports unused *functions*, but treats a field assigned in a composite
literal as used, so it does not cover this class.

**Two process notes worth keeping.** A mutation test caught a test of mine
that asserted nothing: `RecipientsRefused` had an `if n <= 0 { return }`
guard, and deleting it broke no test, because `+= 0` and an early return
leave the counter identical. The guard defended nothing reachable either —
the only caller is inside the branch where the slice is non-empty — so both
the guard and the vacuous test were removed rather than the test being
patched up. Second: `make build-all` produces the platform-suffixed binaries
and does **not** refresh `bin/smtprelayd`, so a live check or
`scripts/selftest-ci.sh` run after it can silently exercise a stale binary.
The first live metrics check did exactly that and reported the metric
missing; `go build -o ./bin/smtprelayd ./cmd/smtprelayd` first.

**Previous session**: 2026-09-18 (forty-first session) — Two findings implemented
from a review, and **one retracted after it turned out to be wrong**.

**One refused recipient no longer bounces the message for everybody.**
`Deliver` returned at the first `c.Rcpt` error, so a 550 for one address
failed the whole message permanently — measured, with a three-recipient
message bounced after its middle recipient was refused while the other two
had already been accepted with 250 in that same session. A printer mailing a
distribution list lost the mail for all three because one person had left.

New `offerRecipients` collects the refusals instead. A **permanent** refusal
is that recipient's problem: the message goes to everyone else and comes back
as `PartialError`, which `attempt` treats as delivered — retrying would
duplicate it for the recipients who did accept — while logging it and writing
the refused address and its verbatim reply into the attempt row, so it is
visible on the message detail page rather than only in the log. A
**temporary** refusal still defers the whole entry before anything is sent,
deliberately: a queue entry is one envelope, so retrying it for one recipient
would deliver it twice to the others. All recipients refused is still a
`PermError`. Documented in `CONFIGURATION.md` section 5.

**`listener.domainOf` was dead**, an exact copy of `router.domainOf` left
behind when routing moved packages, with a doc comment still claiming a
purpose it no longer had. Nothing in the gates reports an uncalled unexported
function — not gofmt, vet, govulncheck or gosec. `staticcheck` now runs in CI
beside them. Measured before adding it: three findings in ~23k lines, so this
is prevention, not cleanup. One of the three was a **false positive worth
keeping**: `validate_test.go` uses `fmt.Sprintf("%s", secret)` on purpose,
because the verb is the behaviour under test; it carries a `//lint:ignore`
naming that reason, the same convention the `#nosec` annotations follow.

**Retracted: "one unroutable recipient refuses the whole message".** The
review reported that a recipient with no route makes `doData` answer 451 for
the entire message. The probe that showed it used a configuration
`config.Validate` **rejects** — `client "local" has no route and no default
route exists`. Every client either names a route or a default route exists,
and `Resolve` falls back to one of them, so `Split` cannot fail for a loaded
configuration and that 451 is unreachable defensive code. Nothing was
changed. Same mistake as the `FindMessages` retraction earlier in the week:
the code path was read, the validator constraining its inputs was not. Do not
re-report it.

**Previous session**: 2026-09-18 (fortieth session) — Five findings from a review
aimed, per the previous session's note, at the lowest-coverage code with no
mutation history. One of them disabled a security control.

**The open-relay self-test passed silently without having tested anything.**
`probe` never negotiated STARTTLS, and treated every `code >= 400` at MAIL
FROM as "rejected already, which is the desired outcome". But `doMail`
answers **530** when `require_tls` is set and the session is not encrypted —
before any relay policy is consulted. Measured with an identical
configuration carrying a client with `cidr = 0.0.0.0/0`, the open relay
`acceptedVerdict` has a dedicated branch for:

| listener | result |
| --- | --- |
| without `require_tls` | correctly reported as an open relay |
| **with** `require_tls` | `err=<nil> notes=[]` — a clean pass |

So hardening a listener turned its open-relay check into a no-op. A rate
limit (451) did the same. `probe` now negotiates STARTTLS on a `starttls`
listener (refusing to hand a pre-handshake buffer to the TLS session, which
is the classic STARTTLS injection bug), and new `refusalVerdict` separates a
relay denial from a refusal that answered a different question — 530 and any
4xx become a **note**, not a silent pass. `main` no longer prints an
unqualified "passed" when notes exist, which `selftest.Run`'s own contract
had always demanded and the caller had never honoured.

**`scripts/selftest-ci.sh` could never have caught that**, because its client
CIDR deliberately excludes loopback, so the probe takes the 550
unmatched-source path — which `doMail` answers *before* the TLS gate. It now
runs two scenarios: the existing gate, plus a `require_tls` listener with
loopback **allowlisted**, where the note is the assertion. Verified against
the real binary both ways: on the fixed code both scenarios pass; on the
unfixed code scenario 1 still passes and scenario 2 fails with the
silent-pass message.

**`SECURITY.md` described a cookie hardening that does not exist.** It
claimed cookies are `HttpOnly`, `SameSite=Strict` and `Secure` over TLS.
There is **no cookie anywhere in the tree** — no `http.Cookie`, no
`SetCookie`, nothing in the templates or the JavaScript; the dashboard has no
session by design, and the CSRF HMAC's per-process key plays that role. The
"over TLS" half was doubly unreachable: `web.Serve` only ever calls
`ListenAndServe`, and `validate` refuses a non-loopback `web.address`
outright. Both are correct; only the document was wrong. It now describes the
CSRF HMAC, the absence of a session, and loopback as the trust boundary.

**`retentionCleanup` claimed a cascade `audit` does not have.** `attempts`
carries `ON DELETE CASCADE`; the `audit` table has no foreign key at all.
Measured: `messages=0 attempts=0 audit=1`. Keeping audit rows is right — an
audit log that prunes itself with the evidence is not one — so the code is
unchanged and the comment and `CONFIGURATION.md` section 9 now say so,
including that the table is therefore unbounded.

**`authms365.Token` dated two values from before its own HTTP request.**
`now` was captured before a `fetch` that can take `requestTimeout` (15s), and
then used for `retryAfter` and `issuedAt` — so a 30s fail cooldown became 15s
after a timeout, in exactly the outage it exists to throttle.

**Mutation-verified clean this session**, so nobody re-derives it: `rewrite`
CRLF/control-character refusal, `rewrite` duplicate-`From` refusal, `router`
default-deny, `metrics` label escaping, API scope enforcement, failed-auth
backoff (2 tests). `bounce.Notifier` resets its hourly window correctly and
carries capped entries forward. `checkSecretFile` exists on **both**
platforms — checked as a suspected Unix blind spot; it is not one.

**Previous session**: 2026-09-18 (thirty-ninth session) — Five findings from an
architecture review that went into the delivery path, plus a real Windows test
run. Unlike the last several reviews, three of these lose or duplicate mail.
Every fix carries a test that was checked against the unfixed code first.

**A failing QUIT duplicated the message.** `Deliver` ended on
`return c.Quit()`. A successful `w.Close()` means the smarthost answered the
body with 250 and owns the message; reporting a later QUIT failure left the
copy queued and the next attempt sent it again. Proved against a server that
hangs up after `250 Ok: queued as ...`: `Deliver` returned `EOF`, which
`attempt` classifies as deferred. Reachable three ways — Exchange not waiting
for QUIT, the delivery deadline expiring in that gap, and the shutdown hook
expiring the connection deadline, which happens on *every* service stop. New
`smarthost.QuitError`; `attempt` logs it and treats the message as delivered.
Note this is the outbound mirror of the rule `commitCopies` already applied
inbound, where partial copies are withdrawn so a client retry cannot duplicate
them.

**One saturated route stalled every other route.** `Claim` returns the
globally oldest due message whatever route it belongs to, and the dispatcher
is a single goroutine that blocked sending to the route's concurrency budget.
Measured with two routes: a healthy route's message went out in **100 ms**
beside a working neighbour and was still queued after **8 s** beside a hanging
one — bounded only by `limits.delivery_timeout_sec`, 600 s shipped. So an M365
outage stopped the internal relay path too. Now a non-blocking send falling
through to `hold`, which is exactly what the rate limiter beside it already
did; `hold`'s comment was generalised for its second caller.

**The removal retry sat on the wrong file.** `removeRetry` exists for the
Windows case where a scanner holds a handle, and its own comment says a
stranded body is inert because `recover()` drops metadata-less bodies. That
makes the *metadata* the dangerous file — and it was the one without the
retry, in all three paths. `Remove` (after delivery) and `Discard` (operator
delete) now unlink the body first and the metadata unconditionally, both
through `removeRetry`; `Fail` uses a new `renameRetry`. Before this, a lost
race meant a delivered message was re-indexed at the next start and **sent
twice**, and a message the operator deleted **went out anyway**.

**The connect timeout was the whole delivery budget.** `net.Dialer{Timeout:
timeout}` with `timeout` = `delivery_timeout_sec`, so a host that drops
packets — the usual result of a changed egress rule — spent all 600 s in the
dial, per attempt, having sent nothing. Now `min(connectTimeout, timeout)`
with `connectTimeout = 30s`; `conn.SetDeadline` still holds the full budget
over the rest of the session.

**`authFor` had no test at all**, and deleting `Deliver`'s refusal to
authenticate over a cleartext connection left the suite green. Not a hole —
`routeTLS` rejects the combination at load time and all three mechanisms
refuse `!s.TLS` from inside — but that guard exists precisely for a Route that
did not come through the loader, and nothing held it. Now a table test over
every mechanism plus a `Deliver` test asserting no AUTH command reaches the
wire.

**`store.Open`'s ping timeout raised from 5 s to 30 s.** It is a wall-clock
deadline on the shipped startup path, on the first use of the database — file
creation, `-wal` replay, first lock. Five seconds was not enough on a loaded
Windows VM, and the consequence in the field is a service that does not start,
reporting "context deadline exceeded" rather than anything about a slow disk.

**Mutation-verified clean, so nobody re-derives it**: CSRF HMAC (2 tests
killed it), `ErrBusy` on a leased message (1), log redaction (2). `xoauth2.go`,
`pinVerifier`, `commitCopies` and `csrfSigner` were read closely and are
correct — note `csrfSigner` feeds the attacker-supplied `exp` into the MAC, so
a forged expiry does not carry.

**Windows**: the four fixes from the previous session are confirmed on a real
Windows Server 2022 VM (`dockurr/windows`) — `cmd/smtprelayd`, `buildpolicy`,
`config` and `web` all pass. That run showed one further failure,
`canary.TestRunReturnsImmediatelyWhenIntervalIsZero`, in its `store.Open`
setup rather than in canary logic; the same test had passed in 2.5 s on the
same image in the previous run, and this run was ~6× slower throughout. It
could **not** be reproduced locally under CPU starvation (64 hogs / 16 CPUs)
or disk contention, so the cause is unproven — the ping-timeout change above
addresses the symptom either way.

**Previous session**: 2026-09-17 (thirty-eighth session) — Four findings from a
sixth architecture review. The review found no defect that loses mail or kills
a service; its subject was comment drift, and most of it was mine from the two
sessions before.

**`metrics` no longer depends on `authms365`.** The last odd edge in the
graph, open since the second review, existed for one gauge. New
`metrics.TokenAger` — a one-method interface declared on the consumer side —
and `delivery` builds `map[string]metrics.TokenAger` instead, since Go does
not convert map value types. `internal/authms365` satisfies it without
knowing it exists and was not touched.

**`ExpiryWatcher.collect` now checks the window before reading anything.** It
read the certificate and logged about it before deciding whether warnings were
switched off at all. `Run` returns early in that case, so the path is
unreachable in the service, but the disabled state should not cost an hourly
file read and a log line if it ever became reachable.

**Nine doc comments corrected.** Two named `WarnBefore`, a symbol renamed out
of existence two sessions ago. Four had been orphaned onto a neighbouring
symbol by an insertion — `maxOffset` carrying `pageCursor`'s comment,
`parseOffset` carrying the comment of `parseTimeRange` (moved to `httpx`),
`Redacted` carrying `journalCols`'s, and `TokenAger` carrying `Registry`'s,
which I introduced an hour earlier in this same session. Two named the old
name after a rename (`Watcher`/`compose`). One block of rationale — the
explanation of why the watcher lives in `bounce` — had been left floating
before a `const`, documenting nothing and invisible to `go doc`. Plus
`queue.js`, whose comment claimed `refresh()` updates the submit buttons; it
does not.

**The check is now enforced in-tree, not by a linter.** `revive`'s `exported`
rule finds this class, but cannot be separated from its other half, which
demands a doc comment on every exported symbol — for the twenty config structs
that mirror TOML sections that means twenty "Service is the [service] section"
lines, precisely the what-not-why commenting CLAUDE.md forbids. So the useful
half went into `internal/buildpolicy` as `TestDocCommentsNameTheirSymbol`,
beside the banned-import checks: pure `go/ast`, no new dependency, runs under
`make test` and in CI. It found all four remaining orphans on its first run,
including two the reviewer had missed by eye.

Test files are exempt by design: a test's doc comment here states the
behaviour under test ("A page the operator visits can rebind a name...")
rather than repeating the function name, which is worth more than the
convention. The rule is for the API surface, and it covers files behind build
tags too, since `parser.ParseFile` ignores them.

Mutation-checked by pointing a comment at the wrong symbol; the test names the
file, the line, the symbol and the first words found.

Verified: `gofmt -l .` clean, `go vet ./...` clean, `make test` green,
`go build` for all three targets, `scripts/check-banned-imports.sh` clean for
each.

**Note for the next review**: this note used to say a further review was not
worth running without larger changes first. That was wrong, and the session
after it is the evidence: three mail-integrity defects, all in the delivery
path. What had converged was the *structural* findings, not the behavioural
ones. The lesson for the next review is where to point it — the areas with
the lowest coverage and no mutation history, not the module layout, which is
now settled. `Config.Validate()` has since been split into a `validator` with
per-section methods, so the finding that stood across five reviews is closed.

**Previous session**: 2026-09-17 (thirty-seventh session) — Four findings from a
fifth architecture review, which went into the protocol readers, the session
lifecycle, the queue-ID type and the API cursors. The readers themselves are
clean; the lifecycle was not.

**The shutdown waited for every connected client, measured at 30 seconds.**
`session.loop` reaches its ctx check only *between* commands, so a session
blocked in a read never sees it, and `stopAccepting` closes the listener
rather than the accepted connections. `Set.Close` then waits on `wg` for all
of them. Measured with a throwaway probe: one idle client with
`read_timeout_sec = 30` held `Set.Run` for **30.026 s** after cancellation,
and the connection got EOF only then. The shipped `read_timeout_sec = 60`
makes that a minute; a client mid-DATA sets `data_timeout_sec` on the same
connection, **300 s shipped**. systemd's 90 s default survives the first and
not the second; the Windows SCM allows five seconds and kills the service
either way, on every stop where a printer happens to be connected — which is
most of them.

Same fix as yesterday's delivery one, `context.AfterFunc` expiring the
deadline, so both halves of the relay now unwind on cancellation instead of
on a timeout. Mutation-checked: removing the two lines makes the new test
time out at 20 s. The client sees a dropped connection rather than the `421`
in `loop`, which is unreachable this way — writing it from the cancellation
goroutine would race the session's own writes.

**The API cursor bounded `Offset` below but not above.** A caller with a
valid token could send `{"o": 9223372036854775807}`; SQLite must then walk the
whole result set before returning nothing, so one crafted cursor costs a full
scan of `messages` per request. Now clamped at 1,000,000 — far beyond what
`history.retention_days` accumulates at this load — failing the same way an
invalid cursor already did, by resetting to the start.

**`recover()` moved to the front of its deferred function.** It was after
`<-s.sem` and `wg.Done()`, which is correct — `recover` works anywhere inside
a deferred function — but read like a bug and invited a "fix".

**The expiry metric now exists**, which closes the last of the three false
documentation claims found this week. `smtprelayd_expiry_seconds{item=...}`
in seconds rather than as a date, so one Checkmk expression
(`< 2592000`) covers both "expiring soon" and, once negative, "already
expired". A separate `smtprelayd_expiry_read_errors` reports a certificate
file that cannot be read, rather than letting an unknown deadline look like a
distant one.

Getting there required splitting `internal/expiry`, which also closes the
`web → bounce` coupling reported in the third review. The package is now a
leaf over `config` answering only "what expires and when"; the watcher —
the half that needs the mail path — moved to `bounce.ExpiryWatcher`, where
the operator notification channel already lives. `web` and `metrics` now
depend on the leaf instead of dragging `selfmail`, `spool` and `store` in
behind a date calculation. Verified against the live endpoint:
`smtprelayd_expiry_seconds{item="tls-certificate"} 71204276` — 824 days, for
an 825-day certificate.

Verified: `gofmt -l .` clean, `go vet ./...` clean, `make test` green,
`go build` for all three targets, `scripts/check-banned-imports.sh` clean for
each, and the example configuration still parses. Fourteen new tests. The
metric is documented in `docs/guides/CHECKMK.md` with its threshold
rationale, plus `SECURITY.md` and `CONFIGURATION.md`.

**Previous session**: 2026-09-17 (thirty-sixth session) — Four findings from a
fourth architecture review, which went into the spool's mutation paths, the
store's write paths, the bulk actions and the packaging: areas the three
earlier reviews had never opened.

**A real accounting bug in `SweepFailed`.** The retention sweep wrote

```go
for _, ext := range []string{".json", ".eml"} {
    if err := removeRetry(...); err != nil && !os.IsNotExist(err) {
        // Leave it indexed so the next sweep tries again ...
        continue
    }
}
```

where `continue` advances the **extension** loop and skips nothing. The
accounting below then ran unconditionally: the entry was dropped from
`failedIndex`, its bytes were reported as freed, and the files stayed on disk
untracked by `limits.spool_max_gb` until a restart re-read the directory. The
comment described the opposite of what happened. `removeRetry` exists
precisely because this failure is expected on Windows, where a scanner or
backup agent holds a handle — its own comment says so. Now tracked in a flag
across both extensions, which makes the existing comment true.
Mutation-checked against the original code: the new test then reports
`removed=1 freed=819` for a message still on the disk. The test reproduces the
lock portably by replacing the body with a non-empty directory, so `os.Remove`
fails with ENOTEMPTY whatever the test runs as.

**`make test` works for the first time.** The Makefile exports
`CGO_ENABLED=0` while `test:` ran `go test -race`, which needs cgo — the
target failed before running a single test, and had for as long as it has
existed. CI never noticed because it calls `go test -race ./...` directly and
never reads this file. Fixed with a target-specific `export CGO_ENABLED = 1`,
commented so nobody "restores" it: the race detector needs cgo at *test build*
time, which says nothing about the shipped binary, and the `CGO_ENABLED=0` at
the top plus the build targets still enforce that. Third review in a row that
this was reported.

**Configured names are validated for the first time.** `metrics.label` carried
the comment *"Route names are already restricted to a safe identifier set by
the config loader; the escaping here is defensive rather than
load-bearing."* The loader checked names for **empty** and **duplicate** and
nothing else — no character set at all — while validating essentially
everything else strictly. The escaping was correct, so nothing was broken, but
it was load-bearing and the comment invited someone to remove it. New
`config.ValidName` applied to listener, client, route, canary and token names:
1..64 printable ASCII, excluding control characters, `"` and `\` — exactly what
breaks a Prometheus label value, a log line or a journal column. Deliberately
permissive (spaces are fine) so it cannot reject a reasonable existing
configuration; every name in the shipped example is covered by a test that
says so. `metrics.label`'s comment now describes what is actually true.

**Bulk actions are bounded by time, not just by count.** "Delete everything"
looped over up to `bulkMax` = 1000 messages on the request goroutine, each
with an fsync and three SQLite writes, against the dashboard's 60s
`WriteTimeout`. Past that the response is cut off mid-flight and the operator
is left not knowing how much of an irreversible action completed. The loop now
stops on a spent `bulkBudget` (30s, half the WriteTimeout) or a cancelled
request context, reusing the existing `Truncated` flag — the operator repeats
the action in either case, which is what the banner already said. Its wording
was generalised, since "the queue held more than 1000 messages" is only one of
the two reasons now. The tally is logged with an `incomplete` field whatever
happens to the response, because that log line is then the only record.

Verified: `gofmt -l .` clean, `go vet ./...` clean, **`make test` green**,
`go build` for all three targets, `scripts/check-banned-imports.sh` clean for
each, and the name rule confirmed against the real binary on a modified copy
of the shipped configuration. Six new tests.

**Previous session**: 2026-09-17 (thirty-fifth session) — Four findings from a
third architecture review, plus the one documented command that never
existed. "1 2 3 4 umsetzen. bitte auch noch das gen token umsetzen."

**A shutdown could not interrupt a delivery in progress.** `net/smtp` takes
no context, so everything after the dial — handshake, SASL, the whole DATA
transfer — ran to `conn`'s deadline regardless of cancellation. The chain
`winProgram.Stop` → `serve` → `bg.Wait` → `dm.Run` → in-flight `attempt`
therefore blocked for up to the delivery budget. Tolerable under systemd's 90s
default; **not** under the Windows SCM's five seconds, where the service is
reported as not responding and killed. `Deliver` now arms
`context.AfterFunc(ctx, …)` to expire the deadline on cancellation, which
aborts whichever read or write is in flight at once. The resulting timeout is
classified temporary, so the message stays queued rather than being failed.
Mutation-checked: removing the two lines makes the new test hang for its full
10s budget. Note that the "clean shutdown verified" entry below was obtained
with an **empty queue**, so it never covered this.

**`write_timeout_sec` meant two different things.** In the listener it is a
per-reply deadline, reset on every reply. In delivery the same value became
the absolute budget for a whole outbound attempt. With the shipped
`max_message_mb = 100` that gave a 100 MB message 60 seconds to reach the
smarthost — about 14 Mbit/s sustained — and anything slower failed
temporarily and retried until `queue.max_lifetime_hours` expired it. Neither
key was documented anywhere. **Schema change**, on the operator's request:
new `limits.delivery_timeout_sec`, default 600, and `Validate` now refuses a
value that cannot carry `max_message_mb` at a pessimistic 1 MB/s plus
handshake, so the pair cannot be set into that state by accident. All four
timeout keys are now commented in the example config and the guide.

**Subject redaction moved into the store.** It was implemented three times —
twice in `web`, once in `api`. It is now one `Store.redactSubject` applied on
every read path. The existing dashboard test caught that the first attempt
missed `FindMessageByID`, which is the per-message detail page: the gap the
test found was real. A store test that asserted the old write-side behaviour
(subject reads back empty) was rewritten to assert both halves that actually
matter — the column is never written, *and* nothing readable comes back —
plus a new test for the case the read-side policy exists for: a row stored
while `retain_subjects` was on must stop being readable once it is turned off.

**`internal/selfmail`, and the last duplicate is gone.** `bounce` and
`canary` each had their own copy of render-headers → spool → journal →
return-ID. Both now call `selfmail.Enqueue`. Building it surfaced a real
distinction I had collapsed: `HeaderFrom` and `EnvelopeFrom` are separate
fields, because a notification carries a readable `From:` while its reverse
path stays empty — the existing loop-prevention tests caught that immediately,
which is what they are for. `selfmail` is a leaf over `rewrite`/`spool`/
`store` with four tests of its own.

**`smtprelayd token new` now exists.** `docs/guides/SECURITY.md` had described
it for months; running it produced "unknown command". It generates 256 bits
from `crypto/rand`, prints the token once as RawURLEncoding (no padding, no
`+` or `/`, so it survives a header and a shell), the SHA-256 digest, a
ready-to-paste `[[web.token]]` block and a working `curl` line. `-scope`
selects read or admin and is validated here rather than leaving
`config.Validate` to refuse the pasted block later. The token is never
written anywhere. Tested for what matters: the printed pair authenticates
through `config.MatchToken`, a modified token does not, two runs differ, and
the token is 32 bytes.

**`token new` is documented in all five places** that previously told an
operator to do it by hand: `README.md`, `docs/guides/SECURITY.md`,
`docs/guides/API.md`, `configs/smtprelayd.example.toml`, and
`docs/guides/CONFIGURATION.md` section 8, whose six-step manual walkthrough
("There is no `token new` helper yet") became four steps around the command,
with rotation and revocation added. The example config had been advertising
`smtprelayd token new --name checkmk --scope read` — a `--name` flag that
never existed, for a command that never existed.

**A trap found while writing that documentation**: Go's flag package stops at
the first non-flag argument, so `smtprelayd token new -scope admin` silently
issued a **read** token and the operator would only find out at the first 403.
`main` now refuses anything trailing the command and prints the corrected
line, which is copy-pasteable. Verified both orders by hand.

Verified: `gofmt -l .` clean, `go vet ./...` clean, `go build` for
`linux/amd64`, `windows/amd64` and `linux/arm64`,
`scripts/check-banned-imports.sh` clean for all three, and
`CGO_ENABLED=1 go test -race ./...` green across all 23 packages. The
dependency graph stays acyclic. Fifteen new tests.

**Previous session**: 2026-09-16 (thirty-fourth session) — Five fixes from a
second architectural review, plus one new feature. No phase work, no schema
change.

## Second new feature: expiry warnings by mail (`internal/expiry`)

Asked immediately after the gen-cert limitation above was reported: "können
wir … ein mail schicken an den hinterlegten kontakt wie bei der testmail" —
warn by mail, the way the canary already reports through the bounce digest.

**No schema change was needed**, which is why this did not need sign-off
under working agreement 4. The "hinterlegter Kontakt" already exists as
`bounce.notify` / `bounce.sender` / `bounce.notify_route`, and the threshold
is hardcoded at thirty days to match the `secretExpiryWarning` constant
`delivery.warnSecretExpiry` has always used.

**Scope decision worth flagging**: the question came out of the *certificate*
expiry gap, but the OAuth2 client secret has the identical gap — it is
announced once at startup by `warnSecretExpiry` and a service running for
months never repeats it. Both are total failures (an expired certificate
refuses every TLS submission, an expired secret fails every delivery on that
route). Both are therefore covered. Say so if the secret half was unwanted.

**The send path was extended, not copied.** `internal/canary` and
`internal/bounce` already each carry their own "compose a message, enqueue via
spool, record in store" block, and the last architecture review called that
duplication out — so a third copy was not written. `bounce.Notifier` gained an
exported `Notify(source, subject, body, now)` plus a private `enqueue` that
the digest path now shares. The three loop-prevention properties (null reverse
path, `Notification: true`, never passing through the listener) live in
`enqueue`, so every caller inherits them rather than re-deriving them. That
mildly widens `bounce` from "delivery-failure digests" to "the operator
notification channel", which is the coherent reading of what it already was.

Deliberately **not** subject to `bounce.max_per_hour`: that cap exists so a
delivery-failure storm cannot become a mail storm, and an expiry warning is
already limited to one a day by its own gate. Dropping a warning about
something expiring would defeat the point of sending it.

`Watcher` checks immediately at startup and hourly thereafter, batches every
due item into one mail (an operator with a certificate and two secrets
expiring the same month wants one mail, not three), and re-sends at most once
per day per item. An expiry that has **already passed** is still reported,
with `ACTION REQUIRED` in the subject — that is the case most worth hearing
about, so it is not dropped for being out of range. A certificate that cannot
be read is logged rather than mailed: the listener would not have started on
one, so it means the file changed under a running service. State is in memory
only; a restart re-checks and may mail again, which is the safe direction for
a warning.

**Verified end to end**, not only by unit test: a relay configured with
`bounce.notify` and a certificate generated by **openssl** (not by `certgen`,
so the parsing path is exercised against a foreign certificate) expiring in
nine days logged `expiry warning sent` on startup and left a well-formed
message in the spool — correct `From`/`To`/`Subject`
(`[smtprelayd] the listener TLS certificate expires in 8 day(s)`), the file
path, the RFC 1123 expiry, `8 day(s) left`, and the consequences paragraph.

**Three false documentation claims found and corrected while doing this.**
`docs/guides/SECURITY.md` asserted (a) certificate expiry "is exposed as a
metric" and (b) client secret expiry is "surfaced as a metric" — neither
exists; there is nothing matching `cert` or expiry in `internal/metrics`. Both
lines now describe what actually happens. Still uncorrected and worth a
decision: the same file claims `smtprelayd token new` "generates a 256-bit
random token, prints it once and emits the digest to paste into the
configuration". **That command does not exist** — there is no `token` case in
`cmd/smtprelayd`. Operators are told to run something that will print "unknown
command". Left alone here because inventing the command is a feature, not a
documentation fix.

## The new feature: `smtprelayd gen-cert`

From "können wir selbst generierte zertifikate erstellen beim…" — the
sentence broke off, so the three candidate places (installer, first start, own
subcommand) were put to the operator and they chose the subcommand. That is
also the only one of the three that touches neither the schema nor the startup
path, so it needed no sign-off under working agreement 4.

New `internal/certgen` produces a self-signed certificate and key as PEM
bytes; `cmd/smtprelayd/gencert.go` decides where they go. Stdlib only
(`crypto/x509`, `crypto/rsa`, `encoding/pem`), so no new dependency, no cgo,
Windows cross-compilation unaffected.

**RSA 2048, not ECDSA.** `docs/guides/SECURITY.md` deliberately keeps TLS 1.0
reachable on the internal port 25 listener because the devices this relay
serves are printers and MFPs. A key those clients cannot negotiate would turn
an operator convenience into a support call, and 2048 bits generates in well
under a second. `KeyUsage` therefore includes `KeyEncipherment` alongside
`DigitalSignature`: a client old enough to need TLS 1.0 may still negotiate
RSA key exchange. `IsCA: false` — it is a server certificate, trusted by being
imported or pinned, never by signing anything else.

**It runs on a configuration that does not validate.** This is the point, not
a shortcut. `Validate` refuses to load when a listener sets `tls` and the
certificate it names is absent — the exact state `gen-cert` exists to
resolve — so demanding a valid configuration first would make the command
useless for its own purpose. It relies on `config.Load`'s documented
behaviour of returning the decoded `Config` alongside an error, prints the
validation failure as a warning, and proceeds. A nil `Config` (unreadable or
undecodable file) is still a hard failure, because then there is no `[tls]`
block to act on. Nothing in the command binds a port, opens the spool or
reads a secret: it writes two files and exits.

**It writes to the paths `[tls]` already names** rather than inventing any, so
no path is built by joining an unvalidated string — the CLAUDE.md ban that
`config.LogPath` exists to satisfy elsewhere does not come into play here.
Empty `cert_file`/`key_file` is an error telling the operator to set them
first. It **refuses to overwrite** either file without `-force`, since these
are the paths a CA-issued key lives at. `fsmode.RestrictFile` is called after
writing the key because `os.WriteFile` applies its mode only on creation, so
a `-force` run over a key someone had loosened to 0644 would otherwise leave
it loose — verified by hand and by test.

SANs are derived from `service.hostname`, every non-wildcard listener bind
address, and loopback, then printed. A wildcard bind contributes nothing: it
is not a name any client asks for.

**Verified for real, not just by unit test.** Against a generated pair, a
relay with an `implicit` TLS listener on loopback completed a TLS 1.3
handshake with `openssl s_client -verify_return_error -CAfile <the cert>
-servername relay.test.invalid` reporting `Verification: OK`, and answered
with its `220 relay.test.invalid ESMTP smtprelayd` banner. `openssl x509`
confirms RSA 2048/SHA-256, `CA:FALSE`, `TLS Web Server Authentication`, and
the SAN list split correctly into DNS and IP entries. Also confirmed on the
real `configs/smtprelayd.example.toml` (paths redirected to a temp dir): the
`[tls]: open …relay.crt: no such file` error that `make check` has been
failing on for months is gone after one `gen-cert` run.

That same end-to-end run doubled as live confirmation of this session's
selftest fix: the test config allowlists `127.0.0.1/32`, so `selftest` would
have reported that correct configuration as an open relay before today. It
now prints the `note:` and passes.

**The limitation this shipped with was closed the same session.** The
certificate is valid 825 days and nothing warned as that approached; that is
what `internal/expiry` above now does by mail. A *metric* for the same value
still does not exist, so a host with no `bounce.notify` contact gets no
notice beyond the date printed at generation.

### expiry.warn_days, and the expiry view on the dashboard (2026-09-16)

Two operator requests, one after the other. First: show the certificate and
`oauth2.secret_expires` deadlines in the dashboard. Then, after "finde nichts"
when looking for how to configure the warning: make the lead time a setting.

**Schema change**, the only one of this session, and made on an explicit
request rather than unilaterally. New `[expiry] warn_days`, default 30,
range 0..3650, where 0 switches the mails off. Its own section rather than a
key under `[bounce]` precisely because of the "finde nichts": an operator
looking for expiry configuration now finds a section called `expiry`. The
contacts are still `bounce.notify`/`bounce.sender`/`bounce.notify_route`, so
there is no second place to keep addresses.

`expiry.WarnBefore` (a constant) became `expiry.WarnWindow(cfg)`, and
`collect` returns nothing at all when the window is zero.

**Deliberate triggering is now the documented test.** Raising `warn_days`
above the remaining lifetime pulls a healthy certificate into the window and
the mail goes out at the next restart, because the watcher checks immediately
at startup. Verified both directions end to end: an 825-day certificate with
`warn_days = 30` sends nothing, and the same certificate with
`warn_days = 900` produced `[smtprelayd] the listener TLS certificate expires
in 824 day(s)` with a well-formed message in the spool. That is cheaper than
reissuing a short-lived certificate and exercises the identical path.

**The dashboard view sits at the top of the Configuration page**, on the
operator's instruction — it was first built into the Routes page and moved.
It lists *every* deadline regardless of `warn_days`, with a state of `ok`,
`soon` or `expired`, so a healthy certificate is visible rather than only an
unhealthy one being audible. A certificate that cannot be read is shown as
such instead of being omitted. `internal/expiry` gained exported `Items`,
`DaysUntil` and `WarnWindow` so the page and the mail share one definition of
what expires and when, rather than the web layer parsing the certificate a
second time.

`gen-cert` also gained `-days N` (1..7300) along the way, before the operator
redirected to a config setting. It was kept: it is tested, and a shorter
certificate lifetime is a reasonable thing to want independently of testing.
Say so if it should go.

**A third false metric claim** was corrected while here:
`configs/smtprelayd.example.toml` said `secret_expires` was "surfaced as a
metric for alerting". It is not. That makes three such claims found and fixed
this session; none of them ever existed in `internal/metrics`.

### Three gen-cert defects fixed (2026-09-16, same session)

Found while answering operator questions rather than by review, which is why
they are recorded separately from the feature above.

**The key was unreadable by the service on Linux.** `gen-cert` wrote the key
`0600` and its directory `0700` owned by whoever ran it — root, on a server —
while the service runs as `smtprelayd`. The account could not even traverse
into the directory, and the symptom is a service that refuses to start saying
nothing about permissions. New `fsmode.ShareWithGroupOf` gives a path the
group that owns a reference path and the least permissive mode that still
lets that group read it (`0750` for a directory, `0640` for a file); the
reference is the configuration file, because the package already set
`/etc/smtprelayd` to `root:smtprelayd`, so no account name is hardcoded. It
runs *after* `RestrictFile`, so a failure leaves the key too restrictive
rather than too open, and a failure prints the exact `chown`/`chmod` instead
of failing the command. No-op on Windows, where the inherited DACL governs
access — which is why the operator never hit this there.

**The printed SAN list showed duplicates.** `certHosts` did not deduplicate,
so a hostname that was also a listener bind address appeared several times.
The certificate itself was always correct (`certgen.dedupe` handled it), but
the output an operator checks did not match what was issued. Worse, the test
covering it was named `…AndDeduplicates` and asserted the duplicates — a test
whose name contradicted its assertion.

**The metrics address was missing from the SANs.** `metrics.Serve` presents
this same certificate when it binds beyond loopback, so a certificate valid
for the mail listeners failed hostname verification for Checkmk. `certHosts`
now includes `metrics.address` when the endpoint is enabled. The dashboard
needs no entry — `Validate` pins it to loopback, already covered.

Verified end to end, not only by unit test: a configuration with a listener on
`10.0.0.10`, metrics on `10.0.0.5` and a hostname produced
`relay.test.invalid, 10.0.0.10, 10.0.0.5, localhost, 127.0.0.1, ::1` — each
once — and left `drwxr-x---` on the directory and `-rw-r-----` on the key,
both carrying the configuration file's group.

Two existing tests asserted the old `0600` intent and were changed to `0640`
plus an explicit check that no other account has any access, which is the
property that actually matters.

**The instructions now generate a certificate as part of the normal flow**
rather than mentioning it afterwards: `packaging/linux/postinstall.sh`'s
first-install text gained it as step 2 of 4, `README.md`'s Run section is an
ordered first-run sequence, and `docs/guides/CONFIGURATION.md` section 1
splits into "1a self-signed, generated here" and "1b from a CA".

### Field verification on the Windows server (2026-09-16)

Confirmed by the operator on the real deployment, not on the dev box:

- **`gen-cert` and the resulting certificate work.** TLS succeeds in both
  modes: implicit on 465 and STARTTLS on 587.
- **Dashboard reachable over plain `http://`** after the `web.Serve` change
  that removed the TLS branch. This was the session's one deliberate
  operator-visible behaviour change, and it is the confirmation that mattered.
- **Clean shutdown** — no `sql: database is closed` in the log after a service
  stop, which is what the `sync.WaitGroup` in `serve()` was added for.

`contrib/Test-SmtpTls.ps1` was written for this and is now validated in the
field as well as by reading. It connects with TLS 1.2 by default, prints the
negotiated **key exchange** (the diagnostic that matters, since Go disabled
RSA key exchange by default in 1.22, so a device that cannot do ECDHE fails
even when the version matches), and has `-ProbeAll` for a version sweep and
`-StartTls` for 587/25. Written against PowerShell 5.1 / .NET Framework 4.8,
since that is what a Windows Server ships.

Measured against a real listener while building it, with `min_tls = "1.0"`:
TLS 1.0 through 1.3 all negotiate, but 1.0 and 1.1 **only** over
`ECDHE_RSA_WITH_AES_128_CBC_SHA`. Pure RSA key exchange is refused with alert
40 unless the process runs with `GODEBUG=tlsrsakex=1`, which was verified to
re-enable `AES128-SHA` on TLS 1.0. On Windows that is set per service with a
`REG_MULTI_SZ` `Environment` value under the service key. It is a real
weakening (no forward secrecy) and would need a `MEMORY.md` decision before
being deployed permanently.

**Still untested on hardware**: the expiry warning actually arriving as mail.
The cheapest way to trigger it is to set `oauth2.secret_expires` on the M365
route to a date about ten days out and restart — the watcher checks
immediately at startup, so no waiting — then revert. That exercises the whole
collect/batch/compose/send path; only the source of the date differs from the
certificate case, which is already verified end to end above.

## The thirteenth review (2026-09-17)

The twelfth review's closing advice -- "do not run another review until a
feature changes" -- was wrong, and the way it was wrong is worth keeping. It
was true only for Linux. **Windows had never been tested at all.**

**The test package `cmd/smtprelayd` did not compile for Windows.**
`TestGenCertGivesTheKeyTheConfigurationsGroup` guarded itself with
`if runtime.GOOS == "windows" { t.Skip(...) }` -- which reads correctly and is
useless, because it also used `syscall.Stat_t`, a type that does not exist on
Windows. The skip never got to run: the package failed to compile first, which
took **all 23 tests in it** with it, including the service startup, token and
bind tests. Introduced in `ca5b036` during this session's gen-cert work.

The lesson generalises: **a platform-specific *type* cannot be gated at
runtime.** It needs a build tag. The function moved verbatim into
`cmd/smtprelayd/gencert_unix_test.go` behind `//go:build !windows`, and the
runtime skip went with it as dead weight.

Nothing could have noticed: both CI jobs run on `ubuntu-latest`, and
`make build-all` cross-compiles the *binary*, never the tests. The only
`windows-latest` job in the tree builds the MSI.

Two CI gates now close that:

- `GOOS=windows go vet ./...` on the existing Ubuntu runner. vet type-checks
  test files, so it catches exactly this class in seconds without needing a
  Windows runner. Verified by reintroducing the fault: Linux vet still passes
  (which is why it was invisible), Windows vet fails with the undefined type.
- A `windows-latest` job running `go test ./...` (no `-race`: it needs cgo,
  and the Linux job already runs it; what this adds is the platform).

**The Windows job was run for real before landing**, in a Windows Server 2022
VM (`dockurr/windows` under podman with KVM, unattended: the VM installs Go,
copies the tree from a shared folder and writes the output back). **18 of 21
packages pass. Four failures, in four distinct classes -- and only one is a
product defect.** Recorded here because the job as written will be red until
they are addressed, and a knowingly red required check blocks every PR.

1. **`buildpolicy.TestBannedImports` -- a path-separator bug in the test, not
   a policy violation.** It reports `internal\config\dpapi_windows.go imports
   "unsafe"`. The exception is already recorded and justified at
   `policy_test.go:32-33`, but its keys use forward slashes while `rel()`
   returns `filepath.Rel`, which yields backslashes on Windows, so the lookup
   misses. Fix: `filepath.ToSlash` in `rel`. One call. **The finding reads
   exactly like a banned import in shipped code and is not one** -- worth
   remembering before anyone reacts to that failure text.

2. **`config.TestLogPathRejectsEscapes/absolute_path` -- a Unix-only
   expectation.** `\etc\cron.d\smtprelayd` is not absolute on Windows
   (`filepath.IsAbs` wants a drive letter), so it is joined rather than
   refused, resolving to `\var\lib\smtprelayd\etc\cron.d\smtprelayd` --
   still inside the data directory, so the containment property LogPath exists
   to guarantee does hold. What differs is the mechanism, not the guarantee.
   Windows-specific escape shapes (`C:foo`, UNC `\\server\share`) have not
   been probed and should be before this is called settled.

3. **`web` and `theme` tests -- a test bug that mirrors a real documentation
   defect.** The tests write `data_dir = "<t.TempDir()>"` into a TOML *basic*
   string; on Windows the temp path contains backslashes, and TOML reads `\U`
   as an escape. The tests should use a literal string or `ToSlash`.
   **The documentation has the same problem and it reaches operators**:
   `configs/smtprelayd.example.toml:5` says `# Windows: C:\ProgramData\SMTPRelayd`,
   and a Windows operator who writes that in double quotes gets
   `invalid escape in string '\P'` and a config that will not load. Verified
   against the real binary. Single quotes parse. This is the project's primary
   production platform.

4. **`TestLogStartupFailureWritesToDataDir` -- a real behaviour worth a
   decision.** `logStartupFailure` runs `checkEnvironment` first, which on
   Windows includes `CheckDataDirACL`. A test temp directory inherits its
   DACL, so the gate refuses and nothing is written. In production the data
   directory has the protected DACL and it works -- **except on a fresh
   install before `secure-datadir` has run**, which the 2026-08-11 field
   incident shows is a state that occurs. In exactly that case a service
   startup failure produces no console (it is a service) and no error log,
   which is the scenario the function was built for. A narrower gate for this
   one file is defensible -- it carries the config path and the validation
   error, not message data -- but that is a design decision, not a fix to make
   silently.

The VM is at `~/.cache/smtprelayd-win-vm` (11 GB, container `smtprelayd-win`,
stopped). `podman start smtprelayd-win` reuses it; deleting the directory
reclaims the space.

Roughly 630 lines of the tree are Windows-only and had no automated coverage
of any kind: the data directory ACL (`SecureDataDir`, `CheckDataDirACL`), the
reparse-point refusal in `trust_windows.go`, DPAPI secret decryption, the
service wrapper. They were verified in the field, which is real evidence but
not regression protection.

Checked while sizing the Windows job: every permission assertion in the suite
(`Mode().Perm()`, `os.Chmod`) already sits behind a `runtime.GOOS == "windows"`
skip, and all test binaries cross-compile for Windows. Those skips are correct
where the *values* are Unix-only; the failure above was specific to a Unix-only
*type*.

### Verified clean, with evidence

**No other test copies product logic verbatim.** The twelfth review found a
test that rebuilt the logic it was meant to check. A mechanical search for
non-trivial logic lines (carrying a comparison or boolean operator) appearing
identically in a test file and in the product of the same package finds only
two hits today, both false positives -- they are *calls* to the function under
test. The detector was calibrated against the known case first: run over the
pre-fix `expiry_test.go` it reports the copied line exactly. Limit: it finds
only verbatim copies, not ones with renamed variables.

**The Windows `noFollow = 0` justification holds.** `nofollow_windows.go`
drops `O_NOFOLLOW` and points at the data directory ACL instead. That ACL
defect was fixed and field-verified, and `CheckDataDirACL` refuses to start
when the DACL is not protected, so the compensating control is enforced
fail-closed. Under that ACL only SYSTEM, Administrators and the service
account can create a reparse point there, and all three already have full
access.

## The twelfth review (2026-09-17)

With this review every trust boundary in the program has been measured by
mutation: SMTP session, HTTP authorization, sender rewriting, spool crash
recovery, delivery outcomes, the Host-header check, the startup trust checks
and the expiry warning. **Recommendation recorded here on purpose: do not run
a thirteenth architecture review until a feature has changed.** There is no
surface left that has not been measured; it would find wording, not defects.

Three mutations survived and are now killed.

**A test that tested its own copy.** `TestAnItemIsNotRepeatedWithinTheResendInterval`
existed and was named for exactly the guarantee in question -- the once-a-day
resend gate on expiry warnings -- yet deleting that gate from
`ExpiryWatcher.check` left it green. It rebuilt the gate inside a closure and
asserted on the closure; it never called `check`, which sat at 0.0% coverage.
It would have passed with no gate in the product at all. It was replaced, not
supplemented: the new version drives `check` through a real notifier at +0,
+1h, +23h and +25h and counts the warnings actually queued. What the gate
prevents: `check` runs hourly and `expiry.warn_days` defaults to 30, so one
expiring certificate would produce up to 720 mails instead of 30 -- and an
operator filters those away, losing the warning the feature exists for.

Worth remembering as a pattern: a test's name is not evidence. Only a
mutation shows whether it guards anything.

**The startup trust check.** `checkTrusted` has three refusals. The
group/world-writable one was already covered via `checkSecretFile`; the
**symlink** refusal was not, and neither was `CheckDir` itself -- returning
`nil` unconditionally went unnoticed. That is the check on `service.data_dir`
and the binary's directory in a process that may be privileged enough to bind
port 25. `TestCheckDirRefusesASymlink` covers both. The **ownership** refusal
is still untested and stays that way deliberately: it needs a directory owned
by another uid, which an unprivileged test run cannot create.

`internal/bounce` went from 72.7% to 81.1%.

### Verified clean, with evidence

- DNS-rebinding defence (`config.IsLoopbackHostHeader`, used by the dashboard
  and `/metrics`): accepting any Host header is caught.
- The expiry warning's window filter: reporting deadlines outside
  `warn_days` is caught.
- `checkTrusted`'s writable-directory refusal is caught.

## The eleventh review (2026-09-17)

Mutation sweeps at three trust boundaries that had never been tested that
way. **Two of the three came back clean**, which is the more useful half of
the result: the pattern from the ninth and tenth reviews does not generalise.

**The HTTP authorization layer holds completely.** Six mutations, six killed:
no bearer token required at all; the scope check removed so a read token could
requeue and delete; `ScopeSatisfies` always permitting; the failed-auth
backoff never blocking; the dashboard's bulk action skipping CSRF
verification; `MatchToken` accepting any non-empty token. **Sender rewriting
likewise** -- an unauthorized sender passing through unrewritten, and
`if_unauthorized` with an empty allowlist behaving as `force` while reading as
selective, both caught.

**The spool's crash-recovery path was the gap.** Two of five mutations
survived, and the consequence of the worse one was demonstrated rather than
argued. `recover` drops metadata whose body is gone; with the guard removed,
the same probe reports:

```
with the guard:    indexed=false  metadata still on disk=false
without the guard: indexed=true   metadata still on disk=true
                   and it is claimable for delivery: true
```

So the message is not merely listed -- it is handed out, fails on the missing
body, and retries until `queue.max_lifetime_hours` expires it. That is
reachable without any operator mistake (a crash between the two unlinks, an
interrupted removal, a hand-deleted spool file), and `store.ReconcileRemoved`
exists precisely to clean up the history row it leaves behind. The second
survivor was the `spool/tmp` sweep: without it, interrupted stages accumulate
across restarts while counting toward no quota, so the disk fills without
`limits.spool_max_gb` ever firing.

**`attempt` was entirely unexecuted** -- its pure helpers were covered by the
tenth review, the wiring between them was not. There is no seam to inject a
smarthost through, and adding one only for the test would be a production
change made for the test's benefit; the route's host and port come from the
configuration, so `attempt_test.go` points them at a scripted SMTP server on
loopback and drives the real path. All four outcomes are covered: delivered,
permanent, deferred with backoff, and expired.

One assumption of mine was wrong while writing these and is worth recording:
`Spool.Has` returns true for a **permanently failed** message too, by design
-- it reports "the spool still holds files for this", and a failed message
keeps them under `spool/failed` so the quota still counts them. The test
asserts on `Len` and on `Claim` instead.

All ten mutations across the four items are now killed. `internal/spool` went
from 79.4% to **83.5%**, `internal/delivery` from 33.3% to **61.3%**.

### Verified clean, with evidence

- Six of six authorization mutations killed (API bearer check, scope check,
  `ScopeSatisfies`, failed-auth backoff, dashboard CSRF, `MatchToken`).
- Two of two sender-rewriting policy mutations killed.
- Three of five spool recovery mutations were already killed before this
  session: orphaned body removal, `spool/failed` accounting at startup, and
  the failed body's bytes counting toward the quota.

## The tenth review (2026-09-17)

Measured instead of asserted. Coverage per package put `internal/listener` at
**42.9%** with every SMTP verb handler at 0.0%, so a mutation sweep was run
over the session's security controls. All six survived -- deleting any one of
them left the whole suite green:

```
SURVIVED  open relay: unmatched source may MAIL FROM
SURVIVED  require_tls no longer enforced
SURVIVED  MAIL accepted before HELO
SURVIVED  declared SIZE over the limit accepted
SURVIVED  SMTP smuggling: session kept open after a bare-LF dot
SURVIVED  hop limit not enforced
```

The first line means the default-deny refusal -- the one guarantee
`docs/guides/SECURITY.md` says cannot be recovered from cheaply, and which
CLAUDE.md names as a required negative test -- could be removed with CI still
green. `.github/workflows/ci.yml` runs the unit tests, gofmt, vet,
banned-imports, govulncheck and gosec; it did not run `selftest`, which needs
a running instance. Two controls had half coverage that is easy to mistake for
whole: `TestMatcherDefaultDeny` proves `Matcher.Match` does not match, and
`TestDotReaderFlagsNonConformingEndOfData` proves `dotReader` sets the
smuggling flag. Neither proved the **session acts on it**.

All six are now killed by tests that speak the protocol over a real socket
(`internal/listener/session_smtp_test.go`). Four need no spool or store,
because `doMail` touches neither; the hop limit and the smuggling refusal use
a real spool and history store in a temp dir. `internal/listener` went from
42.9% to **77.5%**.

`internal/delivery` was at 25.3% with `backoff`, `isPermanent`,
`isAuthFailure` and `extractSMTPError` -- all pure, all deciding whether a
message is retried or given up on -- at 0.0%. Four mutations there are now
killed too, including "isPermanent treats an authentication failure as
permanent", which is the exact scenario the code's own comment about the 535
warns would empty the queue into `spool/failed` on a secret rotation.

`scripts/selftest-ci.sh` starts a throwaway instance on loopback and probes
it, wired into CI and available as `make selftest-ci`. The client CIDR
deliberately excludes the loopback address the probe dials from: allowlisting
it makes the probe report "allowlisted, so the default-deny path was not
exercised" and still exit 0 -- true, and useless as a gate. Readiness is taken
from the instance's own `"listening"` log line rather than from `nc`, which is
not installed on every runner.

Both of the gate's failure modes were verified. Removing the guard from
`doMail` makes it fail with `EOF`, because `doMail` then dereferences a nil
client and the connection drops -- a crash, not a demonstrated open relay. A
genuine open relay (a client CIDR of `0.0.0.0/0`) is reported properly:
`relay to open-relay-probe@example.net was accepted from 127.0.0.1, allowed by
client "devices" whose cidr covers every address: that is an open relay`.

### Verified clean, with evidence

- **The documented retry semantics are true.** `CONFIGURATION.md:315` says
  "then the last interval repeats"; `backoff` clamps the index to
  `len(sched)-1` and does exactly that. Now pinned by a test.
- **Every package has tests.** No `no test files` anywhere in the tree.

## The ninth review (2026-09-17)

Two of the three findings were **test gaps on security-relevant code, not
defects** -- the code did the right thing in both cases. After the eighth
review reported a bug that one test run would have disproved, every finding
here was proved by running it before it was written down.

**`loginAuth` had no test at all.** Its `Start` carries two guards: the
refusal to offer LOGIN on an unencrypted connection, and the check that the
server name matches the configured host. Removing the cleartext refusal left
the **entire suite green**. That guard is load-bearing, not belt and braces:
`config.Validate` only rejects `auth` against `tls = "none"`, and `Deliver`'s
own check compares against that same literal, so a `config.Route` whose TLS is
neither `"none"` nor `"starttls"` reaches AUTH with neither having fired --
exactly the "hand-edited or future in-memory Route" the comment at
`client.go:153` names as the thing to defend against. `smtp.PlainAuth` blocks
this itself and `xoauth2Auth` had the test; `login` had neither. Both guards
plus the `Next` challenge dispatch are now covered.

**No test bound `client`, `route`, `since` or `until` in any of the three
query builders.** Deleting the client and route clauses outright from
`FindMessages` left the suite green, and the same block appeared three times,
each equally undetected. `TestEveryFilterFieldBinds` now exercises every field
against `FindMessages`, `FindBounces` and `FindBounceSummaries`; all three
copies were mutation-checked individually. A silently dropped filter is
invisible and shows an operator other clients' mail in a view that claims to
be filtered -- the same shape as `spool_warn_percent`.

**Only then were the three copies merged** into `commonFilters.apply`. Doing
it the other way round would have consolidated three unverified copies. The
`Since`/`Until` column differs between the queue views and the bounce summary,
so it is a parameter -- given a defined `timeColumn` type with exactly two
package-level values, because it is interpolated rather than bound. Verified
by capturing the generated SQL and the bound values from all three builders
for a fully populated filter, before and after: **byte-identical**.

**`<-done` on the bind-failure path was not synchronisation.** The deferred
`stop(); bg.Wait()` already covers every return path, which is why the
`web.New` failure path returns without draining and is still correct. The
explicit `stop()` there went with it for the same reason. The remaining
`<-done` does earn its place, and now says so: it orders the final
`queued` count after the delivery manager stops draining the spool.
`TestServeReturnsWhenTheListenerCannotBind` was added because that path had no
coverage at all -- it fails in 20 seconds if the deferred `stop()` is ever
dropped, and passes in under 20 ms otherwise.

### Verified clean, with evidence

Recorded so the next review does not re-derive them:

- **`query.go:354` interpolates the sort column into SQL under a `#nosec
  G202`, and the claim is true.** `col` comes from a `messageSortColumns`
  lookup with a fallback; the request value is never passed through. `order`
  is a two-branch choice between literals.
- **`InsecureSkipVerify` occurs once in the tree**, in the selftest probe,
  replaced by an exact pin -- and the comment reasons correctly about there
  being no session cache, which is the resumption path that would otherwise
  bypass the pin.
- **`pinVerifier` is on `VerifyConnection`, not `VerifyPeerCertificate`**, for
  two correct reasons: the latter is handed the certificates sent rather than
  the chain built (an appended pinned cert would satisfy it), and it is
  skipped entirely on a resumed session.
- **STARTTLS never downgrades.** A smarthost not offering it produces a
  temporary error and the message stays queued.
- **Shutdown ordering in `serve()` is correct**: `bg.Wait()` runs before
  `st.Close()` because the defers are registered after the store is opened.

## The eighth review (2026-09-17)

**The review's headline finding was wrong, and that is the most useful thing
in this entry.** I reported that `web.activeQueueIDs` could never detect
truncation, because it asks `store.FindMessages` for `Limit: bulkMax` (1000)
and then tests `len(msgs) > bulkMax`, while `FindMessages` clamps
`filter.Limit` to at most 1000. I had read the clamp and never opened the
`LIMIT` binding 85 lines below it:

```go
args = append(args, filter.Limit+1, filter.Offset) // +1 to detect "has more"
```

The clamp runs first and leaves 1000 unchanged; the query then binds 1001.
Proved with a throwaway probe: 1005 active rows, `Limit: 1000`, **1001 rows
returned**, so `len(msgs) > bulkMax` is true and the "repeat the action"
banner appears. `FindBounces` and `FindBounceSummaries` bind `Limit+1` the
same way, so the sidebar's `len(recent) > 5` guard is load-bearing too, not a
defensive check against an impossible state as I claimed. `bulkMax`'s own
comment states the behaviour correctly and I should have read it.

**Do not re-report this.** Every `FindMessages`/`FindBounces` caller in the
tree relies on the `Limit+1` contract, and all of them are correct: the queue
and search pages' next-page links, `/api/v1/messages`'s `next_cursor` via
`splitHasMore`, and the bulk truncation flag.

What was actually implemented from that review:

**`web.go` split**, 1084 lines to 650. `internal/web/format.go` holds the
twelve presentation helpers (link building, paging parameters, the value
formatting the configuration page renders) -- none of them touch the store,
the spool or the request, which is why they can sit apart from the handlers.
`internal/web/bulk.go` holds the queue's bulk actions with `bulkMax` and
`bulkBudget`. The per-message primitives stayed in `web.go`, where the
single-message endpoints use them too.

**`routes()` split**, the 158-line residue of the previous session's
`Validate` work, into `routeIdentity`, `routeTLS`, `routeAuth`, `routeCAPin`,
`routeDomains` and `routeSources`; `routes()` itself is 23 lines. The
file-order check used last session no longer proves anything here, because
the extracted methods are defined below their caller -- verified instead by
running a configuration that trips fifteen route errors across two routes,
including the cross-route domain and source claims, through the old and new
code: the error list is byte-identical.

**`logging.redact` no longer redacts a credential's name.** `secretKeys`
matches key substrings and contains `"token"`, so `token_name` -- the field
that says *which* API token performed an audited action -- would have been
replaced with `[redacted]`, leaving a line recording that somebody did
something. Nothing logs it today (no slog key in the tree matches any
`secretKeys` entry, so `redact` has never fired in production; it is
deliberate insurance against a future call site). `secretKeyNames` now exempts
it, with a test that fails if the exemption is removed.

**`maxInt` replaced with the builtin `max`**, available since Go 1.21 against
this module's `go 1.25.13`.

## The seventh review's five fixes (2026-09-17)

**A token request to Microsoft blocked the whole observability surface.**
`TokenSource.Token` holds `s.mu` across `fetch` — an HTTPS request with a
15-second timeout — and `TokenAge` took the same mutex. `TokenAge` is reached
from the metrics registry, and through its snapshot from every dashboard page
and `/api/v1/health`. With `failCooldown = 30s`, an M365 outage left that
surface blocked roughly half the time, exactly when an operator is trying to
find out what is wrong; a liveness endpoint hanging on a third party's HTTP
call reports "dead" for a relay that is up and accepting mail. `issuedAt` is
now an `atomic.Pointer[time.Time]` and `TokenAge` is lock-free. The serialised
fetch — the reason the lock exists — is untouched.

The first attempt at this stored `now.UnixNano()` in an `atomic.Int64`, which
two reviewers caught: a `time.Time` rebuilt from a nanosecond count carries no
monotonic reading, so `time.Since` falls back to wall-clock subtraction and a
backwards NTP step or a VM resume would emit a *negative*
`smtprelayd_oauth_token_age_seconds`. Storing the `time.Time` keeps the
monotonic reading and makes nil the "no token yet" sentinel.

**`Config.Validate()` split, after standing in five consecutive reviews.**
637 lines in one function became a `validator` struct with one method per
configuration section, called in the file's own order. The requirement was
that nothing change: same checks, same error strings, same *order* of the
accumulated list, since `Validate` joins them into one message. Verified three
ways — all 112 error format strings identical and in identical sequence, a
mechanical normalised diff showing no altered condition or argument list, and
a differential run of the old and new `Validate` over **66,360 generated
configurations** comparing both the error text and the mutated `Config`:
zero mismatches.

The per-element defaults that `Defaults()` cannot hold (they belong to slice
entries that do not exist until the file is decoded) moved into `normalize()`,
which `newValidator` calls so no section method can be reached without it.
`route.oauth2.scope` deliberately stayed inline — it is conditional on the
route actually using OAuth2, and defaulting it unconditionally would populate
the field on routes that do not — as did the domain lower-casing, which is
interleaved with duplicate-domain detection.

**`Spool.Commit` read the quota without the lock.** `SetQuota` writes
`maxQuotaBytes` under `s.mu`; `Commit` read it outside, while calling
`spoolSize()` — which does lock — in the same expression, so the unlocked read
looked deliberate. Not reachable today (`SetQuota` runs once before the
listeners bind) but `SetQuota` is exported and says nothing of the sort. Now
one locked `overQuota`, which also makes the size and the quota consistent
with each other rather than sampled a moment apart. `&&` still short-circuits
inside the lock, so no quota still means no walk of the index.

**`doData` split**, 180 lines into `stageMessage`, `commitCopies` and
`journalAccepted`. `defer staged.Discard()` deliberately stayed in `doData`:
moving it into `stageMessage` would discard the stage before the copies are
committed, which is the one thing this extraction could easily have got wrong.

**`retentionCleanup` lost an error return that was never non-nil**, so the
call site's `_ =` stops reading as a swallowed error.

Both new tests were mutation-checked: restoring the mutex in `TokenAge` fails
`TestTokenAgeDoesNotBlockOnTheFetchLock` cleanly (it was rewritten to assert
on the main goroutine — the original shape would have *panicked* with "Log in
goroutine after test has completed", hiding the regression it exists to
catch), and breaking the route port default fails
`TestElementDefaultsAreApplied`.

## The five review fixes

**Dead code that documented a lie.** `logging.FromContext`, `WithLogger` and
`loggerKey` had zero callers anywhere, tests included — but `WithLogger`'s
comment claimed it was "used to carry the queue ID through the delivery path
so that every line of one message shares a correlation key". That correlation
key is real and is produced a completely different way, by `log.With` in
`delivery.attempt` and `session.handle`. Deleted, along with the now-unused
`context` import. Same class as the `spool_warn_percent` defect last session:
something that reads as working, is documented as working, and is inert.

**The dashboard was silently HTTPS whenever mail TLS was configured.**
`web.Serve` branched on `cfg.TLS.CertFile != ""` — but that field is
populated as soon as *any SMTP listener* uses STARTTLS or implicit TLS, which
`Validate` requires. So turning on TLS for mail flipped the dashboard to
HTTPS on loopback, and an operator following `CONFIGURATION.md` to
`http://127.0.0.1:8025` got a bare handshake error. The function's own doc
comment described a third behaviour again ("binding beyond loopback … serves
HTTPS"), which `Validate` makes unreachable since it refuses a non-loopback
`web.address` outright. The branch is gone: the dashboard is always plain
HTTP, which is what the docs already told operators and what the trust
boundary actually is — there is no address a certificate could authenticate
to. `metrics.Serve` keeps its TLS branch and was already correct, deciding
from the address, because a metrics listener may legitimately bind beyond
loopback behind a bearer token. **This is the one operator-visible behaviour
change of the session**: anyone who had been reaching the dashboard over
`https://` on loopback must drop the `s`.

**One primitive, three copies — two of them security controls.** `web`, `api`
and `metrics` had each grown their own `bearerToken` and `sourceAddr`, byte
for byte identical, X-Forwarded-For rationale comment included, plus a third
copy of `parseTimeRange`. Bearer parsing is credential handling and
`sourceAddr` decides what the failed-auth backoff counts and what the audit
log blames; three copies is three places to fix and two to forget. New
`internal/httpx` holds `BearerToken`, `SourceAddr` and `ParseTimeRange`, and
it is a leaf with no internal dependencies. `api.scopeSatisfies`, a one-line
pass-through to `config.ScopeSatisfies` that `metrics` already called
directly, went with it.

**Deliberately narrowed**: the review also listed the two `requireLoopbackHost`
middlewares as a fourth duplication. They were left alone. Their log messages,
their refusal text and which source field they log all differ, so sharing them
means a function taking two message strings whose call site is as long as the
body it replaced — indirection without a defect fixed. The substance they have
in common, `config.IsLoopbackHostHeader`, was already shared.

**A cap that was not a cap.** `api`'s `failLimiter` called `evictLocked` once
the table passed `maxTrackedSources` (4096), but that only ever deleted
entries whose backoff *and* failure window had both expired. A caller cycling
source addresses fast enough keeps everything unexpired, so eviction found
nothing and the map grew without limit — precisely what the constant existed
to prevent, while its comment promised the opposite. New `makeRoomLocked`
runs before a new source is admitted: expiry first, then, if the table is
still full, it drops the entry whose backoff ends soonest. A never-blocked
entry carries a zero `blockedUntil` and so is always chosen ahead of one
still serving a backoff — evicting a blocked source would hand it a way out
of its own backoff, and that now only happens once every tracked source is
blocked, which costs five failures on each of 4096 addresses. Low reachability
today (the API shares the dashboard's loopback-only listener) but load-bearing
the moment the dashboard login lands.

**The open-relay probe failed correct configurations.** `selftest` dials from
the host the relay runs on, so it arrives on the listener from loopback.
`SECURITY.md` asserted it connects "from an unlisted source" — untrue the
moment an operator allowlists `127.0.0.1` for an application on the same
machine, an ordinary deployment. The probe would then be permitted to relay
and the check would report a correct configuration as an open relay. Since
this is the check CI runs to prove the relay is not open, a false positive
there trains operators to ignore it. `probe` now resolves its own source via
`conn.LocalAddr` and matches it with **`listener.NewMatcher` — the relay's
real matcher, not a second copy**, so the probe cannot pass where the running
listener would deny. An accepted relay from an allowlisted source is a
`note:` on stdout rather than a failure, and the note says the default-deny
path went untested so it cannot be read as an unqualified pass. A client
whose `cidr` covers every address still fails outright: that is an open relay
however the match is reached. `Run` returns `([]string, error)` now; `main`
prints the notes before the verdict.

Verified: `gofmt -l .` clean, `go vet ./...` clean, `go build` for
`linux/amd64`, `windows/amd64` and `linux/arm64` clean,
`scripts/check-banned-imports.sh` clean for all three targets, and
`CGO_ENABLED=1 go test -race ./...` green across all 19 packages. The
dependency graph is still acyclic; `internal/httpx` is a leaf and
`selftest → listener` is the one new edge. Twelve new tests:
`internal/httpx` gets 3 (bearer scheme is case-sensitive and space-required,
`SourceAddr` ignores X-Forwarded-For and handles IPv6 and a portless
RemoteAddr, `ParseTimeRange` rejects a date-only value rather than guessing a
layout), `internal/api` gets 2 for the ceiling (it holds under 8192 same-instant
sources, and a blocked source survives that pressure), `internal/selftest`
goes from **0 tests to 5** against a stub SMTP responder (refusal at RCPT,
refusal at MAIL FROM, acceptance from an unmatched source failing, acceptance
from an allowlisted source noting, and a `0.0.0.0/0` client still failing),
and `internal/web` gets 1 proving a configured certificate no longer changes
the dashboard's scheme. That last one was mutation-checked: restoring the TLS
branch makes it fail with a connection refusal.

**Note for the next session**: `docs/dev/PHASE4-PLAN.md:311` shows a curl
example against `https://localhost:8025/api/v1/bounces`. That was already
wrong before this session and is now definitively so. Left alone deliberately
— it is a dated planning record, and rewriting one to match today's code
loses the history it exists for. `docs/guides/CONFIGURATION.md`, which is the
operator-facing doc, says `http://` and now states the rule explicitly.

**Still deferred**: `smtprelayd token new`, which
`docs/guides/SECURITY.md` documents and which does not exist. A metric for
certificate and client-secret expiry (the mail warning covers the alerting
need; a metric would let Checkmk see it too). A fourth copy of the
"compose, enqueue, record" block still exists in `internal/canary`, which
could now move to `bounce.Notify` as the digest path did.
`Spool.Commit` reads `s.maxQuotaBytes`
without holding `s.mu` while `SetQuota` writes it under the lock (not
reachable today; `SetQuota` runs once before any listener binds).
`Config.Validate()` is 611 lines and applies per-route defaults that
`Defaults()` does not, so `Defaults()` is not the whole answer for
`route.port`, `route.min_tls`, `route.max_concurrent` and `oauth2.scope` —
still the largest single risk surface in the tree, and per working agreement
4 it needs sign-off before anyone splits it. Subject redaction for
`history.retain_subjects` is still implemented three times across `web` and
`api` and belongs in `store`, which already receives the flag and uses it
only on write. `session.doData` is 159 lines. `store`'s three query builders
repeat the same seven filter clauses. `metrics` still depends concretely on
`authms365` for one value. A new smarthost auth type still touches five
files, two of them only to classify a route for display. And `make test`
still cannot run: the Makefile exports `CGO_ENABLED=0` while `test:` runs
`go test -race`, which needs cgo — pre-existing, CI sidesteps it by calling
`go test -race` directly at `.github/workflows/ci.yml:43`.

**Previous session**: 2026-09-15 (thirty-third session) — Three fixes from an
architectural review of the whole tree, no phase work and no schema change.
The operator picked three of eight findings: "fix 1 2 and 5".

**A configured safeguard that did nothing.** `limits.spool_warn_percent` was
defaulted to 80, range-checked 0–100 by `Validate`, documented in two places
and shipped in the example config — and `Spool.warnQuotaPercent` was written
by `SetQuota` and *read nowhere in the tree*. An operator who set a spool
warning threshold got silence right up until `ErrQuotaExceeded` started
refusing mail. Validation is what made it worse rather than better: the key
passed every check, so it read as working. New `Spool.QuotaWarning()` reports
`(used, quota, over)` and holds no logger — that package has none, by design —
and `delivery.Manager.reportQuota` does the logging, `spool is filling up` at
WARN on the rising edge and `spool is back below the quota warning threshold`
at INFO on the falling one. Edge-triggered, because the dispatch loop polls
every 5s and the steady state would bury the one line an operator greps for.
The threshold is `used >= quota/100*percent`, dividing first because
`SetQuota` can clamp the quota to `math.MaxInt64` and the multiplication
would overflow; that loses at most 99 bytes on a threshold measured in
gigabytes. The summation moved into an unlocked `sizeLocked()` shared with
`spoolSize()`, so *what counts against the quota* — the live index plus
`spool/failed`, a deliberate decision so a reliably-failing client cannot
free its own quota — has one definition feeding both the enforced quota and
the warned-about one, not two that can drift.

**Four of five background goroutines were never awaited.** `serve()` ran
`defer st.Close()` on the SQLite history store while the bounce notifier,
every canary, `metrics.Serve` and `web.Serve` were still live — and
`web.Serve` spends up to five seconds in `srv.Shutdown` draining dashboard
requests that query that store. So the graceful HTTP shutdown already written
in `internal/web/http.go` was never actually honoured, and a canary or digest
enqueued during shutdown lost its journal row silently (`database/sql` is
safe after `Close`, so these returned `sql: database is closed` into a `_ =`
rather than crashing). Now a `sync.WaitGroup` covers all five, using Go
1.25's `WaitGroup.Go`. The ordering is the subtle half and is commented in
place: deferred calls run LIFO, so the cleanup calls `stop()` *itself* before
`bg.Wait()` rather than relying on the `defer stop()` above it — otherwise
any early-return startup path (a `web.New` failure, say) would wait on
goroutines whose context had never been cancelled, turning a clean startup
error into a hung process. `dm.Run` was initially left on its existing `done`
channel and that was wrong: `done` is drained on only two of the three paths
that can reach it, so the `web.New` failure path returned with the dispatcher
still writing attempt rows. It is in the WaitGroup now, with `done` kept for
the accept-loop ordering it already did.

**`delivery` built canary runners it never used.** `delivery.New` called
`canary.New` into a field whose only reader was a `Canaries()` accessor whose
only caller was `serve()`, which ran them. The whole `delivery → canary`
package edge existed for construction alone. Runners are now built in
`serve()` next to the goroutine that owns them; the field, the accessor and
the import are gone. `canaryNames` stays in `delivery.New` — `metrics.New`
still needs it to seed the per-canary counters at zero. Deliberately *not*
done to `bounce.Notifier` alongside it, which looks symmetric and is not:
`m.notifier.RecordFail` is called from `Manager.fail`, so that one is
genuinely coupled and belongs where it is.

Verified: `gofmt -l .` clean, `go vet ./...` clean, `go build` for
`linux/amd64`, `windows/amd64` and `linux/arm64` clean,
`scripts/check-banned-imports.sh` clean for all three targets, and
`CGO_ENABLED=1 go test -race ./...` green across all 18 test packages. Two
new tests: `TestQuotaWarningReportsThresholdCrossing` (no quota, quota
without threshold, and the crossing at exactly 80%) and
`TestReportQuotaLogsOnlyOnTransition` (rising edge, staying over logging
nothing, falling edge, staying under logging nothing, plus the zero-quota
division guard). The second was mutation-checked: deleting
`m.quotaWarned = over` makes it fail, so it tests the edge and not just the
message text.

**Note for the next session**: `make test` cannot work as written. The
Makefile has `export CGO_ENABLED = 0` at the top and `test:` runs
`go test -race ./...`, but `-race` requires cgo, so the target fails before
running anything. This is pre-existing and not caused by this session's
change — it fails identically on a clean checkout. CI does not hit it because
`.github/workflows/ci.yml:43` runs `go test -race ./...` directly, outside
the Makefile. Either the `test:` target needs `CGO_ENABLED=1`, or it should
drop `-race` and leave the race build to CI. Not changed here because it is
a toolchain decision, not part of what was asked.

**Deliberately deferred, from the same review**: `Spool.Commit` reads
`s.maxQuotaBytes` at `internal/spool/spool.go` without holding `s.mu` while
`SetQuota` writes it under the lock — `SweepFailed` takes the lock for the
sibling `failedTTL`, so `Commit` is the outlier. Not reachable today
(`SetQuota` is called once in `serve()` before any listener binds) and
`go test -race` cannot catch it because no test calls the two concurrently,
but `SetQuota` is exported and its doc comment does not say it is
configuration-time-only. Five further findings from that review were reported
and not actioned: `Config.Validate()` is 611 lines and also applies per-route
defaults that `Defaults()` does not (so `Defaults()` is not the whole
answer); subject redaction for `history.retain_subjects` is implemented three
times across `web` and `api`; `web.parseTimeRange` and
`api.parseTimeRangeQuery` are byte-identical; `session.doData` is 159 lines;
`internal/selftest` — the open-relay probe — has no tests.

**Previous session**: 2026-09-15 (thirty-second session) — One feature, from
"ich möchte die canary nicht nur als intervall sondern zu einem bestimmten
zeitpunkt. (UTC)" / "z.b täglich 07:00".

A `[[canary]]` entry now configures **exactly one** of `interval_minutes` or
the new `daily_at`; both, or neither, is a load-time error. An interval is
the wrong instrument for "a test mail every morning before anyone is in": it
drifts with every restart, so the one thing the operator wants to be able to
say about a daily canary — *it is late* — stops being answerable. Asked
before touching the schema (working agreement 4); the operator chose both
spellings of the value and fixed UTC.

`config.DailyAt` therefore decodes itself (`UnmarshalTOML`) and accepts a
single `daily_at = "07:00"` or an array `["07:00", "19:30"]`: once a day is
the common case and a one-element array would be noise an operator has to be
told about. The strings are kept verbatim and resolved by `DailyAt.Minutes()`
(sorted, de-duplicated) so a malformed time is one more collected `Validate`
error naming its canary, not a decode failure that aborts the file without
saying which entry was wrong. Parsing is strict `HH:MM` by hand and not
`time.Parse`, which would also accept `"7:00"` and a `"24:00"` that rolls
into the next day — both a schedule other than the one written down.

**UTC, not `service.timezone`**, recorded in `MEMORY.md`: that setting only
ever changed how a timestamp is *displayed*, this one decides when mail is
sent, and a DST zone has one day a year without 02:30 and one with two —
plus `time.LoadLocation` on Windows would mean embedding `time/tzdata` or
depending on the registry. `docs/guides/CONFIGURATION.md` says so explicitly,
with the Vienna example (07:00 UTC = 09:00 local in summer, 08:00 in winter),
because that is the one thing an operator will get wrong.

`Runner.runDaily` takes the wait in steps of at most a minute, recomputed
from the wall clock, instead of arming one timer for up to 24 hours: a Go
timer counts on the monotonic clock, which stops while the machine is
suspended and does not follow an NTP step, so a single long timer would miss
07:00 by exactly as much as either event moved the day. A scheduled time
already past when the process looks again sends once, late — a late canary
is a signal, a missing one is indistinguishable from the failure the canary
exists to detect. Cancellation is selected on *inside* each step, so a
service stop never waits out a step. The next send is logged (`canary
scheduled`) after every send.

Verified with `~/sdk/go1.25.13` (not on `PATH`): `gofmt -l .` clean,
`go vet ./...` clean, `go build ./...` plus `GOOS=windows GOARCH=amd64` and
`GOOS=linux GOARCH=arm64` clean, `go test ./...` and `go test -race` green
including 25 new cases (`nextDaily` across two times a day, exactly on a
scheduled time, a non-UTC `now`, midnight, a month boundary; `waitUntil`
returning immediately for a past deadline and on cancellation without
waiting out a step; `Run` stopping on cancel with a daily schedule and
refusing to start on a malformed one; decoding a single time and an array,
unsorted and repeated times collapsing; both schedules, neither schedule,
`"7:00"`, `"24:00"`, `"07:60"`, a bad time inside an array and a non-string
`daily_at` all refused), `scripts/check-banned-imports.sh` clean for all
three targets, `govulncheck` clean, `gosec -severity=medium` 0 issues over
55 files. Also run for real: the built binary with
`daily_at = ["<now+2min>", "23:59"]` logged `next` as the nearer of the two
and queued the canary at that minute.

**Previous session**: 2026-09-14 (thirty-first session) — One feature and one
real bug, both from the same report: "ich hatte das problem das 94 email in
der queue waren. ich möchte einen punkt haben wo ich einzelne mails markieren
kann oder auch alle und dann aus der queue entfernen bzw nochmals senden
versuchen kann", followed mid-work by "nach dem manuellen löschen ist es
immer noch drinnen. unter queue."

**The bug, which is the more important half.** The queue view is built from
the history store (`FindMessages`, status `active` = no attempts or a
`temporary` latest attempt) while the spool is what actually holds the mail,
and the two can disagree: `Spool.recover` silently drops metadata without a
body and a body without metadata at startup, an operator can delete spool
files by hand (which is what 94 messages and no bulk action invites), and a
crash can land between the unlink and the attempt row. The history row then
matches `active` forever, and `spool.Discard` answering `ErrNotFound` made
both the dashboard and the API return 404 — so the row could never be
cleared, which is exactly the reported symptom. New
`store.ReconcileRemoved(queueID)` appends the `removed` attempt when, and
only when, the derived status is still queued or deferred; a delivered,
bounced or already-removed row is never rewritten (a message that reached an
outcome has no spool copy *because* it is finished). Both entry points go
through it, so "delete" cannot mean two different things depending on which
one is used, and an unknown queue ID is still a 404 — reconciliation repairs
a record, it does not invent one. The API answers `{"status":"cleared"}`
rather than `"deleted"` for that path so a script can tell the two apart.
`spool.Has(id)` is new alongside it, and the queue view marks such a row *no
spool copy*: requeue cannot do anything for a message with no body, and
without the marker its refusal would be a second mystery.

**The feature.** The queue page now carries a bulk form: per-row checkboxes,
a select-all box, `Requeue selected` / `Delete selected`, and whole-queue
variants of both. Design points that needed deciding rather than copying:
*scope* travels as `<button name="scope" value="...">` so the clicked button
picks it with no script; the form posts to `/queue/requeue` with the delete
button carrying `formaction="/queue/delete"`, which means one shared checkbox
set but two CSRF fields (`csrf_requeue`, `csrf_delete`, actions
`queue-requeue`/`queue-delete`, empty queue ID) — the per-action binding the
existing single-message tokens have is kept, and the set of messages cannot
be bound at issue time because it is chosen after the page was rendered.
"All" resolves to the *store's* active set, not the spool index, because that
is what the operator is looking at when they ask for it, and it is the only
resolution that can also clear the stale rows above; it is capped at 1000 per
submission (`store.FindMessages`'s own ceiling) and the banner says when more
remain. Deleting the whole queue is reached as a link to
`/queue?confirm=delete-all`, which renders a confirmation panel holding the
real form — a server-side interstitial, refresh-safe, no `confirm()` and no
script needed for the one irreversible action on the page. Requeue-all is not
confirmed: it is what the operator asked for and it destroys nothing. The
outcome banner is rebuilt from integers parsed out of the redirect
(`?done=delete&ok=91&cleared=2&busy=1`), so a reload cannot repeat the action
and no text from the request can reach the page; an unrecognised `done` value
renders no banner at all. Per-message audit rows are still written for every
message in a bulk action, with `details` = `bulk (selected)` / `bulk (all)`.

**The dashboard's first first-party JavaScript**, `internal/web/static/
queue.js`, loaded on the queue page only. Not avoidable and not incidental: a
select-all box cannot be built server-side, and the ten-second htmx refresh
would otherwise swap the table out from under a selection in progress —
`MEMORY.md` already records that objection as the reason `/search`'s results
table is excluded from polling. The script cancels the poll (via
`htmx:beforeRequest` + `preventDefault`, verified against the vendored htmx's
own `if(!he(r,"htmx:beforeRequest",H))` guard) while any box is ticked, and
the selection counter says "auto-refresh paused" so a visibly frozen table
does not read as a broken page. Everything is delegated from `document`
because htmx replaces the whole `#queue-live` region. An htmx trigger filter
(`every 10s [condition]`) would have been smaller but needs `new Function`,
i.e. `unsafe-eval` in the CSP, which is not worth it — `script-src 'self'` is
unchanged, and a test asserts the file contains neither `eval(` nor
`new Function`.

Verified with the same toolchain as the previous session (`~/sdk/go1.25.13`,
not on `PATH`): `gofmt -l .` clean, `go vet ./...` clean, `go build ./...`
plus `GOOS=windows GOARCH=amd64` and `GOOS=linux GOARCH=arm64` clean,
`go test ./...` and `go test -race ./...` green including 15 new cases
(bulk delete touches only the selection; bulk requeue audits with its
`details`; whole-queue delete refused unconfirmed and accepted confirmed;
CSRF refused for a missing field, the other action's token, a single-message
token and an expired one; malformed scope, a traversal-shaped id, a short id
and a selection over the cap all 400; the banner ignores an unknown action
and never echoes a count; the stale marker appears exactly once; `queue.js`
is served as `text/javascript` and has no `eval`; `ReconcileRemoved` clears
queued and deferred rows and leaves delivered, bounced, removed and unknown
ones alone; `spool.Has` covers queued, failed, discarded and an invalid id),
`scripts/check-banned-imports.sh` clean for all three targets, `govulncheck`
(no vulnerabilities) and `gosec -severity=medium` (0 issues, 55 files) both
clean. The queue page was also rendered once to a file and inspected by hand.
(`govulncheck` and `gosec` were not present in this environment and were
installed with `go install` into `~/go/bin`, which is also not on `PATH` —
next session can use them from there directly.)

**Same session, two corrections from the operator trying it.** "delete-all
geht nicht" plus "bitte als button einbauen": the whole-queue delete was an
`<a class="button-danger-link">` in a toolbar of real buttons, which is both
the wrong affordance and easy to read as dead. It is a `<button>` now. The
mechanism needed one HTML detail: the button's own GET form cannot be nested
inside the bulk `<form>` (a form inside a form is invalid and browsers drop
the inner one), so a hidden `<form method="get" action="/queue"
id="confirm-delete-all">` sits beside it and the button reaches it with the
`form` attribute. That keeps the confirmation interstitial a plain GET —
refresh-safe, no script — while looking and behaving like every other action
on the page. `.button-danger-link` dropped from the stylesheet; `.button-
cancel` stays for the Cancel on the panel, which genuinely navigates.

Then verified the way it should have been before shipping a zip: the real
binary, driven like a browser. A throwaway config (`127.0.0.1:2525`, a route
pointed at a dead port so nothing ever leaves the queue, dashboard on
`127.0.0.1:8025`), messages submitted over SMTP with `smtplib`, and every
action driven by parsing the served HTML and posting the form back verbatim.
Delete-selected (2 of 5), requeue-selected, and the whole-queue button's
GET → panel → POST chain all answered 303 with the expected counts and the
queue ended empty; unconfirmed `scope=all` 400, a requeue token on the delete
endpoint 403, a traversal-shaped id 400. The first run of this, against the
binary built before the button change, reported `button present: False` — the
same thing the operator saw, from the same cause.
The reported bug was reproduced the operator's way too: submit three
messages, `rm` the spool files by hand, restart the service. The three rows
survive the restart, all three are marked *no spool copy*, requeue answers
`missing=3`, and the whole-queue delete answers `cleared=3` and empties the
view — with `queue entry cleared for a message with no spool copy` in the
log three times. Before this session that state was unclearable.

**Same session, handover artefact.** Asked for a zip, then for "das wo die
msi und die exe haben". The MSI cannot be produced on this machine at all:
`smtprelayd.wxs` links `WixUIExtension` (stock ExitDialog/UserExit/
FatalError plus `WixUI_ErrorProgressText`) and the bootstrapper needs WiX
Burn, so candle/light on Windows are the only route — `wixl` from msitools
does not implement the UI extension, and a hand-rolled substitute would be a
*different* installer from the one verified on hardware, which is not
something to hand over as "the MSI". So the zip
(`dist/smtprelayd-v0.5.4-test.zip`, not in git, `dist/` is ignored) carries
the three built binaries plus new `scripts/build-msi.ps1`, which reproduces
the release workflow's candle/light invocations byte for byte and produces
both the MSI and the setup.exe from an unpacked zip with no Go toolchain and
no checkout. The script is transcribed from known-good CI steps but **has
never been executed** — there is no Windows machine here — so its first run
is also its test. Binaries are built as `v0.5.4-test` and the MSI's
ProductVersion is `0.5.4`, deliberately above the installed 0.5.3: the wxs
declares `MajorUpgrade` without `AllowSameVersionUpgrades`, so a same-version
MSI installs a *second* product under the same UpgradeCode and produces the
duplicate service registration an earlier session already had to fix. Noted
in the zip's own README, along with the stale
`docs/guides/img/dashboard-queue.png`, which still shows the queue page
without the bulk form.

Not done, deliberately: the JSON API got the reconciliation but no bulk
endpoints — the ask was the dashboard, and a bulk API surface is its own
contract and its own docs. Also not done and worth a future session:
`Spool.recover` still drops a half-written pair silently, with no log line
and no way to tell the store about it, which is one of the ways a stale row
appears in the first place. Reconciling at startup, or at least logging what
recovery dropped, would attack the cause rather than the symptom; it needs a
logger in `spool.Open` (signature change, ripples into every caller), so it
was left out rather than half-done.

**Previous session**: 2026-08-24 (thirtieth session) — New feature, real phase-5
adjacent work (not a numbered phase item, added on direct request). Started
as "ein auto test wäre noch gut, dass täglich ein testmail geschickt wird."
Researched before designing: `smtprelayd selftest` is an active local
open-relay check only, never sends real mail anywhere, so it was the wrong
starting point; `internal/bounce`'s digest notifier turned out to be the
right template both for scheduling (a `time.Ticker` goroutine started from
`serve()`, stopped on context cancellation — an established internal pattern,
not something needing OS-level cron/Task Scheduler) and for composing and
enqueueing a message directly into the spool, bypassing the listener
entirely (`Notifier.send`, `internal/bounce/notifier.go`). Three scope
questions asked and answered before writing code, since this is both a new
feature (`CLAUDE.md`: "no speculative features") and a config schema change
(same file: "needs confirmation first"): actively warn on failure rather
than a canary-only "you'll notice it's missing" design; scheduling built
into the daemon rather than a new CLI subcommand plus external timers; the
success recipient configurable separately from `[bounce].notify`.

New `internal/canary` package (`Runner.Run`/`Runner.send`, closely mirroring
`bounce.Notifier`'s shape) composes and enqueues one message every
`[canary].interval_minutes` through `[canary].route` to `[canary].recipient`.
The one deliberate divergence from the bounce-notifier template, and the
reason a straight copy would not have worked: `spool.Envelope.Notification`
bundles two behaviours together in `internal/delivery` — it keeps a
message's outcome out of its route's own metrics, *and* it stops
`fail()` from calling `bounce.Notifier.RecordFail` (loop prevention for the
notifier's own mail). A canary needs the first but explicitly not the
second: a failing canary's entire purpose is to be reported through the
existing bounce digest, not to loop-guard against reporting itself. New
`spool.Envelope.Canary bool`, a second, independent flag, lets
`internal/delivery/delivery.go`'s `attempt()` route a canary's
delivered/permanent-failure/expired/deferred outcome to new dedicated
metrics while leaving `fail()`'s `RecordFail` gate checking `Notification`
alone — so a canary rides the existing alerting path unchanged, exactly as
asked, and required no changes to `internal/bounce` at all.

**Same session, "vergiss das nicht in den metrics"**: read `internal/metrics`
before designing this: `NotificationFailure()` was already the precedent for
"diagnostic traffic must not muddy a route's own delivered/bounced/deferred/
auth-failure counters," so `CanaryDelivered()` (records only a timestamp —
the useful signal is staleness, not a count) and `CanaryFailure()` (a plain
counter, covering permanent, expired and deferred alike, again mirroring how
`NotificationFailure` does not distinguish the three) were added the same
way and wired into `attempt()`'s three-way switch. Exposed on `/metrics` as
`smtprelayd_canary_last_delivery_time` (gauge, absent until the first
success) and `smtprelayd_canary_failures_total` (counter), both unlabeled
like the existing api/notification failure counters, since there is only
ever one canary. `docs/guides/CHECKMK.md`'s metrics table and
`docs/guides/CONFIGURATION.md` section 7 (renamed "Bounce notifications and
the canary probe," bounce and canary now `###` subsections rather than
inserting a new numbered `##` section and renumbering everything after it)
both updated. Not done, flagged as a natural follow-up rather than
in-scope for what was asked: extending the bundled Checkmk local-check
scripts (`contrib/checkmk/smtprelayd_metrics` / `.ps1`) to alert on the two
new metrics — the metrics themselves were the ask, the bundled check script
is a separate, non-trivial AWK/PowerShell change on top.

Config: new `[canary]` (`sender`, `recipient`, `route`, `interval_minutes`),
"enabled" precisely when `recipient` is non-empty — the same no-separate-
boolean idiom `[bounce].notify` already uses. Validation
(`internal/config/validate.go`) mirrors `[bounce]`'s required-together-when-
enabled block closely, plus one cross-section rule with no `[bounce]`
precedent to copy: `canary.recipient` set with `bounce.notify` empty is
rejected at load time, fail-closed, since a canary with nowhere to report a
failure to would silently not do the one thing it exists for.
`configs/smtprelayd.example.toml` documents it, disabled by default
(`recipient = ""`).

**Verified for real this session, not just reasoned about** — a working Go
toolchain was found already installed in this environment
(`~/sdk/go1.25.13`, from an earlier session's install, not on `PATH`), the
first session able to run the full `CLAUDE.md` definition of done against
Go code rather than deferring it to CI: `gofmt -l .` clean, `go vet ./...`
clean, `go build ./...` and `GOOS=windows GOARCH=amd64 go build ./...` both
clean, `go test ./...` and `go test -race ./...` green across every
package including the new `internal/canary` tests and the new
`internal/delivery`/`internal/metrics`/`internal/config` cases,
`scripts/check-banned-imports.sh` clean for all three targets, `govulncheck`
v1.6.0 (no vulnerabilities) and `gosec` v2.28.0 `-severity=medium` (0 issues
across 55 files) both run successfully for the first time in this
environment rather than left as the recurring "not installed here" gap. One
self-caught test bug on the way, not a production one: the first version of
`TestCanaryDeliveredSetsLastDeliveryTimeNotRouteDelivered` checked for the
bare metric name as a substring, which also matches the `# HELP`/`# TYPE`
comment lines for an unlabeled metric — fixed to check for an actual value
line before it was ever reported passing.

Not yet verified: real mail actually arriving on schedule and a real
permanent failure actually surfacing through the bounce digest — both
require a live route and a live tenant, so this is compile/vet/test/security
clean, not yet hardware/production confirmed.
**Same session, immediate follow-up**: "kann ich auch mehrere canary
hinterlegen um mehrere routes zu testen?" — the singleton design above did
not support it; asked directly whether to restructure before touching
anything already built and verified the same session ("Ja, umbauen"), since
nothing had been committed yet and the schema was cheap to change while
still true. `[canary]` (one table) became `[[canary]]` (zero or more,
mirroring `[[route]]`/`[[client]]`'s own list-of-tables idiom exactly, which
this codebase already uses everywhere else for "N independently configured
things"), each entry gaining a required `Name`. The one design question this
raised with no direct `[bounce]` precedent to copy: `Name` must be unique
both among canaries and against every configured client name — `Envelope.
Client` already doubles as the canary's own bounce-digest grouping key and
now also its metrics label, and a collision with a real client's name would
silently reroute that canary's failures to the client's own `[client.bounce]
notify` override instead of the global list, which is confusing enough to
reject at load time rather than document as a gotcha.
`internal/metrics.Registry`'s two canary fields moved from a bare
counter/timestamp to `map[string]uint64`/`map[string]time.Time` keyed by
name, seeded with zero values for every configured canary the same way
routes already are, and `smtprelayd_canary_failures_total`/
`smtprelayd_canary_last_delivery_time` gained a `name` label in the
exposition. `internal/delivery.Manager` now constructs one `canary.Runner`
per `[[canary]]` entry itself (mirroring how it already constructs
`bounce.Notifier`, not something `main.go` did directly before this), so
`main.go` only loops over `dm.Canaries()` starting one goroutine each — a
smaller, more consistent `main.go` than the version that shipped an hour
earlier. Caught while wiring the metrics snapshot back up, before it was
ever exercised under `-race`: the two new per-name maps were first read
straight off the Registry inside `text()`'s lock-free section, aliasing the
live map instead of copying it — exactly the bug `cloneCounts` already
exists in this file to prevent for the route-keyed maps, just not yet
applied to the two new ones. Fixed the same way, before any test ran, not
found by one.
Re-verified in full after the restructure, same toolchain and same checks as
above: `gofmt -l .` clean, `go vet ./...` clean, `go build ./...` and
`GOOS=windows GOARCH=amd64 go build ./...` and `GOOS=linux GOARCH=arm64 go
build ./...` all clean, `go test ./...` and `go test -race ./...` green
(new tests added: two canaries enqueue under distinct names and route to
their own configured routes; per-name canary metrics stay independent;
config rejects a missing name, a duplicate name, and a name colliding with
a client), `scripts/check-banned-imports.sh` clean for all three targets,
`govulncheck` v1.6.0 clean, `gosec` v2.28.0 `-severity=medium` clean (0
issues, 55 files). `configs/smtprelayd.example.toml`, `docs/guides/
CONFIGURATION.md` section 7 and `docs/guides/CHECKMK.md`'s metrics table all
updated for the `[[canary]]`/`name=` shape; `MEMORY.md` section 8's canary
subsection likewise.
**Previous session**: 2026-08-21 (twenty-ninth session) — MSI installer UI
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
**Same session, second real `light.exe` failure from a second pasted CI
log**: the Binary/"do nothing button" errors were gone (confirming
`WixUI_Common` and the `Finish` `Publish` fix above both landed correctly),
but three ICE31 errors remained — `FatalError.Title`, `UserExit.Title` and
`ExitDialog.Title` all "uses undefined TextStyle WixUI_Font_Bigger,"
meaning `WixUI_Common` does not, in fact, supply that TextStyle despite
supplying the `Binary` entries the same three dialogs also need. Rather than
guess a third fragment reference against another CI round-trip, declared
`<TextStyle Id="WixUI_Font_Bigger" FaceName="Tahoma" Size="12" />` directly
in `smtprelayd.wxs`'s own `<UI>` block — the exact face/size only affects
how big the dialog title text renders, nothing functional, and light.exe
would have reported a duplicate-symbol error instead of "undefined" if this
collided with something already in the linked graph. `xmllint --noout`
clean; still not build-verified — the next CI run is the real check, and at
this point should be the last one needed for the Finish-dialog change
specifically unless another undefined symbol turns up.
**Same session, confirmed on hardware**: `light.exe` links clean and the MSI
now shows a Finish dialog at the end of install ("dialog finish geht") —
the Finish-dialog checklist item is closed. The `WixUI_Font_Bigger` guess
(Tahoma 12pt, declared locally rather than sourced from a WiX fragment) is
therefore also confirmed adequate, cosmetically. Uninstall's Finish dialog
specifically, and the still-open `MSI_LUA`/`CLIENTUILEVEL` bootstrapper
work, remain unstarted/unverified — see the checklist.
**Same session, confirmed as expected, not a new bug**: "beim deinstall ist
noch kein dialog" after the Finish-dialog fix above — exactly the
`MSI_LUA`/`CLIENTUILEVEL` suppression already diagnosed and tracked, not a
regression from the dialog work. Operator confirmed "Bootstrapper bauen" for
this earlier in the session; started the same session, on request
("weitermachen"): new `packaging/windows/smtprelayd-bundle.wxs`, a WiX Burn
bundle chaining the existing, unchanged `smtprelayd.wxs` MSI as a single
`MsiPackage`. New UpgradeCode `2ab0d134-9ff4-49c4-bf86-1c63c7f27540`
(bundle-level, independent of the MSI's own `64270ec1-...` — Burn's own
bundle-upgrade tracking is a separate mechanism from the wrapped product's
`MajorUpgrade` element, which is untouched and still handles the MSI's own
upgrade path). `DisplayInternalUI="yes"` on the `MsiPackage` deliberately:
lets the already-verified MSI UI (`PurgeDataDlg`, `ExitDialog`) render as-is
rather than being hidden behind Burn's own themed screens — the accepted
tradeoff is a brief bundle-level license screen
(`WixStandardBootstrapperApplication.HyperlinkLicense`, pointed at the
repository's own `LICENSE` file on GitHub rather than embedding an RTF)
shown first, then the MSI's own UI underneath, i.e. two short screens back
to back instead of one. `CLEANDATA` is forwarded from a bundle-level
`bal:Overridable` `Variable` into the wrapped MSI's property table via
`<MsiProperty>`, so the documented scripted-purge workflow keeps working,
now against the bundle: `smtprelayd-<version>-amd64-setup.exe /uninstall
/quiet CLEANDATA=1`. `release.yml`'s `package-windows` job gained a second
candle.exe/light.exe pair (`-ext WixBalExtension`) right after the existing
MSI build, producing `dist\smtprelayd-<version>-amd64-setup.exe` — no
`insignia.exe`/`burn.exe` detach-reattach needed, since this project signs
nothing (that step exists only to Authenticode-sign the Burn engine stub
separately from the outer bundle exe). The new file already hit, and had
fixed before ever running it through CI, the exact double-hyphen-in-an-
XML-comment mistake `MEMORY.md` tracks as a recurring one in this project
(caught by `xmllint --noout`, four instances, all in prose describing the
`MSI_LUA` background) — the same category of self-caught mistake as the
twentieth/twenty-second sessions' WiX comments, just a new file this time.
**Explicitly higher-risk than the Finish-dialog change**: Burn/`Bundle`
syntax (`Variable`/`bal:Overridable`, `MsiProperty` forwarding,
`WixStandardBootstrapperApplication` attributes) is less familiar terrain
than plain `Product`/`UI` authoring, which itself still needed two rounds of
real `light.exe` errors to get right this same session — this is reasoned
from documentation, not from having built a Burn bundle against a working
toolchain, so more than one CI round-trip pasted back here should be
expected, same as the dialog work. Not yet attempted: an actual CI run, an
install via the new bootstrapper, an Apps & Features uninstall through it
(the actual scenario this whole bundle exists to fix), and whether the
existing hardware-verified MSI upgrade/uninstall cycle still behaves once
wrapped. `docs/` not yet updated to mention the new `-setup.exe` artifact or
which of the two Windows artifacts an operator should use when — deferred
until the bundle itself is confirmed working.
**Same session, first real bundle test, two findings from a paired
Burn/MSI log ("dialog kommt. uninstaller stop den dienst nicht. auswahl für
clear data nicht vorhanden")**: one confirms and corrects the design above,
one is unrelated and pre-existing.

First: `DisplayInternalUI="yes"` does not do what its own comment claimed.
The chained MSI's own verbose log showed `CLIENTUILEVEL=3` (Basic) on the
uninstall Burn drove — confirmed by the property dump, not inferred — and
Basic suppresses every package-authored dialog, `PurgeDataDlg` and the new
`ExitDialog`/`UserExit`/`FatalError` alike, regardless of
`DisplayInternalUI`. Burn simply never grants a chained `MsiPackage` Full
UI. Fetched the real WiX v3 source rather than guess a third time
(`wixtoolset/wix3` on GitHub, `develop` branch, `src/ext/BalExtension/
wixstdba/Resources/HyperlinkTheme.xml` and `WixStandardBootstrapperApplication.cpp`)
and confirmed the actual, documented mechanism instead:
`WixStandardBootstrapperApplication.cpp` automatically binds any named
`<Checkbox Name="X">` control on the stock theme's Install/Options/Modify
pages to a same-named Bundle `Variable`, read via `BalGetNumericVariable`
when the page loads and written back via `SetVariableNumeric` when the page
is left (e.g. clicking "Uninstall"). New `packaging/windows/
smtprelayd-bundle-theme.xml`, a copy of the fetched stock `HyperlinkTheme.xml`
with one addition: a `CLEANDATA` checkbox on the `Modify` page specifically
— the page WixStdBA shows when Burn detects the bundle is already
installed, exactly the case for Apps & Features' "Uninstall." `smtprelayd-
bundle.wxs`'s `CLEANDATA` `Variable` changed from `Type="string"` to
`Type="numeric"` to match what the binding reads/writes. `release.yml`
passes the new theme file's path as a `-dThemeFile=` candle variable,
mirroring the existing `-dMsiPath=` pattern rather than relying on
`ThemeFile`'s own bare-relative-path resolution. Important operational
consequence documented in both files' comments: this checkbox is only ever
reached through the *interactive* Modify page — an explicit `/uninstall` on
the bundle's command line (exactly the test command used to capture the
diagnostic logs) skips straight to execution and never shows it, so
`CLEANDATA=1` on the command line remains the only scripted path, unchanged.
**Confirmed on hardware the same session, first try, no further `light.exe`
round-trip needed**: "unisnstall funktioniert sauber auch das auswahlfeld
kommt für das programmdata beide fälle funktionieren" — the Modify page's
`CLEANDATA` checkbox renders through the bundle on an interactive Apps &
Features uninstall, and both the checked and unchecked cases behave
correctly. The three-fragment WiX-source fetch (`HyperlinkTheme.xml`,
`WixStandardBootstrapperApplication.cpp`, the customize doc) paid off:
unlike the two-round Product/UI dialog fix and the Bundle/Chain wiring
earlier this session, working from the real upstream source instead of
memory got this one right on the first pass.

Second, unrelated to the above and unrelated to the bundle at all: asked
"Zum Service" directly, the operator answered "ich habe den dienst
gestopped" — they had to stop the Windows service manually after the
uninstall, it did not stop on its own. The paired MSI verbose log had
already shown `StopServiceCA` "returned actual error code 1 but will be
translated to success due to continue marking," previously read (in an
earlier session, on the raw-MSI path) as the benign "service already
stopped" case; the operator's answer now rules that reading out for this
run. Delegated to a background investigation (not yet acted on): `cmd/
smtprelayd/main.go`'s `stop` dispatch surfaces `controlService`'s error only
to stderr and `os.Exit(1)` — invisible to msiexec, which is exactly why
`Return="ignore"` on `StopServiceCA` (`packaging/windows/smtprelayd.wxs`)
has silently tolerated this. `controlService`
(`cmd/smtprelayd/service_windows.go`) is a thin, three-line wrapper calling
`kardianos/service`'s `Control(s, "stop")` with no pre-check of current
service state and no logging of the underlying Win32 error. The vendored
`kardianos/service` v1.3.0's own `stopWait` was independently found to have
a real bug of its own (a `break` inside a `select` inside a `for` only exits
the `select`, not the polling loop, so its 20s timeout does not actually
bound the wait) — but that produces a *hang*, not a fast exit code 1, so it
does not explain what was observed here; the more likely cause is `Control(
svc.Stop)` itself returning a Win32 error immediately (`Impersonate="no"`
rules out access-denied, SYSTEM has full rights regardless of the requested
access mask), but the exact error cannot be confirmed since it never
reaches any log. No test exists today for `controlService`/the stop path at
all. Cross-referencing this file's own history: every previous
"hardware-verified" Windows uninstall/upgrade claim only ever confirmed the
service running again *after* an upgrade, never a plain terminal uninstall
ending with the service actually stopped — this may be the first time that
specific path was ever exercised end to end, on any invocation (raw
`msiexec`, not just the bundle), which is why `smtprelayd.wxs`'s own header
comment asserting "StopServiceCA already stops the service deterministically"
turned out to be untested rather than false-but-known. Not yet fixed; needs
a decision on scope (Go code in a different area than this session's
packaging work, needs its own test coverage per `CLAUDE.md`'s definition of
done, and the exact Win32 failure is still unconfirmed) before touching it.
**Retested the same session, on the rebuilt bundle with the Modify-page
checkbox above**: "ja auch das passt" — the service stopped correctly this
time. No Go code changed between the two tests, only the WiX bundle/theme
files, so this is not a fix; most consistent with the suspected
`kardianos/service` `stopWait` bug being intermittent/timing-dependent
rather than a fast, reliably-reproducing failure — it simply did not
trigger on this run. **Closed by the operator regardless**: "service stop
passt auch ist erledigt" — not pursuing further. Recorded here precisely so
a future session does not mistake this for a code fix: no Go code changed,
the underlying `kardianos/service` v1.3.0 `stopWait` for-loop bug (the
timeout `break` only exits the `select`, not the loop) is still present and
unfixed in the vendored code, and the one clean retest does not rule out
the same intermittent failure recurring later. Revisit only if it
resurfaces.
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
- [x] MSI Finish/success dialog on install — added 2026-08-21 (twenty-ninth
      session), `WixUIExtension`'s stock `ExitDialog`/`UserExit`/`FatalError`
      referenced via `<UIRef Id="WixUI_Common" />` +
      `<UIRef Id="WixUI_ErrorProgressText" />`, a `WixUI_Font_Bigger`
      `TextStyle` declared locally (not supplied by either fragment,
      confirmed by two rounds of `light.exe` ICE17/ICE31 errors), an explicit
      `Finish`-button `Publish`, and three new `<Show>` entries in
      `InstallUISequence` (`smtprelayd.wxs`). **Confirmed on hardware same
      session** ("dialog finish geht") — `light.exe` links clean and a
      Finish screen appears at the end of install. Uninstall's Finish
      dialog specifically not yet separately confirmed (see the `MSI_LUA`
      item below — uninstall via Apps & Features may still suppress it
      entirely until the bootstrapper fix lands).
- [x] WiX Burn bootstrapper wrapping the `.msi` — scoped 2026-08-21 (twenty-
      ninth session) to fix the `MSI_LUA`/`CLIENTUILEVEL` UI suppression
      documented above: requests elevation once before `msiexec` runs, so
      Apps & Features uninstall (the operator's real trigger) is no longer
      silently downgraded to no UI. New `packaging/windows/
      smtprelayd-bundle.wxs` (`MsiPackage` chaining the existing, unchanged
      MSI) plus `packaging/windows/smtprelayd-bundle-theme.xml` (a fetched
      copy of WiX's stock `HyperlinkTheme.xml` with a `CLEANDATA` checkbox
      added to the Modify page — `DisplayInternalUI="yes"` alone turned out
      not to surface the MSI's own dialogs, since Burn only ever grants a
      chained package Basic UI; the purge-data question had to move into
      the bundle's own UI instead). `release.yml` builds it alongside the
      `.msi` as `dist\smtprelayd-<version>-amd64-setup.exe` (both artifacts
      ship; the raw `.msi` stays for scripted/enterprise deployment). No
      `burn.exe`/`insignia.exe` detach-reattach needed — this project signs
      nothing. **Confirmed on hardware same session**: install, and an
      interactive Apps & Features uninstall showing the Modify page's
      `CLEANDATA` checkbox, both checked and unchecked, "beide fälle
      funktionieren." Not yet confirmed: the existing hardware-verified MSI
      upgrade cycle surviving the wrap, and SmartScreen friction on the new
      unsigned `.exe` (flagged as a possible regression versus today's
      unsigned `.msi`, not yet observed either way).
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

### Deferred findings from the seventh review (2026-09-17)

Found by the review agents while checking the five fixes above. All three are
**pre-existing**, none was introduced by that change, and all three were left
alone deliberately to keep it behaviour-preserving. Recorded so they are not
rediscovered from scratch a fourth time.

- **`internal/listener/session.go`, `journalAccepted` re-parses the header
  block 3–4 times per route group.** `rewrite.HeaderValue` and
  `rewrite.HeaderCount` each call `parseBlock`, which allocates per header
  line; with the default `limits.max_headers = 200` that is up to ~400
  allocations per parse, taken once for Message-ID, once for Content-Type,
  once for the count and once more for the subject when
  `history.retain_subjects` is on (the default). All four results are
  invariant across groups. The fix is one helper in `internal/rewrite` that
  parses once and returns all four, called once before the loop — but that is
  a new exported API in another package and wants its own sign-off.
- **`internal/spool/spool.go`, `Claim` is an O(N) walk plus a slice allocation
  plus an O(N·logN) sort, under `s.mu`, called in a drain loop.** Draining a
  backlog of N messages therefore costs N walks and N sorts. It wants a single
  oldest-due message, so a one-pass minimum scan replaces both the slice and
  the sort. This is the mutex `Commit`'s `overQuota` now also takes, so an
  inbound burst during a backlog drain queues behind it.
- **`internal/store/store.go`, `retentionCleanup` runs a full-table `DELETE`
  while holding `s.mu`, from inside `RecordAttempt`.** Once an hour, one
  delivery worker's attempt write blocks every other store writer for the
  duration. It belongs on the existing ticker in `internal/delivery`, with
  `s.mu` held only around the `lastCleanup` timestamp.

Also noted and *not* acted on: `routes()` is still 158 lines with four-deep
nesting after the `Validate` split — the one section the split did not
actually break up. Splitting it further into `routeTLS`/`routeAuth`/
`routeNetworks` is a new finding beyond what was approved.


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
| 2026-09-14 | A delete of a message whose spool copy is already gone marks the history row removed instead of answering 404, when and only when its derived status is still queued or deferred | The queue view is built from history and the spool is what holds the mail; the two disagree after a recovery sweep, a manual file deletion or a crash between the unlink and the attempt row. The 404 left such a row listed as queued forever with nothing able to clear it, which is the defect as reported. Restricting it to queued/deferred is what keeps a finished message's journal from being rewritten just because its files are (correctly) gone |
| 2026-09-14 | "All" in the queue's bulk actions means the history store's active set, not the spool's index | That set is what the operator is looking at when they click it, and it is the only one that includes a row with no spool copy — precisely the entry that needs clearing. Bounded by `store.FindMessages`'s own 1000-row ceiling, with the banner reporting that more remain, rather than looping until the queue is empty inside one request |
| 2026-09-14 | The bulk form carries two CSRF fields (`csrf_requeue`, `csrf_delete`) rather than one token covering both endpoints | The checkbox set has to be shared, so `formaction` picks the endpoint from one form; a single field named `csrf` would then have to validate for either action, retiring the per-action binding the single-message tokens already have. The queue ID is empty in both, because the message set is chosen after the page was rendered — the property being relied on, that an origin which never read the page cannot produce the MAC, is unchanged |
| 2026-09-14 | Deleting the whole queue is confirmed by a server-rendered interstitial (`/queue?confirm=delete-all`), not a `confirm()` dialog, and the handler refuses an unconfirmed `scope=all` delete outright | It is the one irreversible action on the page, and a link to a page holding the real form is refresh-safe, needs no script, and cannot be reached by a mis-click on a toolbar. Requeue-all is deliberately not confirmed: it destroys nothing |
| 2026-09-14 | The bulk outcome banner is rebuilt from integers in the redirect's query string | A POST that renders its own result page re-fires on reload, and server-side flash state would mean a session the dashboard does not have. Parsing counts rather than echoing text also means a crafted `/queue?done=...` link cannot put a sentence of someone else's choosing on the page |
| 2026-09-14 | `internal/web/static/queue.js` is accepted as the dashboard's first first-party script | A select-all box cannot be rendered server-side, and the ten-second htmx swap would otherwise discard a selection in progress — the same reason `/search`'s results table is not polled. An htmx trigger filter would have done it in one attribute but requires `unsafe-eval`; plain delegated DOM code keeps `script-src 'self'` exactly as it is |
| 2026-08-21 | `Server.accept`'s `wg.Add` and `Set.Close`'s `wg.Wait` are serialised through a `closeMu`/`closed` pair, not left to rely on the listener socket being closed first | `sync.WaitGroup` requires every `Add` with a positive delta on a counter that could be zero to happen before the matching `Wait`; closing the socket does not guarantee that ordering against a connection `Accept` had already returned. Found by `-race` in the new `Set`-level test the `Bind`/`Run` split needed, not something this session set out to fix — pre-existing in the previous combined `Serve`, simply never exercised by a test at that level before |
