# Phase 5 checklist — packaging and service integration

Working checklist for the items left open after the 2026-08-08 packaging
session (see `PROGRESS.md` decision log for the reasoning behind each piece).
Check items off as they're verified; update `PROGRESS.md` once a whole
section is done, this file is not itself the handover document.

## Windows: manual install/uninstall/upgrade test

Only doable on a real Windows machine.

- [ ] Build `smtprelayd-<version>-amd64.msi` (from a `release.yml` run, or
      locally with `candle.exe`/`light.exe` per the comment at the top of
      `packaging/windows/smtprelayd.wxs`)
- [ ] Install requires an elevated prompt (UAC) — confirm a non-admin run is
      refused, not silently degraded
- [ ] `smtprelayd.exe` present under `C:\Program Files\SMTPRelayd\`
- [ ] `smtprelayd.toml.example` present under `C:\ProgramData\SMTPRelayd\`
- [ ] `icacls C:\ProgramData\SMTPRelayd` shows only Administrators and
      `NT SERVICE\smtprelayd`, no inherited entries from `C:\ProgramData`
- [ ] `sc.exe query smtprelayd` shows the service registered, start type
      Automatic, **not** running
- [ ] Services console: "Log On As" for the service is
      `NT SERVICE\smtprelayd`, not Local System
- [ ] Copy the example config to `smtprelayd.toml`, edit it, then:
      `smtprelayd.exe -config C:\ProgramData\SMTPRelayd\smtprelayd.toml check`
- [ ] `sc.exe start smtprelayd` — service reaches RUNNING
- [ ] A log line ("starting", version, config path) appears where configured
- [ ] `sc.exe stop smtprelayd` — service reaches STOPPED within a few seconds
- [ ] Install version B's MSI over a running version A (same `UpgradeCode`):
      no duplicate service, service registration and running/stopped state
      untouched by the upgrade, binary on disk replaced
- [ ] Uninstall: service no longer listed in `sc.exe query`, Program Files
      folder removed
- [ ] Uninstall with spool/history files present in `C:\ProgramData\SMTPRelayd`:
      that data survives (folder only removed if empty)

## Linux: manual install/uninstall/upgrade test

Package *contents* were verified locally with `dpkg-deb`/`rpm2cpio`. The
`.rpm` path was then run on a live Fedora host on 2026-08-11; the `.deb` path
still has not been installed anywhere. Ticked below only where there was
evidence, not where it was likely.

- [x] `rpm`/`dnf install` on a real Fedora host — 0.2.5-1 installed, `%post`
      ran, exit status clean
- [x] `id smtprelayd` — the service runs as a non-root uid (963 observed
      holding the listener), so the system user exists and is in use
- [x] `/etc/smtprelayd` is `0750 root:smtprelayd`, `/var/lib/smtprelayd` is
      `0700 smtprelayd:smtprelayd` — both observed on the live host after the
      upgrade (`drwxr-x--- root:smtprelayd` and `drwx------ smtprelayd:
      smtprelayd`). The log file inside it is `0600 smtprelayd:smtprelayd`
      although it was created on 2026-08-11 at 01:05 by a version that still
      wrote 0644, so the restrict-on-startup upgrade path works in the field
- [x] `systemctl status smtprelayd` — unit loaded, inactive, not started.
      Verified 2026-08-11 on a genuine first install, made testable again by
      the `dnf remove` earlier that day: `Loaded: loaded (…; disabled; preset:
      disabled)` and `Active: inactive (dead)`. The package registers the unit
      and neither starts nor enables it, which is the intended behaviour on a
      host that has no usable configuration yet.
      The reinstall also showed that a remove/install cycle keeps the data:
      `/var/lib/smtprelayd` still carries its original birth time
      (00:58:47 that morning), so it is the same directory with the same
      spool and history, not a freshly created one.
- [x] Copy the example config, edit it, then:
      `smtprelayd -config /etc/smtprelayd/smtprelayd.toml check`
- [x] `systemctl enable --now smtprelayd` — **binds port 25 as uid 963, not
      root**: `tcp 0 0 192.168.8.102:25 0.0.0.0:* LISTEN 963`. This is the
      item most likely to fail silently, and it confirms
      `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the packaged unit works.
- [x] The startup line appears — **in the log file, not the journal**, which
      is not what this item said. Confirmed from both sides on the live host:
      `journalctl -u smtprelayd` carries only systemd's own `Started …`, while
      `/var/lib/smtprelayd/smtprelayd.log` has
      `{"msg":"starting","version":"v0.2.6",…}`. The packaged unit does not
      pass `-console`, and `logging.New` writes to stderr only when it is set
      or when no log file is configured. `MEMORY.md` section 10 claims Linux
      logs "to journald plus file", so either the unit should pass `-console`
      or that sentence is wrong — open decision, 2026-08-11
- [x] `systemctl stop smtprelayd`
- [x] `dnf remove` (remove, not purge) — verified 2026-08-11. The binary,
      the unit and the package are gone (`systemctl is-enabled` reports
      `not-found`, no process left), while `/var/lib/smtprelayd` survives as
      `0700 smtprelayd:smtprelayd` and `/etc/smtprelayd` as `0750
      root:smtprelayd`. Both are package-owned directories, and rpm removes an
      owned directory only when it is empty — so the fact that they survived
      *is* the evidence that the spool, the history database and the
      operator's own `smtprelayd.toml` are still in them. The system user and
      group are deliberately retained, so nothing is left owned by an orphaned
      uid. `dpkg -r` still untested.
- [ ] `dpkg -i smtprelayd_<version>_amd64.deb` on a real Debian/Ubuntu host,
      whole sequence above
- [x] Upgrade in place, `rpm -U`: 0.2.0-1 → 0.2.5-1 replaced the old package
      and ran `%post` without error
- [x] …and the running service is restarted into the new binary. Verified on
      a real `rpm -U` 0.2.5 → 0.2.6 of a *running* service on 2026-08-11: the
      scriptlet printed `smtprelayd upgraded and restarted.`, the RPM install
      time (22:24:43) matches the journal's
      `Stopping … Stopped … Starting … Started` pair, and the process was up
      again one second later. Before the 2026-08-11 fix nothing restarted the
      service and the replaced binary kept running

## Follow-up implementation work (next coding session, not manual testing)

All done; kept for the record. Ticked 2026-08-11 after checking each against
the tree rather than against the session notes.

- [x] Windows ACL verification at startup — `config.CheckDataDirACL`
      (`internal/config/trust_windows.go`) refuses to start on a DACL that
      still inherits from `%ProgramData%`. The installer side of the same
      contract is `config.SecureDataDir` / `smtprelayd secure-datadir`; the
      MSI has not been rebuilt with it yet, which is the open item in the
      Windows section above, not here
- [x] A CI workflow that runs on every push/PR — `.github/workflows/ci.yml`:
      gofmt, `go vet`, `go test -race`, `govulncheck`, plus a cross-compile
      job. The banned-import check exists in two halves, both wired in:
      `internal/buildpolicy` (AST over first-party source) and
      `scripts/check-banned-imports.sh` (`go list -deps` over the full graph,
      per target)
- [x] Log rotation dependency decision — `lumberjack`, in-process. Rotation
      is disabled and the log simply appends when `max_size_mb` is 0

## Unrelated, phase 3/4 (not packaging)

- [ ] End-to-end test against a real Microsoft 365 tenant (needs tenant,
      mailbox, sending domain — see "Open questions" in `PROGRESS.md`)
- [x] Phase 4 — observability: complete, all five sub-phases. `internal/store`
      (history and per-message metadata journal), `internal/metrics`,
      `internal/web`, `internal/api`, `internal/bounce`. Only the live-tenant
      run above is still missing, not the code
