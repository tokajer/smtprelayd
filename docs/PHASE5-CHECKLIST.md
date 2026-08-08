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

Package *contents* were verified locally with `dpkg-deb`/`rpm2cpio`; actual
installation on a live system was not.

- [ ] `dpkg -i smtprelayd_<version>_amd64.deb` on a real Debian/Ubuntu host
- [ ] `id smtprelayd` — system user/group exist
- [ ] `/etc/smtprelayd` is `0750 root:smtprelayd`, `/var/lib/smtprelayd` is
      `0700 smtprelayd:smtprelayd`
- [ ] `systemctl status smtprelayd` — unit loaded, inactive, not started
- [ ] Copy the example config, edit it, then:
      `smtprelayd -config /etc/smtprelayd/smtprelayd.toml check`
- [ ] `systemctl enable --now smtprelayd` — binds to port 25/587 without
      running as root (confirms `AmbientCapabilities=CAP_NET_BIND_SERVICE`
      actually works)
- [ ] `journalctl -u smtprelayd` shows the startup log line
- [ ] `systemctl stop smtprelayd`
- [ ] `dpkg -r smtprelayd` (remove, not purge) — service stopped and
      disabled, `/var/lib/smtprelayd` and its contents survive
- [ ] Repeat the same sequence with the `.rpm` on Fedora/RHEL/Alma
      (`rpm -i`/`dnf install`, `dnf remove`)
- [ ] Install version A, then upgrade in place to version B
      (`dpkg -i` the newer `.deb` / `rpm -U`) — running/stopped state survives

## Follow-up implementation work (next coding session, not manual testing)

- [ ] Windows ACL verification at startup (`golang.org/x/sys/windows`,
      deferred from phase 1, natural fit alongside the MSI's own ACL setup)
- [ ] A CI workflow that runs on every push/PR: `go vet`, `gofmt -l`,
      `go test -race`, and the banned-import check
      (`unsafe`, `os/exec`, `plugin`, cgo, ...) that CLAUDE.md requires but
      that doesn't exist as an enforced check anywhere yet
- [ ] Log rotation dependency decision (`lumberjack` vs. external `logrotate`
      / Windows equivalent)

## Unrelated, phase 3/4 (not packaging)

- [ ] End-to-end test against a real Microsoft 365 tenant (needs tenant,
      mailbox, sending domain — see "Open questions" in `PROGRESS.md`)
- [ ] Phase 4 — observability (dashboard, history store, metrics) not started
