# PROGRESS.md

Handover document. Update at the end of every working session.
Keep it short — this file is pasted into every new chat. Session logs,
closed defects and finished restructurings go to `docs/dev/HISTORY.md`.

## Current state

**All phases (0–5) are complete** as of 2026-09-29. The relay runs in the
live deployment: the Microsoft 365 route delivers with both `file:` and
`dpapi:` client secrets. Packaging is verified on hardware for the `.msi`,
the Burn `setup.exe`, `.rpm` and `.deb` (install, upgrade in every
combination, uninstall with and without purging the data directory).

**Last session**: 2026-09-29 — the last two field verifications of phase 5.
A Windows service start with a configured listener port already bound fails
visibly and logs the bind error instead of reporting running. The unsigned
`setup.exe` draws exactly the same SmartScreen prompt as the unsigned `.msi`.
`PROGRESS.md` was cut down; everything moved is in `docs/dev/HISTORY.md`.

**Nothing is open.** Every remaining item is a deferred feature the operator
chose not to pursue yet, each of which would be its own phase. The scoping
for each is in `docs/dev/HISTORY.md`; grep for the quoted term.

- Token login for the dashboard, which would allow it off loopback
  ("token login")
- Ingesting downstream bounces from the relay mailbox via Graph
  ("Mail.Read")
- Sovereign cloud authorities ("Sovereign cloud")
- A MIME nesting depth bound, relevant only once MIME is parsed
  ("MIME nesting")

## Open defects

None as of 2026-09-29. Closed defects and their reasoning are in
`docs/dev/HISTORY.md`.

## Phases

| Phase | Scope | State |
|---|---|---|
| 0 | Scaffolding | ✅ |
| 1 | Minimum viable relay | ✅ |
| 2 | Microsoft 365 (XOAUTH2) | ✅ |
| 3 | Client policy, sender rewriting, recipient routing | ✅ |
| 4 | Observability: history, metrics, dashboard, API, bounce digest | ✅ |
| 5 | Productionisation: packaging, service wrappers, CI, release | ✅ |

The ticked checklists, the answered open questions and the decision log are
in `docs/dev/HISTORY.md`. A new phase gets its checklist here.
