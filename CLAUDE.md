# CLAUDE.md

Instructions for any AI assistant working on this repository.
Read this file, `MEMORY.md` and `PROGRESS.md` first. Do not read the whole tree.

## Project in one sentence

A cross-platform (Linux + Windows) SMTP relay service that accepts mail from
internal devices (printers, ERP, monitoring) and forwards it to smarthosts,
primarily Microsoft 365 via OAuth2 / XOAUTH2.

## Working agreement

1. **Language**: all code, comments, identifiers, log messages, commit messages
   and documentation in **English**. Chat replies may be in German.
2. **Output only what changed.** Never reprint an unchanged file. For edits,
   show the diff or the single changed function, not the surrounding file.
3. **One phase at a time.** Phases are defined in `PROGRESS.md`. Do not start
   work on a later phase without being asked.
4. **Ask before restructuring.** Renaming packages, changing the config schema
   or swapping a dependency needs confirmation first.
5. **No speculative features.** If it is not in `MEMORY.md` scope, it is out of
   scope. Say so instead of building it.
6. **Commit messages**: Conventional Commits. Subject `type(scope): summary`,
   blank line, body explaining *why* (not what), wrapped at 72 characters.
   Include measured effects where available.

## Token discipline

- Update `PROGRESS.md` at the end of each working session. It is the handover
  document for the next chat.
- Start a new chat per phase. Paste `MEMORY.md` + `PROGRESS.md` to bootstrap.
- Do not summarise previous conversation content back to the user.
- Prefer editing existing files over generating new ones.
- Keep generated code free of tutorial comments. Comment *why*, never *what*.

## Security

`docs/SECURITY.md` and `docs/EXPLOIT-SURFACE.md` are binding. Read them before
working on the listener, the rewriting code, the configuration loader, the
spool, the installer or the API. Do not weaken anything in
it without an explicit decision recorded in `MEMORY.md`. In particular: never
introduce an option to disable TLS certificate verification, never allow an
unmatched source to relay, and never log or echo a secret.

**Banned outright**, enforced by an import test in CI: `unsafe`, `os/exec`,
`plugin`, cgo, `template.HTML` / `template.JS` / `template.URL` conversions,
SQL built by concatenation, and any path built by joining an unvalidated
string. Queue IDs are a validated named type, never a raw string.

## Constraints that must not be violated

- **Pure Go only.** No cgo. Windows cross-compilation must stay trivial
  (`GOOS=windows go build`). This is why `modernc.org/sqlite` is used and not
  `mattn/go-sqlite3`.
- **No Node.js build step.** The dashboard is server-rendered Go templates plus
  htmx, embedded with `embed.FS`.
- **Single binary.** No external runtime, no external resolver, no OpenSSL.
- **Open source dependencies only**, preferably EU-hosted or vendor-neutral.

## Definition of done for a phase

- Code compiles for `linux/amd64` and `windows/amd64`.
- `go vet ./...` clean, `gofmt` clean.
- Unit tests for the logic that is not I/O bound, including negative tests for
  the security-relevant paths (unmatched source, CRLF in addresses, oversized
  input, expired or wrong-scope token).
- `govulncheck` and `gosec` clean.
- `PROGRESS.md` updated, `docs/` updated if behaviour changed.
- A Conventional Commit message is supplied with the change.
