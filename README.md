# smtprelayd — Open Source SMTP Relay for Windows & Linux

Accepts mail from printers, ERP systems and monitoring on the local network and
forwards it to a smarthost — primarily Microsoft 365 using OAuth2 / XOAUTH2.
Runs as a Windows service or a systemd unit from a single static binary, with
no runtime dependencies and no cgo.

## Features

- SMTP on port 25, submission on 587, implicit TLS (SMTPS) on 465
- Durable on-disk queue with crash recovery and exponential retry
- Per-client policy matched by CIDR: sender rewriting, rate limits, size limits
- Microsoft 365 authentication via OAuth2 client credentials, no stored password
- Routing per recipient domain or source network across multiple smarthosts,
  splitting a message whose recipients belong to different routes
- Structured JSON logs, searchable SQLite history, web dashboard
- Prometheus-format metrics endpoint for Checkmk

## Status

Phase 3 is implemented: mail from an allowlisted client reaches a smarthost
over TLS with SASL PLAIN, LOGIN or XOAUTH2, Microsoft 365 tokens are acquired
through the OAuth2 client credentials flow, and senders are rewritten and
recipients routed per message. The dashboard, the REST API and the searchable
history are not implemented yet.

Nothing has been compiled or run against a live smarthost or tenant: phases 1
to 3 were all written without a Go toolchain available. See `PROGRESS.md`.

## Build

```sh
go mod tidy         # once, to write go.sum
make build          # host platform
make build-all      # linux/amd64, linux/arm64, windows/amd64
make test lint
```

No cgo, no Node.js. `GOOS=windows go build ./cmd/smtprelayd` is all a Windows
build takes.

## Run

```sh
smtprelayd -config /etc/smtprelayd/smtprelayd.toml check      # validate and exit
smtprelayd -config /etc/smtprelayd/smtprelayd.toml run        # foreground
smtprelayd -config /etc/smtprelayd/smtprelayd.toml selftest   # open relay probe
```

`check` refuses to pass a configuration that would relay for an unmatched
source. `selftest` connects to the running listeners and fails loudly if a
relay attempt from an unlisted address succeeds. Run it after every
configuration change.

## Releases

Tagging `v*` builds reproducible `linux/amd64`, `linux/arm64` and
`windows/amd64` binaries with `-trimpath` and `CGO_ENABLED=0`, publishes a
CycloneDX SBOM and `SHA256SUMS`, and attaches build provenance:

```sh
sha256sum -c SHA256SUMS
gh attestation verify smtprelayd-linux-amd64-v1.0.0.tar.gz --repo <owner>/smtprelayd
```

## Configuration

Copy `configs/smtprelayd.example.toml` and adapt it. Secrets are read from
environment variables using `${VAR}` expansion — do not commit them.

## Documentation

- `MEMORY.md` — architecture decisions and rationale
- `PROGRESS.md` — phase tracking
- `docs/MS365-AUTH.md` — Entra ID and Exchange Online setup
- `docs/SECURITY.md` — threat model, hardening requirements, deployment checklist
- `docs/EXPLOIT-SURFACE.md` — privilege escalation and code-level attack surface
- `docs/API.md` — HTTP API contract
- `docs/SESSION-BOOTSTRAP.md` — how to start an assisted session cheaply

## Licence

GNU General Public License, version 3 or later. Copyright (C) 2026 Tokajer.

smtprelayd is free software: you can redistribute it and modify it under the
terms of the GPL as published by the Free Software Foundation, either version 3
of the licence or, at your option, any later version. It is distributed without
any warranty, without even the implied warranty of merchantability or fitness
for a particular purpose. See the licence for details.

The licence text is not checked in as a copy. Run `make license` once, or
fetch <https://www.gnu.org/licenses/gpl-3.0.txt> into `LICENSE`, so that the
file is byte-exact rather than transcribed.

The only third-party dependency, `github.com/BurntSushi/toml`, is MIT licensed
and compatible with the GPL.

## If you like my work you can

[![Buy me a coffee](https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20coffee&emoji=☕&slug=tokajer&button_colour=1e4c7a&font_colour=ffffff&font_family=Inter&outline_colour=ffffff&coffee_colour=FFDD00)](https://www.buymeacoffee.com/tokajer)