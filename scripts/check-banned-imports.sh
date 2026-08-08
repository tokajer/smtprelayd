#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Tokajer
#
# Enforces the dependency-graph half of the import ban in CLAUDE.md and
# docs/SECURITY.md. The other half -- this module's own source -- is enforced
# by internal/buildpolicy, which also runs under `make test`.
#
# This exists because a transitive import can reintroduce a banned package on
# one platform only. github.com/kardianos/service is the live example: its
# Linux backend shells out to systemctl via os/exec, and only the _windows.go
# build constraint keeps that out of the Linux graph. A ban that is verified by
# hand once is a ban that regresses on the next dependency bump.
#
# unsafe is deliberately not checked here: the standard library uses it
# everywhere, so it is only meaningful as a rule about first-party code, which
# is where internal/buildpolicy enforces it.
set -eu

PKG=./cmd/smtprelayd
BANNED='os/exec|plugin|runtime/cgo'
status=0

for target in linux/amd64 linux/arm64 windows/amd64; do
	goos=${target%/*}
	goarch=${target#*/}

	# CGO_ENABLED=0 mirrors the Makefile: the check has to describe the binary
	# that is actually shipped, not what a default toolchain would produce.
	hits=$(CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go list -deps "$PKG" |
		grep -xE "$BANNED" || true)

	if [ -n "$hits" ]; then
		echo "FAIL $target: banned package(s) in the dependency graph of $PKG:" >&2
		echo "$hits" | sed 's/^/  - /' >&2
		status=1
	else
		echo "ok   $target"
	fi
done

exit $status
