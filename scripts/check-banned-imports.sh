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
# The check reports the *importer*, not just the banned package, and every
# accepted importer has to be named in ALLOWED_PAIRS below. Asserting "os/exec
# is absent" stopped being possible once modernc.org/sqlite was adopted, and
# degrading the rule to "os/exec is present, we assume harmlessly" would have
# retired it. Naming the one importer keeps every other route a failure.
#
# unsafe is deliberately not checked here: the standard library uses it
# everywhere, so it is only meaningful as a rule about first-party code, which
# is where internal/buildpolicy enforces it.
set -eu

PKG=./cmd/smtprelayd
BANNED='os/exec|plugin|runtime/cgo'

# "<importing package> <banned package>" pairs that are accepted, one per line.
# modernc.org/libc is the pure-Go C runtime under modernc.org/sqlite, which the
# no-cgo rule forces on us; it imports os/exec only to implement the C system()
# and popen() shims. The SQLite amalgamation never calls either -- system() is
# used by the sqlite3 CLI, which is not part of the library -- so the code is
# linked but unreachable. Re-verify with:
#   grep -r 'Xsystem\|Xpopen' "$(go env GOMODCACHE)/modernc.org/sqlite@*/lib/"
ALLOWED_PAIRS='modernc.org/libc os/exec'

allowfile=$(mktemp)
trap 'rm -f "$allowfile"' EXIT HUP INT TERM
printf '%s\n' "$ALLOWED_PAIRS" >"$allowfile"

status=0

for target in linux/amd64 linux/arm64 windows/amd64; do
	goos=${target%/*}
	goarch=${target#*/}

	# CGO_ENABLED=0 mirrors the Makefile: the check has to describe the binary
	# that is actually shipped, not what a default toolchain would produce.
	pairs=$(CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go list -deps \
		-f '{{$p := .ImportPath}}{{range .Imports}}{{$p}} {{.}}
{{end}}' "$PKG" | grep -E " ($BANNED)\$" || true)

	hits=''
	if [ -n "$pairs" ]; then
		hits=$(printf '%s\n' "$pairs" | grep -vxF -f "$allowfile" || true)
	fi

	if [ -n "$hits" ]; then
		echo "FAIL $target: banned import(s) in the dependency graph of $PKG:" >&2
		printf '%s\n' "$hits" | awk '{print "  - " $1 " imports " $2}' >&2
		status=1
	else
		echo "ok   $target"
	fi
done

exit $status
