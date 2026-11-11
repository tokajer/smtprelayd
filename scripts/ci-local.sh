#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Tokajer
#
# Run every step of the Linux jobs in .github/workflows/ci.yml locally, with
# the tool versions pinned there.
#
# Hand-assembled local checks missed steps and misread exit codes: after the
# go1.27.3 bump gosec and then staticcheck passed "locally" (output piped
# through tail, which reported tail's status) and failed in CI one after the
# other. The versions are read from ci.yml so there is one place to bump them;
# the step list is not, so a step added to ci.yml has to be added here too.
#
# Every step runs even after a failure, so one run shows everything that would
# fail in CI. The Windows job (go test on windows-latest) is not reproduced;
# the windows vet step covers compilation only.
set -eu

# The Makefile exports CGO_ENABLED=0 for its build targets, and `make ci`
# would hand that to every analyzer here. CI runs them with the runner's
# default, so the analysed file set must not depend on how this was started.
unset CGO_ENABLED

cd "$(dirname "$0")/.."

WORKFLOW=.github/workflows/ci.yml

pin() {
	v=$(sed -n "s/^  $1: \"\(.*\)\"$/\1/p" "$WORKFLOW")
	if [ -z "$v" ]; then
		echo "ci-local: $1 not found in $WORKFLOW" >&2
		exit 2
	fi
	echo "$v"
}

GO_VERSION=$(pin GO_VERSION)
GOVULNCHECK_VERSION=$(pin GOVULNCHECK_VERSION)
GOSEC_VERSION=$(pin GOSEC_VERSION)
STATICCHECK_VERSION=$(pin STATICCHECK_VERSION)

# A local toolchain other than the CI one is how the export-data failures
# above stayed invisible, so a mismatch is fatal rather than a warning.
have=$(go env GOVERSION)
if [ "$have" != "go$GO_VERSION" ]; then
	echo "ci-local: go is $have, $WORKFLOW pins go$GO_VERSION" >&2
	exit 2
fi

failed=""

step() {
	name=$1
	shift
	echo "==> $name"
	if "$@"; then
		echo "    ok: $name"
	else
		echo "    FAILED (exit $?): $name"
		failed="$failed
  $name"
	fi
}

gofmt_clean() {
	out=$(gofmt -l .) || return 1
	[ -z "$out" ] || { echo "$out"; return 1; }
}

step "Format" gofmt_clean
step "Vet" go vet ./...
step "Vet for windows/amd64" env GOOS=windows GOARCH=amd64 go vet ./...
step "Vet load tests" go vet -tags loadtest ./...
step "Test" env CGO_ENABLED=1 go test -race ./...
step "Fuzz" ./scripts/fuzz.sh
step "Banned imports" ./scripts/check-banned-imports.sh
step "govulncheck $GOVULNCHECK_VERSION" go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...
step "gosec $GOSEC_VERSION" go run "github.com/securego/gosec/v2/cmd/gosec@$GOSEC_VERSION" -severity=medium ./...
step "staticcheck $STATICCHECK_VERSION" go run "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" ./...
step "Build and open relay probe" sh -c 'make build && ./scripts/selftest-ci.sh'
step "Cross-compile" make build-all

if [ -n "$failed" ]; then
	echo "ci-local: failed steps:$failed" >&2
	exit 1
fi
echo "ci-local: all steps passed on go$GO_VERSION"
