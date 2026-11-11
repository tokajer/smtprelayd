#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Tokajer
#
# Run every native fuzz target for FUZZTIME each (default 10s), stopping at
# the first failure. `go test -fuzz` takes one target per package per run,
# hence one invocation per target. A failing input is written under the
# package's testdata/fuzz/ by go test; keep it as a regression seed once the
# defect it found is fixed.
set -eu

cd "$(dirname "$0")/.."

FUZZTIME=${FUZZTIME:-10s}

for target in \
	rewrite:FuzzParseBlock \
	rewrite:FuzzApply \
	rewrite:FuzzAddrOfMailbox \
	mailaddr:FuzzSplitMailbox \
	mailaddr:FuzzCheckEnvelope \
	listener:FuzzParsePath \
	spool:FuzzDecodeMeta; do
	pkg=${target%%:*}
	name=${target#*:}
	echo "==> $name ($FUZZTIME)"
	go test -run='^$' -fuzz="^$name\$" -fuzztime="$FUZZTIME" "./internal/$pkg"
done
