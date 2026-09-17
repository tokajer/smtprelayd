#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Tokajer
#
# Start a throwaway instance and probe it for open relay.
#
# internal/selftest is the only check that exercises the built binary the way
# a device reaches it, but it needs a running instance, so CI never ran it:
# the refusal of an unmatched source could regress with every other gate
# still green. This runs it against a short-lived instance on loopback.
#
# The client CIDR deliberately excludes the loopback address the probe dials
# from. Allowlisting it would make the probe report "allowlisted, so the
# default-deny path was not exercised" and still exit 0 -- true, and useless
# as a gate.
set -eu

BIN=${BIN:-./bin/smtprelayd}
PORT=${PORT:-12525}

WORK=$(mktemp -d)
cleanup() {
	if [ -n "${PID:-}" ]; then
		kill "$PID" 2>/dev/null || true
		wait "$PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/data"
cat > "$WORK/smtprelayd.toml" <<TOML
[service]
data_dir = "$WORK/data"
hostname = "selftest.invalid"

[log]
file = "smtprelayd.log"

[[listener]]
name = "probe"
address = "127.0.0.1:$PORT"
tls = "none"

[[client]]
name = "devices"
cidr = ["10.10.5.0/24"]
route = "null"

[[route]]
name = "null"
default = true
host = "smtp.invalid"
port = 587
tls = "none"
auth = "none"
TOML

"$BIN" -config "$WORK/smtprelayd.toml" run &
PID=$!

# The instance logs "listening" from listen(), which Bind calls, so this is
# its own statement that the socket is open -- no extra tool to depend on.
LOG="$WORK/data/smtprelayd.log"
i=0
while [ "$i" -lt 30 ]; do
	if [ -f "$LOG" ] && grep -q '"listening"' "$LOG"; then
		break
	fi
	if ! kill -0 "$PID" 2>/dev/null; then
		echo "the instance exited before it was listening:" >&2
		cat "$LOG" "$WORK/data/smtprelayd-error.log" 2>/dev/null >&2 || true
		exit 1
	fi
	i=$((i + 1))
	sleep 1
done
if [ "$i" -ge 30 ]; then
	echo "the instance did not report listening within 30s" >&2
	cat "$LOG" 2>/dev/null >&2 || true
	exit 1
fi

"$BIN" -config "$WORK/smtprelayd.toml" selftest
