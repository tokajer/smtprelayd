#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Tokajer
#
# Start throwaway instances and probe them for open relay.
#
# internal/selftest is the only check that exercises the built binary the way
# a device reaches it, but it needs a running instance, so CI never ran it:
# the refusal of an unmatched source could regress with every other gate
# still green. This runs it against short-lived instances on loopback.
#
# Two scenarios, because one of them cannot see the other's regression.
#
# 1. Cleartext listener, client CIDR deliberately excluding the loopback
#    address the probe dials from. Allowlisting it would make the probe report
#    "allowlisted, so the default-deny path was not exercised" and still exit
#    0 -- true, and useless as a gate. This is the open-relay gate proper.
#
# 2. STARTTLS listener with require_tls, and loopback deliberately *included*
#    in the client CIDR, so the probe is supposed to be allowed to relay and
#    the run must say so. Until 2026-09-18 the probe never negotiated
#    STARTTLS, so such a listener refused it at MAIL FROM with 530 and the
#    check read that as a relay denial: a silent, unqualified pass in which
#    nothing about the relay policy had actually been asked. Scenario 1 takes
#    the unmatched-source path, which is refused with 550 *before* the TLS
#    gate, so it can never catch that. Here the note is the assertion: no
#    note means the probe did not get through TLS to the relay decision.
set -eu

BIN=${BIN:-./bin/smtprelayd}
PORT=${PORT:-12525}
TLS_PORT=${TLS_PORT:-12526}

WORK=$(mktemp -d)
PID=
cleanup() {
	if [ -n "${PID:-}" ]; then
		kill "$PID" 2>/dev/null || true
		wait "$PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

# start_instance <config> <data dir>
# Leaves the pid in PID. The instance logs "listening" from listen(), which
# Bind calls, so this is its own statement that the socket is open -- no extra
# tool to depend on.
start_instance() {
	cfg=$1
	data=$2
	"$BIN" -config "$cfg" run &
	PID=$!

	log="$data/smtprelayd.log"
	i=0
	while [ "$i" -lt 30 ]; do
		if [ -f "$log" ] && grep -q '"listening"' "$log"; then
			return 0
		fi
		if ! kill -0 "$PID" 2>/dev/null; then
			echo "the instance exited before it was listening:" >&2
			cat "$log" "$data/smtprelayd-error.log" 2>/dev/null >&2 || true
			exit 1
		fi
		i=$((i + 1))
		sleep 1
	done
	echo "the instance did not report listening within 30s" >&2
	cat "$log" 2>/dev/null >&2 || true
	exit 1
}

stop_instance() {
	if [ -n "${PID:-}" ]; then
		kill "$PID" 2>/dev/null || true
		wait "$PID" 2>/dev/null || true
		PID=
	fi
}

# ---------------------------------------------------------------- scenario 1
mkdir -p "$WORK/plain"
cat > "$WORK/plain.toml" <<TOML
[service]
data_dir = "$WORK/plain"
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

start_instance "$WORK/plain.toml" "$WORK/plain"
echo "scenario 1: cleartext listener, probe source not allowlisted"
out=$("$BIN" -config "$WORK/plain.toml" selftest)
echo "$out"
case "$out" in
*note:*)
	echo "scenario 1 produced a note; the default-deny path was not exercised" >&2
	exit 1
	;;
esac
stop_instance

# ---------------------------------------------------------------- scenario 2
mkdir -p "$WORK/tls"
cat > "$WORK/tls.toml" <<TOML
[service]
data_dir = "$WORK/tls"
hostname = "selftest.invalid"

[log]
file = "smtprelayd.log"

[tls]
cert_file = "$WORK/tls/cert.pem"
key_file  = "$WORK/tls/key.pem"

[[listener]]
name = "secure-probe"
address = "127.0.0.1:$TLS_PORT"
tls = "starttls"
require_tls = true

[[client]]
name = "same-host-app"
cidr = ["127.0.0.1/32"]
route = "null"

[[route]]
name = "null"
default = true
host = "smtp.invalid"
port = 587
tls = "none"
auth = "none"
TOML

"$BIN" -config "$WORK/tls.toml" gen-cert >/dev/null

start_instance "$WORK/tls.toml" "$WORK/tls"
echo "scenario 2: starttls listener with require_tls, probe source allowlisted"
out=$("$BIN" -config "$WORK/tls.toml" selftest)
echo "$out"
case "$out" in
*"same-host-app"*)
	# The probe negotiated STARTTLS, reached the relay decision, was allowed,
	# and said so. That is the whole assertion.
	;;
*)
	echo "scenario 2: the probe never reported reaching the relay decision behind require_tls;" >&2
	echo "this is the silent-pass regression -- it did not get through STARTTLS" >&2
	exit 1
	;;
esac
stop_instance

echo "open relay self-test gates passed"
