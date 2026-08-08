#!/bin/sh
# Runs before files are unpacked (deb: preinst, rpm: %pre).
set -e

if ! getent group smtprelayd >/dev/null 2>&1; then
	groupadd --system smtprelayd
fi

if ! getent passwd smtprelayd >/dev/null 2>&1; then
	useradd --system --gid smtprelayd --home-dir /var/lib/smtprelayd \
		--no-create-home --shell /usr/sbin/nologin \
		--comment "smtprelayd service account" smtprelayd
fi

exit 0
