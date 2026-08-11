#!/bin/sh
# Runs after files are unpacked (deb: postinst, rpm: %post).
set -e

CONFIG=/etc/smtprelayd/smtprelayd.toml
BINARY=/usr/sbin/smtprelayd

chown -R root:smtprelayd /etc/smtprelayd
chmod 0750 /etc/smtprelayd
chown -R smtprelayd:smtprelayd /var/lib/smtprelayd
chmod 0700 /var/lib/smtprelayd

systemctl daemon-reload >/dev/null 2>&1 || true

# The two packagers disagree about how they say "this is an upgrade": rpm
# passes the number of installed instances as $1 (1 on a first install, 2 or
# more on an upgrade), dpkg passes "configure" as $1 with the previously
# configured version in $2, empty on a first install. preremove.sh already
# reads the rpm form to avoid stopping the service on an upgrade; this reads
# both, because printing first-install instructions to someone who has been
# running the relay for a year is worse than printing nothing.
is_upgrade=no
case "$1" in
configure)
	if [ -n "$2" ]; then
		is_upgrade=yes
	fi
	;;
'' | *[!0-9]*)
	# Neither convention; treat it as a first install.
	;;
*)
	if [ "$1" -gt 1 ]; then
		is_upgrade=yes
	fi
	;;
esac

if [ "$is_upgrade" != yes ]; then
	cat <<'EOF'
smtprelayd installed.

Before starting the service:
  1. Copy /etc/smtprelayd/smtprelayd.toml.example to
     /etc/smtprelayd/smtprelayd.toml and edit it (tenant, mailbox, clients).
  2. Validate it:   smtprelayd -config /etc/smtprelayd/smtprelayd.toml check
  3. Start it:      systemctl enable --now smtprelayd

The service was not started automatically because it has no usable
configuration yet.
EOF
	exit 0
fi

# From here on this is an upgrade of an existing installation.
#
# The unpacked binary is not the running one: preremove.sh deliberately does
# not stop the service on an upgrade, so without a restart here the operator
# keeps running the version they just replaced -- including whatever they
# upgraded to get.
#
# try-restart, not restart: it restarts the unit only if it is currently
# running, so a service the operator had deliberately stopped stays stopped.
# That keeps the standing rule that a package never *starts* this service.
#
# The configuration is deliberately NOT validated first. Running "check" here
# looks like the safer order, but a ${ENV_VAR} secret resolves from the
# service's own environment -- supplied by a unit drop-in, which this script
# does not see -- so check would fail with "environment variable is unset" on
# a perfectly good configuration and turn every upgrade into a refusal to
# restart. Instead the restart is attempted and its outcome is reported: if
# this version rejects the configuration, the operator gets that here and in
# the journal rather than silently keeping the replaced binary.
if [ ! -f "$CONFIG" ]; then
	echo "smtprelayd upgraded. No $CONFIG yet, so nothing was restarted."
	exit 0
fi

if ! systemctl is-active --quiet smtprelayd; then
	echo "smtprelayd upgraded. The service was not running, so it was not started."
	exit 0
fi

systemctl try-restart smtprelayd >/dev/null 2>&1 || true

# The unit has Restart=on-failure, so a unit that is still starting reports
# "activating" rather than "active". Wait briefly before concluding that it
# failed, so that a slow start is not reported as a broken upgrade.
i=0
while [ "$i" -lt 5 ]; do
	if systemctl is-active --quiet smtprelayd; then
		echo "smtprelayd upgraded and restarted."
		exit 0
	fi
	i=$((i + 1))
	sleep 1
done

cat <<EOF
smtprelayd was upgraded and restarted, but the service did not come back.

This version may enforce something the previous one did not. Mail is not being
relayed until it starts, so check now:

  journalctl -u smtprelayd -n 30
  $BINARY -config $CONFIG check
  systemctl restart smtprelayd

Note that "check" resolves \${ENV_VAR} secrets from the environment; run it
the way the service does if a secret is reported as unset.
EOF

exit 0
