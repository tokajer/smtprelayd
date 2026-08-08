#!/bin/sh
# Runs after files are unpacked (deb: postinst, rpm: %post).
set -e

chown -R root:smtprelayd /etc/smtprelayd
chmod 0750 /etc/smtprelayd
chown -R smtprelayd:smtprelayd /var/lib/smtprelayd
chmod 0700 /var/lib/smtprelayd

systemctl daemon-reload >/dev/null 2>&1 || true

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
