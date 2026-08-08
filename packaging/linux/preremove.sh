#!/bin/sh
# Runs before files are removed. deb passes "remove" here and "upgrade" when
# a new version is about to be unpacked; rpm passes 0 on final erase and 1+
# on upgrade. Only stop the service on a real removal, never on an upgrade.
set -e

case "$1" in
0 | remove)
	systemctl stop smtprelayd >/dev/null 2>&1 || true
	systemctl disable smtprelayd >/dev/null 2>&1 || true
	;;
*) ;;
esac

exit 0
