#!/bin/sh
# Runs before removal and before upgrade. Only on removal: stop and disable the
# service. Stopping leaves the managed tunnels in place.
set -e

# DEB: "remove" (not "upgrade"). RPM: 0 when the last version is being removed.
case "$1" in
    remove | 0) ;;
    *) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl disable --now gre-controller.service
else
    systemctl disable gre-controller.service || true
fi
