#!/bin/sh
# Runs after installation and upgrade. The service is never enabled or started on a
# first installation: the user configures it first. On upgrade, a running service is
# restarted with the new binary; existing tunnels stay in place.
set -e

# DEB: "configure" with the previous version on upgrade. RPM: 1 on installation,
# 2 or more on upgrade.
upgrade=
case "$1" in
    configure)
        if [ -n "${2:-}" ]; then
            upgrade=1
        fi
        ;;
    [2-9]*) upgrade=1 ;;
esac

# Skip when systemd is not running, for example in a container or chroot.
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload
if [ -n "$upgrade" ]; then
    systemctl try-restart gre-controller.service
fi
