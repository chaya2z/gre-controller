#!/bin/sh
# Runs after removal and upgrade: let systemd forget the removed unit file.
set -e
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload
