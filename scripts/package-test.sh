#!/usr/bin/env bash
# Installs the packages in dist/ (from scripts/build-packages.sh) and checks their
# behavior: the DEB on this machine under systemd, the RPM in a Fedora container
# without systemd.
#
# This installs, upgrades, and removes a system package and starts its service, so
# run it only on a disposable Ubuntu machine with Docker, such as a CI runner.
set -euo pipefail

fail() {
    echo "$1" >&2
    exit 1
}

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
machine=$(uname -m)

# Use the package files nfpm wrote instead of predicting their names: nfpm turns a
# prerelease such as 0.1.0-rc.1 into 0.1.0~rc.1. Exactly one of each must exist.
only() {
    local files
    shopt -s nullglob
    # shellcheck disable=SC2206 # The pattern is meant to be expanded.
    files=(dist/$1)
    shopt -u nullglob
    ((${#files[@]} == 1)) ||
        fail "expected exactly one dist/$1, found ${#files[@]}: ${files[*]}"
    printf '%s\n' "${files[0]}"
}
deb=$(only '*.deb')
rpm=$(only '*.rpm')
archive="dist/gre-controller-$version-$machine-linux-gnu.tar.gz"
[[ -f $archive ]] || fail "missing $archive"
if dpkg-query -W gre-controller >/dev/null 2>&1; then
    fail "gre-controller is already installed here; refusing to touch it"
fi

unit=gre-controller.service
config=/etc/gre-controller/config.toml
state() {
    systemctl "$1" "$unit" || true
}

echo "== DEB: installation"
dpkg-deb --info "$deb"
sudo apt-get install -y "./$deb"
gre-controller --version
grep -qx "$config" <<<"$(dpkg-query --control-show gre-controller conffiles | awk '{print $1}')" ||
    fail "$config is not a conffile"
[[ $(state is-enabled) == disabled ]] || fail "service enabled on first installation"
[[ $(state is-active) == inactive ]] || fail "service started on first installation"
# The shipped configuration is valid and readable without privileges.
gre-controller validate

echo "== DEB: upgrade keeps the configuration and restarts the service"
# With the shipped configuration (no tunnels) and no owned interfaces on this
# machine, the service changes nothing.
sudo systemctl start "$unit"
sleep 2
[[ $(state is-active) == active ]] || fail "service did not start"
before=$(systemctl show -p InvocationID --value "$unit")
echo "# local change" | sudo tee -a "$config" >/dev/null
sudo apt-get install -y --reinstall "./$deb"
grep -q "local change" "$config" || fail "upgrade replaced the modified configuration"
[[ $(state is-active) == active ]] || fail "service not running after upgrade"
after=$(systemctl show -p InvocationID --value "$unit")
[[ $before != "$after" ]] || fail "upgrade did not restart the service"

echo "== DEB: removal stops the service and keeps the configuration; purge removes it"
sudo apt-get remove -y gre-controller
[[ $(state is-active) == inactive ]] || fail "service still running after removal"
[[ ! -e /usr/bin/gre-controller ]] || fail "binary left after removal"
[[ -e $config ]] || fail "configuration removed by remove"
sudo apt-get purge -y gre-controller
[[ ! -e $config ]] || fail "configuration left after purge"

echo "== RPM: installation, upgrade, and removal in Fedora, without systemd"
docker run --rm -v "$PWD/dist:/dist:ro" fedora:44 bash -euxc "
    dnf install -y /dist/$(basename "$rpm")
    gre-controller --version
    rpm -qc gre-controller | grep -qx $config
    rpm -q --requires gre-controller | grep '^glibc >= '
    gre-controller validate
    echo '# local change' >> $config
    dnf reinstall -y /dist/$(basename "$rpm")
    grep -q 'local change' $config
    dnf remove -y gre-controller
    test ! -e /usr/bin/gre-controller
    # A modified configuration file is saved, not deleted.
    test -e $config.rpmsave
"

echo "== Binary archive"
tar -tzf "$archive"
echo "package test passed"
