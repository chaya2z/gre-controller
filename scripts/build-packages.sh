#!/usr/bin/env bash
# Builds the release binary for this machine's architecture and writes a binary
# archive, a DEB package, and an RPM package to dist/. Needs nfpm in PATH.
#
# Build on the oldest distribution to support: the binary links glibc dynamically
# and requires at least the glibc of the build machine's symbols it uses.
set -euo pipefail

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
machine=$(uname -m)
case "$machine" in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *)
        echo "unsupported architecture: $machine" >&2
        exit 1
        ;;
esac

cargo build --locked --release
binary=target/release/gre-controller

# The newest versioned glibc symbol the binary uses is its real minimum.
glibc_min=$(objdump -T "$binary" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' |
    sed 's/^GLIBC_//' | sort -uV | tail -n 1)
echo "gre-controller $version for $arch needs glibc >= $glibc_min"

mkdir -p dist
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
root="$staging/gre-controller-$version"
mkdir -p "$root"
install -m 0755 "$binary" "$root/gre-controller"
install -m 0644 packaging/gre-controller.service packaging/config.toml \
    README.md docs/design.md LICENSE-MIT LICENSE-APACHE "$root/"
tar -C "$staging" --owner=0 --group=0 --numeric-owner \
    -czf "dist/gre-controller-$version-$machine-linux-gnu.tar.gz" \
    "gre-controller-$version"

for packager in deb rpm; do
    VERSION=$version ARCH=$arch GLIBC_MIN=$glibc_min BINARY=$binary \
        nfpm package --config packaging/nfpm.yaml --packager "$packager" --target dist/
done
ls -l dist/
