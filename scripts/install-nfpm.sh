#!/usr/bin/env bash
# Downloads nfpm, verifies it as nfpm's installation guide describes, and installs it
# into /usr/local/bin. Needs cosign in PATH and root through sudo.
#
# 1. cosign checks that checksums.txt was signed by nfpm's release workflow for this
#    exact tag (keyless signature, GitHub Actions OIDC).
# 2. sha256sum checks the downloaded archive against checksums.txt.
set -euo pipefail

version=2.48.0
case $(uname -m) in
    x86_64) arch=x86_64 ;;
    aarch64) arch=arm64 ;;
    *)
        echo "unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac
archive="nfpm_${version}_Linux_${arch}.tar.gz"
base="https://github.com/goreleaser/nfpm/releases/download/v$version"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
for file in checksums.txt checksums.txt.sigstore.json "$archive"; do
    curl -fsSLO "$base/$file"
done

cosign verify-blob \
    --certificate-identity "https://github.com/goreleaser/nfpm/.github/workflows/release.yml@refs/tags/v$version" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --bundle checksums.txt.sigstore.json \
    checksums.txt
sha256sum --ignore-missing -c checksums.txt
# --ignore-missing passes when the archive is not listed at all.
grep -q "  $archive\$" checksums.txt

tar -xzf "$archive" nfpm
sudo install -m 0755 nfpm /usr/local/bin/nfpm
nfpm --version
