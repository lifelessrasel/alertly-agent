#!/usr/bin/env bash
#
# Builds the Linux agent binaries and SHA-256 checksums into dist/, ready to attach to a GitHub release.
#
# Usage: ./build.sh 0.1.0
#
set -euo pipefail

VERSION="${1:?Usage: ./build.sh VERSION}"
VERSION="${VERSION#v}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] || { echo "Invalid version: $VERSION" >&2; exit 1; }

cd "$(dirname "$0")"
rm -rf dist
mkdir -p dist

go vet ./...
go test ./...

for target in amd64:amd64: arm64:arm64: armv7:arm:7; do
    IFS=: read -r name goarch goarm <<<"$target"
    asset="alertly-agent-linux-${name}"
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM="$goarm" go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" -o "dist/${asset}" .
    if command -v sha256sum >/dev/null 2>&1; then
        (cd dist && sha256sum "$asset" >"${asset}.sha256")
    else
        (cd dist && shasum -a 256 "$asset" >"${asset}.sha256")
    fi
done

ls -l dist
