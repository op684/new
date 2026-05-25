#!/usr/bin/env bash
#
# Cross-compile SPECTER release binaries. Output lands in ./dist.
# The arm64 builds are what you want for a OnePlus 7 Pro running Termux.
#
set -e

mkdir -p dist
LDFLAGS="-s -w"

build() {
    local goos=$1 goarch=$2 out=$3
    echo ">> $goos/$goarch -> dist/$out"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -ldflags "$LDFLAGS" -o "dist/$out" .
}

# Primary targets for the OnePlus 7 Pro (Snapdragon 855 / aarch64):
build android arm64 specter-android-arm64
build linux   arm64 specter-linux-arm64

# Handy extras:
build linux   amd64 specter-linux-amd64
build darwin  arm64 specter-darwin-arm64
build windows amd64 specter-windows-amd64.exe

echo
echo "done. binaries:"
ls -lh dist/
