#!/usr/bin/env bash
#
# Cross-compile SPECTER release binaries. Output lands in ./dist.
# The arm64 builds are what you want for a OnePlus 7 Pro running Termux.
#
set -e

mkdir -p dist
LDFLAGS="-s -w"

# build <goos> <goarch> <suffix> — builds the single unified specter binary
# (auto / recon / harvest / analyze are all subcommands of it).
build() {
    local goos=$1 goarch=$2 sfx=$3
    echo ">> $goos/$goarch"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -ldflags "$LDFLAGS" -o "dist/specter-$sfx" .
}

# Primary targets for the OnePlus 7 Pro (Snapdragon 855 / aarch64):
build android arm64 android-arm64
build linux   arm64 linux-arm64

# Handy extras:
build linux   amd64 linux-amd64
build darwin  arm64 darwin-arm64
build windows amd64 windows-amd64.exe

echo
echo "done. binaries:"
ls -lh dist/
