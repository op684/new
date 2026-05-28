#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ABI="arm64-v8a"
API="26"
BUILD="$ROOT/build/$ABI"
OUT="$ROOT/zygisk"

: "${ANDROID_NDK:?Set ANDROID_NDK to your NDK root (e.g. ~/Android/Sdk/ndk/26.1.x)}"

mkdir -p "$BUILD" "$OUT"

cmake -S "$ROOT/jni" -B "$BUILD" -GNinja \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM="android-$API" \
  -DCMAKE_BUILD_TYPE=Release

cmake --build "$BUILD" --parallel

cp "$BUILD/${ABI}.so" "$OUT/${ABI}.so"
"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" "$OUT/${ABI}.so" || true

cd "$ROOT"
ZIP="mcpe_modmenu.zip"
rm -f "$ZIP"
zip -r9 "$ZIP" \
  META-INF \
  module.prop \
  customize.sh \
  zygisk/${ABI}.so >/dev/null
echo "built $ZIP"
