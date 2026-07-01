#!/usr/bin/env bash
# Build a statically-linked openvpn binary for macOS arm64.
# Run once from the repo root: bash build/openvpn/build.sh
# Output: build/openvpn/bin/openvpn
set -euo pipefail

OPENSSL_VERSION="3.3.1"
OPENVPN_VERSION="2.6.12"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/tmp"
OUT_DIR="$SCRIPT_DIR/bin"
MACOS_MIN="12.0"

mkdir -p "$BUILD_DIR" "$OUT_DIR"

echo "==> Building OpenSSL $OPENSSL_VERSION (arm64, static)"
OPENSSL_SRC="$BUILD_DIR/openssl-$OPENSSL_VERSION"
if [ ! -d "$OPENSSL_SRC" ]; then
  curl -fsSL "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz" | tar xz -C "$BUILD_DIR"
fi
pushd "$OPENSSL_SRC" > /dev/null
./Configure darwin64-arm64-cc \
  no-shared no-tests no-docs \
  --prefix="$BUILD_DIR/openssl-install" \
  --openssldir="$BUILD_DIR/openssl-install/ssl" \
  -mmacosx-version-min=$MACOS_MIN
make -j"$(sysctl -n hw.logicalcpu)"
make install_sw
popd > /dev/null

echo "==> Building OpenVPN $OPENVPN_VERSION (arm64, static)"
OPENVPN_SRC="$BUILD_DIR/openvpn-$OPENVPN_VERSION"
if [ ! -d "$OPENVPN_SRC" ]; then
  curl -fsSL "https://swupdate.openvpn.org/community/releases/openvpn-$OPENVPN_VERSION.tar.gz" | tar xz -C "$BUILD_DIR"
fi
pushd "$OPENVPN_SRC" > /dev/null
./configure \
  --disable-shared \
  --disable-debug \
  --disable-lz4 \
  --disable-lzo \
  --disable-plugin-auth-pam \
  --disable-plugin-down-root \
  --disable-unit-tests \
  CFLAGS="-arch arm64 -mmacosx-version-min=$MACOS_MIN" \
  LDFLAGS="-arch arm64 -mmacosx-version-min=$MACOS_MIN" \
  OPENSSL_CFLAGS="-I$BUILD_DIR/openssl-install/include" \
  OPENSSL_LIBS="-L$BUILD_DIR/openssl-install/lib -lssl -lcrypto" \
  PKG_CONFIG_PATH="$BUILD_DIR/openssl-install/lib/pkgconfig"
make -j"$(sysctl -n hw.logicalcpu)"
popd > /dev/null

cp "$OPENVPN_SRC/src/openvpn/openvpn" "$OUT_DIR/openvpn"
echo ""
echo "Built: $OUT_DIR/openvpn"
echo "Sign:  codesign --sign 'Developer ID Application: Alexander Steiner (M53GHX9FAY)' --options runtime --timestamp $OUT_DIR/openvpn"
