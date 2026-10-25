#!/usr/bin/env bash
# Build a statically-linked openvpn binary for macOS arm64.
# Run once from the repo root: bash build/openvpn/build.sh
# Output: build/openvpn/bin/openvpn
set -euo pipefail

# OpenVPN 2.7.x officially supports OpenSSL 4.0 (Changes.rst, 2.7.2:
# "fully support OpenSSL 4.0 now"). OpenSSL 4.0 is supported until 2027-05-14
# (https://openssl-library.org/policies/releasestrat/). Do not jump to a newer
# OpenSSL minor until OpenVPN's Changes.rst says it is supported.
OPENSSL_VERSION="4.0.3"
# From https://github.com/openssl/openssl/releases/download/openssl-4.0.3/openssl-4.0.3.tar.gz.sha256
OPENSSL_SHA256="325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9"
OPENVPN_VERSION="2.7.8"
# From the GitHub release asset digest for
# https://github.com/OpenVPN/openvpn/releases/download/v2.7.8/openvpn-2.7.8.tar.gz
# (identical to the swupdate.openvpn.org tarball).
OPENVPN_SHA256="c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/tmp"
OUT_DIR="$SCRIPT_DIR/bin"
MACOS_MIN="13.0"

# The binary runs as root from the privileged helper. OpenSSL bakes
# OPENSSLDIR (openssl.cnf, which can load provider modules) and MODULESDIR
# into libcrypto at build time; if those pointed into this (user-writable)
# build tree, any local user could plant an openssl.cnf / provider dylib that
# root would load. Point OPENSSLDIR at a non-existent path under the
# root-owned /var/empty, and build with no-module so providers (incl. legacy)
# are compiled into libcrypto and nothing is ever dlopen()ed.
OPENSSL_DIR_RUNTIME="/var/empty/lockplus-openssl"

mkdir -p "$BUILD_DIR" "$OUT_DIR"

# fetch_verified <url> <sha256> <dest-file>
fetch_verified() {
  local url="$1" want="$2" dest="$3"
  if [ ! -f "$dest" ]; then
    curl -fsSL -o "$dest.part" "$url"
    mv "$dest.part" "$dest"
  fi
  local got
  got="$(shasum -a 256 "$dest" | awk '{print $1}')"
  if [ "$got" != "$want" ]; then
    echo "SHA256 mismatch for $dest" >&2
    echo "  expected: $want" >&2
    echo "  got:      $got" >&2
    rm -f "$dest"
    exit 1
  fi
}

echo "==> Building OpenSSL $OPENSSL_VERSION (arm64, static)"
OPENSSL_TGZ="$BUILD_DIR/openssl-$OPENSSL_VERSION.tar.gz"
OPENSSL_SRC="$BUILD_DIR/openssl-$OPENSSL_VERSION"
OPENSSL_INSTALL="$BUILD_DIR/openssl-$OPENSSL_VERSION-install"
fetch_verified "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
  "$OPENSSL_SHA256" "$OPENSSL_TGZ"
rm -rf "$OPENSSL_SRC" "$OPENSSL_INSTALL"
tar xzf "$OPENSSL_TGZ" -C "$BUILD_DIR"
pushd "$OPENSSL_SRC" > /dev/null
./Configure darwin64-arm64 \
  no-shared no-dso no-module no-tests no-docs no-apps \
  --prefix="$OPENSSL_INSTALL" \
  --openssldir="$OPENSSL_DIR_RUNTIME" \
  -mmacosx-version-min=$MACOS_MIN
make -j"$(sysctl -n hw.logicalcpu)"
make install_sw
popd > /dev/null

echo "==> Building OpenVPN $OPENVPN_VERSION (arm64, static)"
OPENVPN_TGZ="$BUILD_DIR/openvpn-$OPENVPN_VERSION.tar.gz"
OPENVPN_SRC="$BUILD_DIR/openvpn-$OPENVPN_VERSION"
fetch_verified "https://swupdate.openvpn.org/community/releases/openvpn-$OPENVPN_VERSION.tar.gz" \
  "$OPENVPN_SHA256" "$OPENVPN_TGZ"
rm -rf "$OPENVPN_SRC"
tar xzf "$OPENVPN_TGZ" -C "$BUILD_DIR"
pushd "$OPENVPN_SRC" > /dev/null
# The build tree lives inside the LockPlus git repo; without this, OpenVPN's
# configure finds that repo and stamps our branch/commit into --version.
export GIT_CEILING_DIRECTORIES="$BUILD_DIR"
# --disable-dns-updown-by-default: 2.7 otherwise runs ${libexecdir}/openvpn/
#   dns-updown (/usr/local/libexec/...) as a *built-in* command, which
#   --script-security 1 permits — i.e. root would exec whatever sits at that
#   path. LockPlus applies pushed DNS itself (internal/ovpn/manager.go), and
#   also passes --dns-updown disable at runtime.
# --disable-plugins: no dlopen() of plugin modules from a root process.
# --with-openssl-engine=no: engines are gone in OpenSSL 4.
./configure \
  --disable-shared \
  --disable-debug \
  --disable-lz4 \
  --disable-lzo \
  --disable-plugins \
  --disable-plugin-auth-pam \
  --disable-plugin-down-root \
  --disable-dns-updown-by-default \
  --disable-unit-tests \
  --with-openssl-engine=no \
  CFLAGS="-arch arm64 -mmacosx-version-min=$MACOS_MIN" \
  LDFLAGS="-arch arm64 -mmacosx-version-min=$MACOS_MIN" \
  OPENSSL_CFLAGS="-I$OPENSSL_INSTALL/include" \
  OPENSSL_LIBS="-L$OPENSSL_INSTALL/lib -lssl -lcrypto" \
  PKG_CONFIG_PATH="$OPENSSL_INSTALL/lib/pkgconfig"
make -j"$(sysctl -n hw.logicalcpu)"
popd > /dev/null

cp "$OPENVPN_SRC/src/openvpn/openvpn" "$OUT_DIR/openvpn"
echo ""
echo "Built: $OUT_DIR/openvpn"
"$OUT_DIR/openvpn" --version | head -2
otool -L "$OUT_DIR/openvpn"
echo "Sign:  codesign --sign 'Developer ID Application: Alexander Steiner (M53GHX9FAY)' --options runtime --timestamp $OUT_DIR/openvpn"
