#!/bin/bash
# Recreates the patched Wails checkout that go.mod's replace directive points
# at: upstream module source + build/wails/*.patch. Re-run after bumping the
# Wails version (update WAILS_VERSION and the replace path in go.mod).
set -euo pipefail
WAILS_VERSION="v3.0.0-beta.34"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="$(cd "$ROOT" && go mod edit -json | python3 -c 'import json,sys; print(next(r["New"]["Path"] for r in json.load(sys.stdin)["Replace"] if r["Old"]["Path"]=="github.com/wailsapp/wails/v3"))')"

go mod download "github.com/wailsapp/wails/v3@${WAILS_VERSION}"
SRC="$(go env GOMODCACHE)/github.com/wailsapp/wails/v3@${WAILS_VERSION}"

if [ -e "$DEST" ]; then
  echo "$DEST already exists; remove it first to recreate" >&2
  exit 1
fi
cp -R "$SRC" "$DEST"
chmod -R u+w "$DEST"
for p in "$ROOT"/build/wails/*.patch; do
  patch -d "$DEST" -p1 < "$p"
done
echo "patched Wails ${WAILS_VERSION} ready at $DEST"
