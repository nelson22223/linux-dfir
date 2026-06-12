#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARCH=$(uname -m)

case "$ARCH" in
  x86_64|amd64)
    BIN="$SCRIPT_DIR/bin/dfir-collector-linux-amd64"
    ;;
  aarch64|arm64)
    BIN="$SCRIPT_DIR/bin/dfir-collector-linux-arm64"
    ;;
  i386|i686)
    BIN="$SCRIPT_DIR/bin/dfir-collector-linux-386"
    ;;
  *)
    printf 'unsupported architecture: %s\n' "$ARCH" >&2
    exit 1
    ;;
esac

if [ ! -x "$BIN" ]; then
  printf 'collector binary not found or not executable: %s\n' "$BIN" >&2
  exit 1
fi

cd "$SCRIPT_DIR"
exec "$BIN" "$@"
