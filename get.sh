#!/bin/sh
# zeronat graphical installer launcher. Detects this machine's architecture,
# downloads the matching prebuilt installer, and runs it.
#
#   curl -fsSL https://paltaio.github.io/zeronat/get.sh | sh
#
# Any arguments are passed through (e.g. `... | sh -s -- --dry-run`). On an
# unsupported platform it points at the plain shell installer instead.
set -eu

BASE="https://paltaio.github.io/zeronat"
SHELL_INSTALLER="$BASE/install.sh"

fallback() {
  echo "$1" >&2
  echo "  curl -fsSL $SHELL_INSTALLER | sh" >&2
  exit 1
}

[ "$(uname -s)" = Linux ] || fallback "the graphical installer is Linux-only; use the shell installer:"

case "$(uname -m)" in
  x86_64|amd64)   T=x86_64-unknown-linux-musl ;;
  aarch64|arm64)  T=aarch64-unknown-linux-musl ;;
  armv7l)         T=armv7-unknown-linux-musleabihf ;;
  armv6l)         T=arm-unknown-linux-musleabihf ;;
  mips)           T=mips-unknown-linux-gnu ;;
  mipsel)         T=mipsel-unknown-linux-gnu ;;
  mips64)         T=mips64-unknown-linux-gnuabi64 ;;
  mips64el)       T=mips64el-unknown-linux-gnuabi64 ;;
  *) fallback "no prebuilt installer for $(uname -m); use the shell installer:" ;;
esac

command -v curl >/dev/null 2>&1 || fallback "curl is required; use the shell installer:"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT INT TERM
curl -fsSL "$BASE/zeronat-installer-$T" -o "$TMP" \
  || fallback "could not download the installer for $T; use the shell installer:"
chmod +x "$TMP"

# The installer drives /dev/tty itself, so it works even though stdin is this pipe.
"$TMP" "$@"
