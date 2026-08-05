#!/bin/sh
# zeronat installer launcher. Detects this machine's architecture, downloads the
# matching prebuilt installer, and runs it.
#
#   curl -fsSL https://paltaio.github.io/zeronat/get.sh | sh
#
# Any arguments are passed through (e.g. `... | sh -s -- --dry-run`).
set -eu

DOCS="https://paltaio.github.io/zeronat/"
LATEST_URL="https://github.com/paltaio/zeronat/releases/latest"
RELEASE_ORIGIN="https://github.com/paltaio/zeronat"
PUBLIC_KEY="RWTxV9kbCgK6hQn0rm2f5SIgbZvFEavw6Qf+b3BgCZldh/Er1tMhlAhK"
KEY_ID="85ba020a1bd957f1"

unsupported() {
  echo "$1" >&2
  echo "see $DOCS for manual and docker install instructions" >&2
  exit 1
}

[ "$(uname -s)" = Linux ] || unsupported "zeronat installs only on Linux."

case "$(uname -m)" in
  x86_64|amd64)   T=x86_64-unknown-linux-musl ;;
  aarch64|arm64)  T=aarch64-unknown-linux-musl ;;
  armv7l)         T=armv7-unknown-linux-musleabihf ;;
  armv6l)         T=arm-unknown-linux-musleabihf ;;
  mips)           T=mips-unknown-linux-gnu ;;
  mipsel)         T=mipsel-unknown-linux-gnu ;;
  mips64)         T=mips64-unknown-linux-gnuabi64 ;;
  mips64el)       T=mips64el-unknown-linux-gnuabi64 ;;
  *) unsupported "no prebuilt installer for $(uname -m)." ;;
esac

for tool in curl grep awk minisign sha256sum mktemp tail wc tr chmod; do
  command -v "$tool" >/dev/null 2>&1 || unsupported "$tool is required."
done

TAG_URL=$(curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' --max-redirs 5 \
  --max-time 20 --output /dev/null --write-out '%{url_effective}' "$LATEST_URL") \
  || unsupported "could not resolve the latest release."
TAG=${TAG_URL##*/}
case "$TAG" in
  v*) ;;
  *) unsupported "the latest release tag is invalid." ;;
esac
printf '%s\n' "$TAG" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
  || unsupported "the latest release tag is invalid."
[ "$TAG_URL" = "$RELEASE_ORIGIN/releases/tag/$TAG" ] \
  || unsupported "the latest release redirect is invalid."

MANIFEST_NAME="zeronat-release-v1-$TAG.manifest"
SIGNATURE_NAME="$MANIFEST_NAME.$KEY_ID.minisig"
ASSET_NAME="zeronat-installer-$T"
DOWNLOAD_BASE="$RELEASE_ORIGIN/releases/download/$TAG"

TMP_DIR=$(mktemp -d)
MANIFEST="$TMP_DIR/$MANIFEST_NAME"
SIGNATURE="$TMP_DIR/$SIGNATURE_NAME"
INSTALLER="$TMP_DIR/$ASSET_NAME"
cleanup() {
  rm -f "$MANIFEST" "$SIGNATURE" "$INSTALLER"
  rmdir "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

fetch() {
  url=$1
  limit=$2
  output=$3
  blocks=$(( (limit + 511) / 512 ))
  (
    ulimit -f "$blocks" || exit 125
    exec curl --fail --silent --show-error --location \
      --proto '=https' --proto-redir '=https' --max-redirs 5 \
      --max-filesize "$limit" --max-time 180 --output "$output" "$url"
  )
}

fetch "$DOWNLOAD_BASE/$MANIFEST_NAME" 65536 "$MANIFEST" \
  || unsupported "the signed release manifest is unavailable."
fetch "$DOWNLOAD_BASE/$SIGNATURE_NAME" 4096 "$SIGNATURE" \
  || unsupported "the release signature is unavailable."
minisign -V -H -q -P "$PUBLIC_KEY" -m "$MANIFEST" -x "$SIGNATURE" \
  || unsupported "the release manifest signature is invalid."

grep -q "$(printf '\r')" "$MANIFEST" \
  && unsupported "the release manifest is malformed."
tail -c 1 "$MANIFEST" | grep -qx '' \
  || unsupported "the release manifest is malformed."

ENTRY=$(awk -v tag="$TAG" -v asset="$ASSET_NAME" '
  NR == 1 {
    if ($0 != "zeronat-release-v1 " tag) exit 10
    next
  }
  {
    if (NF != 3) exit 11
    if (length($1) != 64 || $1 !~ /^[0-9a-f]+$/) exit 12
    if ($2 !~ /^(0|[1-9][0-9]*)$/ || $2 == 0 || $2 > 268435456) exit 13
    if ($3 !~ /^[A-Za-z0-9._-]+$/) exit 14
    if (previous != "" && previous >= $3) exit 15
    previous = $3
    if ($3 == asset) {
      count++
      digest = $1
      size = $2
    }
  }
  END {
    if (count != 1) exit 16
    print digest " " size
  }
' "$MANIFEST") || unsupported "the release manifest is malformed."

DIGEST=${ENTRY%% *}
LENGTH=${ENTRY#* }
fetch "$DOWNLOAD_BASE/$ASSET_NAME" "$LENGTH" "$INSTALLER" \
  || unsupported "could not download the installer for $T."
[ "$(wc -c < "$INSTALLER" | tr -d ' ')" = "$LENGTH" ] \
  || unsupported "the installer length does not match the signed manifest."
[ "$(sha256sum "$INSTALLER" | awk '{print $1}')" = "$DIGEST" ] \
  || unsupported "the installer digest does not match the signed manifest."
chmod +x "$INSTALLER"

# The installer drives /dev/tty itself, so it works even though stdin is this pipe.
"$INSTALLER" "$@"
