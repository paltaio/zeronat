#!/bin/sh
# zeronat installer launcher. Detects this machine's architecture, downloads the
# matching release package, and runs its installer.
#
#   curl -fsSL https://paltaio.github.io/zeronat/get.sh | sh
#
# Any arguments are passed through (e.g. `... | sh -s -- --dry-run`).
set -eu

DOCS="https://paltaio.github.io/zeronat/"
LATEST_URL="https://github.com/paltaio/zeronat/releases/latest"
RELEASE_ORIGIN="https://github.com/paltaio/zeronat"
PUBLIC_KEY="RWTxV9kbCgK6hQn0rm2f5SIgbZvFEavw6Qf+b3BgCZldh/Er1tMhlAhK"

unsupported() {
  echo "$1" >&2
  echo "see $DOCS for manual and docker install instructions" >&2
  exit 1
}

[ "$(uname -s)" = Linux ] || unsupported "zeronat installs only on Linux."

case "$(uname -m)" in
  x86_64|amd64)   PLATFORM=linux-amd64 ;;
  aarch64|arm64)  PLATFORM=linux-arm64 ;;
  armv7l)         PLATFORM=linux-armv7 ;;
  armv6l)         PLATFORM=linux-armv6 ;;
  mips)           PLATFORM=linux-mips ;;
  mipsel)         PLATFORM=linux-mipsel ;;
  mips64)         PLATFORM=linux-mips64 ;;
  mips64el)       PLATFORM=linux-mips64el ;;
  *) unsupported "no prebuilt installer for $(uname -m)." ;;
esac

for tool in curl grep awk minisign sha256sum mktemp tail wc tr chmod tar; do
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

MANIFEST_NAME="release.manifest"
SIGNATURE_NAME="release.manifest.minisig"
ASSET_NAME="zeronat-$TAG-$PLATFORM.tar"
DOWNLOAD_BASE="$RELEASE_ORIGIN/releases/download/$TAG"

TMP_DIR=$(mktemp -d)
MANIFEST="$TMP_DIR/$MANIFEST_NAME"
SIGNATURE="$TMP_DIR/$SIGNATURE_NAME"
PACKAGE="$TMP_DIR/$ASSET_NAME"
INSTALLER="$TMP_DIR/zeronat-installer"
cleanup() {
  rm -f "$MANIFEST" "$SIGNATURE" "$PACKAGE" "$INSTALLER"
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
    if ($0 != "zeronat-release-v2 " tag) exit 10
    next
  }
  NR == 2 {
    prefix = "ghcr.io/paltaio/zeronat@sha256:"
    if (NF != 2 || $1 != "zeronat-image" || index($2, prefix) != 1) exit 11
    digest = substr($2, length(prefix) + 1)
    if (length(digest) != 64 || digest !~ /^[0-9a-f]+$/) exit 12
    next
  }
  NR == 3 {
    prefix = "ghcr.io/paltaio/znpppoe@sha256:"
    if (NF != 2 || $1 != "znpppoe-image" || index($2, prefix) != 1) exit 13
    digest = substr($2, length(prefix) + 1)
    if (length(digest) != 64 || digest !~ /^[0-9a-f]+$/) exit 14
    next
  }
  {
    if (NF != 3) exit 15
    if (length($1) != 64 || $1 !~ /^[0-9a-f]+$/) exit 16
    if ($2 !~ /^(0|[1-9][0-9]*)$/ || $2 == 0 || $2 > 268435456) exit 17
    if ($3 !~ /^[A-Za-z0-9._-]+$/) exit 18
    if (previous != "" && previous >= $3) exit 19
    previous = $3
    if ($3 == asset) {
      count++
      digest = $1
      size = $2
    }
  }
  END {
    if (count != 1) exit 20
    print digest " " size
  }
' "$MANIFEST") || unsupported "the release manifest is malformed."

DIGEST=${ENTRY%% *}
LENGTH=${ENTRY#* }
fetch "$DOWNLOAD_BASE/$ASSET_NAME" "$LENGTH" "$PACKAGE" \
  || unsupported "could not download the package for $PLATFORM."
[ "$(wc -c < "$PACKAGE" | tr -d ' ')" = "$LENGTH" ] \
  || unsupported "the package length does not match the signed manifest."
[ "$(sha256sum "$PACKAGE" | awk '{print $1}')" = "$DIGEST" ] \
  || unsupported "the package digest does not match the signed manifest."

MEMBERS=$(tar -tf "$PACKAGE") || unsupported "the release package is malformed."
EXPECTED_MEMBERS=$(printf '%s\n%s\n' zeronat zeronat-installer)
[ "$MEMBERS" = "$EXPECTED_MEMBERS" ] \
  || unsupported "the release package has unexpected contents."
tar -xOf "$PACKAGE" zeronat-installer > "$INSTALLER" \
  || unsupported "the release package has no installer."
[ -s "$INSTALLER" ] || unsupported "the release package has an empty installer."
chmod +x "$INSTALLER"

# The installer drives /dev/tty itself, so it works even though stdin is this pipe.
"$INSTALLER" "$@"
