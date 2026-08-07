#!/bin/sh
# Runs get.sh against a local file:// mirror and proves it executes a verified
# installer and refuses every tampered or unverifiable download.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

SITE="$WORK/site"
MARKER="$WORK/ran"
mkdir -p "$SITE"

cat > "$WORK/installer" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > "$MARKER"
EOF

TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
armv7-unknown-linux-musleabihf arm-unknown-linux-musleabihf \
mips-unknown-linux-gnu mipsel-unknown-linux-gnu \
mips64-unknown-linux-gnuabi64 mips64el-unknown-linux-gnuabi64"

reset_site() {
  rm -f "$SITE"/* "$MARKER"
  for t in $TARGETS; do
    cp "$WORK/installer" "$SITE/zeronat-installer-$t"
  done
  (cd "$SITE" && sha256sum zeronat-installer-* > SHA256SUMS)
}

run_get() {
  ZERONAT_BASE="file://$SITE" sh "$ROOT/get.sh" "$@"
}

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

refused() {
  if run_get >/dev/null 2>&1; then
    fail "$1 was accepted"
  fi
  [ ! -e "$MARKER" ] || fail "$1 was executed"
}

# A verified installer runs and receives the launcher's arguments.
reset_site
run_get --dry-run >/dev/null 2>&1 || fail "a verified installer was refused"
[ "$(cat "$MARKER")" = "--dry-run" ] || fail "the installer did not receive its arguments"

# A tampered installer is refused before it runs.
reset_site
for t in $TARGETS; do
  printf 'tampered' >> "$SITE/zeronat-installer-$t"
done
refused "a tampered installer"

# A mirror without checksums is refused.
reset_site
rm "$SITE/SHA256SUMS"
refused "a download without checksums"

# A checksums file with no entry for this machine is refused.
reset_site
digest=$(sha256sum "$WORK/installer")
digest=${digest%% *}
printf '%s  zeronat-installer-elsewhere\n' "$digest" > "$SITE/SHA256SUMS"
refused "a download with no matching checksum"

# Duplicate entries for one installer are refused.
reset_site
cat "$SITE/SHA256SUMS" "$SITE/SHA256SUMS" > "$WORK/doubled"
mv "$WORK/doubled" "$SITE/SHA256SUMS"
refused "a checksums file with duplicate entries"

# A malformed digest is refused.
reset_site
for t in $TARGETS; do
  printf 'deadbeef  zeronat-installer-%s\n' "$t"
done > "$SITE/SHA256SUMS"
refused "a malformed checksum"

echo "get_sh.sh: all checks passed"
