#!/bin/sh
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

fixtures="$tmp/fixtures"
shim="$tmp/bin"
mkdir -p "$fixtures" "$shim"

secret="$tmp/test.key"
public="$tmp/test.pub"
minisign -G -W -s "$secret" -p "$public" >/dev/null 2>&1
wrong_secret="$tmp/wrong.key"
wrong_public="$tmp/wrong.pub"
minisign -G -W -s "$wrong_secret" -p "$wrong_public" >/dev/null 2>&1
public_base64=$(sed -n '2p' "$public")

tag=v0.25.1
platform=linux-amd64
asset="zeronat-$tag-$platform.tar"
manifest=release.manifest
signature=release.manifest.minisig
marker="$tmp/ran"

cat > "$fixtures/zeronat-installer" <<'SH'
#!/bin/sh
printf '%s\n' "$*" > "$TEST_MARKER"
SH
chmod +x "$fixtures/zeronat-installer"
cp "$fixtures/zeronat-installer" "$fixtures/zeronat"
tar --format=ustar --owner=0 --group=0 --numeric-owner --mtime='@0' \
  -cf "$fixtures/$asset" -C "$fixtures" zeronat zeronat-installer
digest=$(sha256sum "$fixtures/$asset" | awk '{print $1}')
length=$(wc -c < "$fixtures/$asset" | tr -d ' ')
printf 'zeronat-release-v2 %s\n%s\n%s\n%s %s %s\n' \
  "$tag" \
  'zeronat-image ghcr.io/paltaio/zeronat@sha256:0000000000000000000000000000000000000000000000000000000000000000' \
  'znpppoe-image ghcr.io/paltaio/znpppoe@sha256:1111111111111111111111111111111111111111111111111111111111111111' \
  "$digest" "$length" "$asset" > "$fixtures/$manifest"
sign_manifest() {
  signing_key=$1
  rm -f "$fixtures/$signature"
  minisign -S -s "$signing_key" -m "$fixtures/$manifest" \
    -x "$fixtures/$signature" -t 'zeronat get.sh test' >/dev/null
}
sign_manifest "$secret"

sed \
  -e "s|^PUBLIC_KEY=.*|PUBLIC_KEY=\"$public_base64\"|" \
  "$repo/get.sh" > "$tmp/get.sh"

cat > "$shim/uname" <<'SH'
#!/bin/sh
case "${1-}" in
  -s) printf '%s\n' Linux ;;
  -m) printf '%s\n' x86_64 ;;
  *) exit 1 ;;
esac
SH
chmod +x "$shim/uname"

cat > "$shim/curl" <<'SH'
#!/bin/sh
out=
url=
proto=
proto_redir=
max_redirs=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      out=$2
      shift 2
      ;;
    --proto)
      proto=$2
      shift 2
      ;;
    --proto-redir)
      proto_redir=$2
      shift 2
      ;;
    --max-redirs)
      max_redirs=$2
      shift 2
      ;;
    --user|-u|--header|-H|--cookie|-b|--netrc|--netrc-file|--oauth2-bearer)
      exit 90
      ;;
    --max-filesize|--max-time|--write-out|-w)
      shift 2
      ;;
    http*)
      url=$1
      shift
      ;;
    *)
      shift
      ;;
  esac
done
[ "$proto" = '=https' ] || exit 91
[ "$proto_redir" = '=https' ] || exit 92
[ "$max_redirs" = 5 ] || exit 93
case "$url" in
  https://*@*) exit 94 ;;
esac
case "$url" in
  */releases/latest)
    printf '%s' "${TEST_TAG_URL:-https://github.com/paltaio/zeronat/releases/tag/v0.25.1}"
    ;;
  *)
    source_file="$TEST_FIXTURES/${url##*/}"
    [ -f "$source_file" ] || exit 22
    cp "$source_file" "$out"
    ;;
esac
SH
chmod +x "$shim/curl"

run_get() {
  PATH="$shim:$PATH" TEST_FIXTURES="$fixtures" TEST_MARKER="$marker" \
    TEST_TAG_URL="${TEST_TAG_URL-}" \
    sh "$tmp/get.sh" "$@"
}

run_get hello
[ "$(cat "$marker")" = hello ]

rm -f "$marker"
cp "$fixtures/$asset" "$fixtures/$asset.saved"
printf 'changed\n' >> "$fixtures/$asset"
if run_get changed >/dev/null 2>&1; then
  echo "changed package was accepted" >&2
  exit 1
fi
[ ! -e "$marker" ]
mv "$fixtures/$asset.saved" "$fixtures/$asset"

mv "$fixtures/$signature" "$fixtures/$signature.saved"
if run_get missing >/dev/null 2>&1; then
  echo "missing signature was accepted" >&2
  exit 1
fi
mv "$fixtures/$signature.saved" "$fixtures/$signature"

minisign -S -l -s "$secret" -m "$fixtures/$manifest" \
  -x "$fixtures/$signature.legacy" -t 'zeronat legacy test' >/dev/null
mv "$fixtures/$signature" "$fixtures/$signature.saved"
mv "$fixtures/$signature.legacy" "$fixtures/$signature"
if run_get legacy >/dev/null 2>&1; then
  echo "legacy signature was accepted" >&2
  exit 1
fi
mv "$fixtures/$signature.saved" "$fixtures/$signature"

cp "$fixtures/$manifest" "$fixtures/$manifest.saved"
printf 'zeronat-release-v2 %s\r\n%s\r\n%s\r\n%s %s %s\r\n' \
  "$tag" \
  'zeronat-image ghcr.io/paltaio/zeronat@sha256:0000000000000000000000000000000000000000000000000000000000000000' \
  'znpppoe-image ghcr.io/paltaio/znpppoe@sha256:1111111111111111111111111111111111111111111111111111111111111111' \
  "$digest" "$length" "$asset" > "$fixtures/$manifest"
sign_manifest "$secret"
if run_get malformed >/dev/null 2>&1; then
  echo "malformed manifest was accepted" >&2
  exit 1
fi
mv "$fixtures/$manifest.saved" "$fixtures/$manifest"
sign_manifest "$secret"

sign_manifest "$wrong_secret"
if run_get wrong-key >/dev/null 2>&1; then
  echo "wrong signing key was accepted" >&2
  exit 1
fi
sign_manifest "$secret"

cp "$fixtures/$manifest" "$fixtures/$manifest.saved"
dd if=/dev/zero of="$fixtures/$manifest" bs=65537 count=1 status=none
if run_get oversized >/dev/null 2>&1; then
  echo "oversized unknown-length manifest was accepted" >&2
  exit 1
fi
mv "$fixtures/$manifest.saved" "$fixtures/$manifest"

if TEST_TAG_URL=https://github.com/paltaio/zeronat/releases/tag/v0.25.2 \
  run_get substituted >/dev/null 2>&1; then
  echo "release substitution was accepted" >&2
  exit 1
fi

if TEST_TAG_URL=https://github.com/other/zeronat/releases/tag/v0.25.1 \
  run_get wrong-origin >/dev/null 2>&1; then
  echo "wrong release origin was accepted" >&2
  exit 1
fi
