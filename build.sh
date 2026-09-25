#!/usr/bin/env bash
set -euo pipefail

# Minimal static release builds via nightly build-std.
# Usage: ./build.sh [target-triple ...]   (defaults to a musl target for the host arch)
# Cross targets need a matching linker installed; for multi-arch use Docker buildx.

export RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none -Zunstable-options -Cpanic=immediate-abort -Cforce-unwind-tables=no --cfg curve25519_dalek_backend=\"serial\""

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=("$(rustc -vV | sed -n 's/^host: //p' | sed 's/-gnu$/-musl/')")
fi

musl_flags="-Crelocation-model=static -Ctarget-feature=+crt-static -Clinker-features=+lld -Clink-self-contained=+linker -Clink-arg=-Wl,--icf=all -Clink-arg=-Wl,--build-id=none -Clink-arg=-Wl,-z,noseparate-code -Clink-arg=-Wl,--no-eh-frame-hdr -Clink-arg=-Wl,-O2"
base_flags="$RUSTFLAGS"

for t in "${targets[@]}"; do
  RUSTFLAGS="$base_flags"
  case "$t" in
    *-musl*) RUSTFLAGS="$RUSTFLAGS $musl_flags" ;;
  esac
  if [ "$t" = armv7-unknown-linux-musleabihf ]; then
    RUSTFLAGS="$RUSTFLAGS -Ctarget-feature=+thumb-mode"
  fi
  export RUSTFLAGS
  cargo +nightly build \
    -Z build-std=std,panic_abort \
    -Z build-std-features=optimize_for_size \
    --target "$t" --release
  bin="target/$t/release/zeronat"
  printf '%s  %s bytes\n' "$t" "$(stat -c%s "$bin")"
done
