#!/bin/sh
# zeronat installer. Usage:
#   curl -fsSL https://raw.githubusercontent.com/paltaio/zeronat/main/install.sh | sh -s -- [options]
#
#   --server | --client      side to install on this machine
#   --method docker|systemd  install method (default: docker if present, else systemd)
#   --ports "443/tcp 80/tcp 51820/udp"
#   --control PORT           tunnel control port (default 2222)
#   --secret SECRET          shared secret (default: generated)
#   --server-addr HOST[:PORT] (client only) where the server is reachable
#   -y, --yes                no prompts; fail if a required value is missing
#   -h, --help
#
# With no options it runs interactively.
set -eu

REPO="paltaio/zeronat"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
RAW_URL="${RAW_BASE}/install.sh"
IMAGE="ghcr.io/${REPO}:latest"
RELEASE_BASE="https://github.com/${REPO}/releases/latest/download"
ETC_DIR="/etc/zeronat"
ENV_FILE="${ETC_DIR}/zeronat.env"
BIN_PATH="/usr/local/bin/zeronat"
UNIT="/etc/systemd/system/zeronat.service"

MODE=""; METHOD=""; DEPLOY=""; SECRET=""; CONTROL="2222"; PORTS=""; SERVER_ADDR=""; ASSUME_YES=""

say()  { printf '%s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }
has_tty() { ( : >/dev/tty ) 2>/dev/null; }

usage() {
  cat <<'EOF'
zeronat installer

  curl -fsSL https://raw.githubusercontent.com/paltaio/zeronat/main/install.sh | sh -s -- [options]

  --server | --client       side to install on this machine
  --method docker|systemd   install method (default: docker if present, else systemd)
  --deploy compose|run      (docker only) compose file or plain docker run
  --ports "443/tcp 80/tcp 51820/udp"
  --control PORT            tunnel control port (default 2222)
  --secret SECRET           shared secret (default: generated)
  --server-addr HOST[:PORT] (client only) where the server is reachable
  -y, --yes                 no prompts; fail if a required value is missing
  -h, --help

With no options it runs interactively.
EOF
}

prompt() { # prompt "text" "default" -> echoes answer (default when no TTY)
  _def="$2"
  if ! has_tty; then printf '%s' "$_def"; return; fi
  if [ -n "$_def" ]; then printf '%s [%s]: ' "$1" "$_def" >/dev/tty
  else printf '%s: ' "$1" >/dev/tty; fi
  IFS= read -r _a </dev/tty || _a=""
  [ -z "$_a" ] && _a="$_def"
  printf '%s' "$_a"
}

gen_secret() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
  else head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

pub_ip() {
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    _ip=$(curl -fsSL --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]') || _ip=""
    [ -n "$_ip" ] && { printf '%s' "$_ip"; return; }
  done
  printf 'YOUR_SERVER_IP'
}

# run a command as root (via sudo when needed)
if [ "$(id -u)" = 0 ]; then run() { "$@"; }
elif command -v sudo >/dev/null 2>&1; then run() { sudo "$@"; }
else run() { err "need root: install as root or install sudo"; }; fi

arch_target() { # map uname -m to a release target triple (static musl where available)
  case "$(uname -m)" in
    x86_64|amd64)   echo x86_64-unknown-linux-musl ;;
    aarch64|arm64)  echo aarch64-unknown-linux-musl ;;
    armv7l)         echo armv7-unknown-linux-musleabihf ;;
    armv6l)         echo arm-unknown-linux-musleabihf ;;
    mips)           echo mips-unknown-linux-gnu ;;
    mipsel)         echo mipsel-unknown-linux-gnu ;;
    mips64)         echo mips64-unknown-linux-gnuabi64 ;;
    mips64el)       echo mips64el-unknown-linux-gnuabi64 ;;
    *) err "unsupported arch '$(uname -m)': use --method docker or install the binary manually" ;;
  esac
}

# --- parse args -------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --server) MODE=server ;;
    --client) MODE=client ;;
    --method) METHOD="${2:-}"; shift ;;
    --deploy) DEPLOY="${2:-}"; shift ;;
    --secret) SECRET="${2:-}"; shift ;;
    --control) CONTROL="${2:-}"; shift ;;
    --ports) PORTS="${2:-}"; shift ;;
    --server-addr|--addr) SERVER_ADDR="${2:-}"; shift ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) err "unknown option: $1 (try --help)" ;;
  esac
  shift
done

say "zeronat installer"

# --- mode -------------------------------------------------------------------
if [ -z "$MODE" ]; then
  _m=$(prompt "Install [s]erver (public host) or [c]lient (behind CG-NAT)?" "")
  case "$_m" in s|S|server) MODE=server ;; c|C|client) MODE=client ;;
    *) err "choose server or client (--server / --client)" ;; esac
fi

# --- method -----------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then HAVE_DOCKER=1; else HAVE_DOCKER=""; fi
if [ -z "$METHOD" ]; then
  if [ -n "$HAVE_DOCKER" ]; then _dm=docker; else _dm=systemd; fi
  if [ -n "$HAVE_DOCKER" ]; then
    say "Docker detected. Install methods: docker, systemd."
  else
    say "Docker not found. Install methods: systemd (downloads a static binary), docker."
  fi
  METHOD=$(prompt "Install method (docker/systemd)" "$_dm")
fi
case "$METHOD" in docker|systemd) ;; *) err "method must be docker or systemd" ;; esac
[ "$METHOD" = docker ] && [ -z "$HAVE_DOCKER" ] && err "docker not installed; use --method systemd"

# --- deploy style (docker only) ---------------------------------------------
DC=""
if [ "$METHOD" = docker ]; then
  [ -z "$DEPLOY" ] && DEPLOY=$(prompt "Deploy with docker compose or plain docker run? (compose/run)" "compose")
  case "$DEPLOY" in compose|run) ;; *) err "deploy must be compose or run" ;; esac
  if [ "$DEPLOY" = compose ]; then
    if docker compose version >/dev/null 2>&1; then DC="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
    else say "docker compose not found; using docker run."; DEPLOY=run; fi
  fi
fi

# --- ports ------------------------------------------------------------------
[ -z "$PORTS" ] && PORTS=$(prompt "Ports to forward, space separated as PORT/PROTO (e.g. 443/tcp 80/tcp 51820/udp)" "")
[ -z "$PORTS" ] && err "no ports given"
ZN_ARGS=""
for p in $PORTS; do
  num=${p%/*}; proto=${p#*/}
  case "$num" in ''|*[!0-9]*) err "bad port in '$p'" ;; esac
  case "$proto" in
    tcp) ZN_ARGS="$ZN_ARGS --tcp $num" ;;
    udp) ZN_ARGS="$ZN_ARGS --udp $num" ;;
    *) err "bad protocol in '$p' (use tcp or udp)" ;;
  esac
done

# --- server address (client) ------------------------------------------------
if [ "$MODE" = client ]; then
  [ -z "$SERVER_ADDR" ] && SERVER_ADDR=$(prompt "Server address (HOST or HOST:PORT)" "")
  [ -z "$SERVER_ADDR" ] && err "client needs --server-addr HOST[:PORT]"
  case "$SERVER_ADDR" in *:*) ;; *) SERVER_ADDR="${SERVER_ADDR}:${CONTROL}" ;; esac
  CONTROL=${SERVER_ADDR##*:}
fi

# --- secret -----------------------------------------------------------------
[ -z "$SECRET" ] && SECRET=$(gen_secret)

# --- subcommand -------------------------------------------------------------
if [ "$MODE" = server ]; then
  SUBCMD="server --control $CONTROL$ZN_ARGS"
else
  SUBCMD="client --server $SERVER_ADDR$ZN_ARGS"
fi

# --- summary + confirm ------------------------------------------------------
say ""
say "Plan:"
info "side:    $MODE"
info "method:  $METHOD"
[ "$METHOD" = docker ] && info "deploy:  $DEPLOY"
info "ports:   $PORTS"
[ "$MODE" = client ] && info "server:  $SERVER_ADDR"
info "control: $CONTROL"
info "secret:  $SECRET"
say ""
if [ -z "$ASSUME_YES" ] && has_tty; then
  _ok=$(prompt "Proceed? (y/n)" "y")
  case "$_ok" in y|Y|yes) ;; *) err "aborted" ;; esac
fi

# --- write env --------------------------------------------------------------
run mkdir -p "$ETC_DIR"
if [ "$METHOD" = docker ] && [ "$DEPLOY" = compose ]; then
  # compose reads .env from the project dir for ${ZERONAT_*} and as the container env_file
  { printf 'ZERONAT_SECRET=%s\n' "$SECRET"; printf 'ZERONAT_ARGS=%s\n' "$SUBCMD"; } \
    | run tee "$ETC_DIR/.env" >/dev/null
  run chmod 600 "$ETC_DIR/.env"
else
  printf 'ZERONAT_SECRET=%s\n' "$SECRET" | run tee "$ENV_FILE" >/dev/null
  run chmod 600 "$ENV_FILE"
fi

# --- install ----------------------------------------------------------------
RAN=""
if [ "$METHOD" = docker ]; then
  run docker rm -f zeronat >/dev/null 2>&1 || true

  if [ "$DEPLOY" = compose ]; then
    COMPOSE_FILE="$ETC_DIR/compose.yml"
    _c=$(curl -fsSL "$RAW_BASE/compose.yml") || err "could not fetch compose.yml"
    printf '%s\n' "$_c" | run tee "$COMPOSE_FILE" >/dev/null
    DCF="$DC -f $COMPOSE_FILE --project-directory $ETC_DIR"
    RAN="$DCF up -d   # edit $ETC_DIR/.env to change ports/secret"
    # shellcheck disable=SC2086
    run $DCF pull
    # shellcheck disable=SC2086
    run $DCF up -d
    say "Started via compose ($COMPOSE_FILE)."
    MANAGE="$DCF logs -f    # status: $DCF ps"
  else
    RAN="docker run -d --name zeronat --restart unless-stopped --network host --env-file $ENV_FILE $IMAGE $SUBCMD"
    run docker pull "$IMAGE"
    # shellcheck disable=SC2086
    run $RAN
    say "Started container 'zeronat'."
    MANAGE="docker logs -f zeronat    # status: docker ps"
  fi
else
  TARGET=$(arch_target)
  say "Downloading zeronat ($TARGET) ..."
  TMP=$(mktemp -d)
  curl -fsSL "$RELEASE_BASE/zeronat-$TARGET.tar.gz" -o "$TMP/z.tgz" \
    || err "download failed (no release asset for $TARGET?)"
  tar -xzf "$TMP/z.tgz" -C "$TMP"
  run install -m 0755 "$TMP/zeronat" "$BIN_PATH"
  rm -rf "$TMP"
  cat <<EOF | run tee "$UNIT" >/dev/null
[Unit]
Description=zeronat $MODE
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_PATH $SUBCMD
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  run systemctl daemon-reload
  run systemctl enable --now zeronat
  say "Enabled systemd service 'zeronat'."
  MANAGE="systemctl status zeronat    # logs: journalctl -u zeronat -f"
fi

# --- next step: command for the other machine -------------------------------
say ""
if [ -n "$RAN" ]; then
  say "Ran:"
  info "$RAN"
fi
say "Done. Manage it with:"
info "$MANAGE"
say ""
if [ "$MODE" = server ]; then
  HOST=$(pub_ip)
  say "Run this on the machine behind CG-NAT (the client):"
  say "  curl -fsSL $RAW_URL | sh -s -- \\"
  say "    --client --server-addr $HOST:$CONTROL --secret $SECRET --ports \"$PORTS\""
  [ "$HOST" = YOUR_SERVER_IP ] && info "(replace YOUR_SERVER_IP with this host's public address)"
else
  say "Make sure the server runs with the SAME secret and ports:"
  say "  curl -fsSL $RAW_URL | sh -s -- \\"
  say "    --server --control $CONTROL --secret $SECRET --ports \"$PORTS\""
fi
