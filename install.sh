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
#   --dht                    find the server over the DHT instead of a fixed address
#   --announce-ip IP         (server, with --dht) public IPv4 to announce
#   --announce-port PORT     (server, with --dht) public port to announce
#   --tap NAME               L2 bridge instead of ports: relay raw Ethernet (Linux)
#   --bridge NAME            (with --tap) enslave the TAP to this existing bridge
#   --tap-mtu N              (with --tap) TAP MTU (default 1400)
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
USE_DHT=""; ANNOUNCE_IP=""; ANNOUNCE_PORT=""; TAP=""; BRIDGE=""; TAP_MTU=""; KIND=""

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
  --dht                     find the server over the DHT (dynamic IP, no fixed address)
  --announce-ip IP          (server, with --dht) public IPv4 to announce
  --announce-port PORT      (server, with --dht) public port to announce
  --tap NAME                L2 bridge instead of ports: relay raw Ethernet/PPPoE (Linux)
  --bridge NAME             (with --tap) enslave the TAP to this existing bridge
  --tap-mtu N               (with --tap) TAP MTU (default 1400)
  -y, --yes                 no prompts; fail if a required value is missing
  -h, --help

With no options it runs interactively. Ports and --tap are mutually exclusive.
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

# Read a secret already on disk so re-running the installer does not silently
# rotate it (which would break every client). Reads through `run` because the
# env file is mode 600, and checks both layouts (compose .env and run/systemd).
existing_secret() {
  for _f in "$ETC_DIR/.env" "$ENV_FILE"; do
    [ -f "$_f" ] || continue
    _s=$(run cat "$_f" 2>/dev/null | sed -n 's/^ZERONAT_SECRET=//p' | head -n1)
    [ -n "$_s" ] && { printf '%s' "$_s"; return 0; }
  done
  return 1
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
    --dht) USE_DHT=1 ;;
    --announce-ip) ANNOUNCE_IP="${2:-}"; shift ;;
    --announce-port) ANNOUNCE_PORT="${2:-}"; shift ;;
    --tap) TAP="${2:-}"; shift ;;
    --bridge) BRIDGE="${2:-}"; shift ;;
    --tap-mtu) TAP_MTU="${2:-}"; shift ;;
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

# --- tunnel kind: forward ports or bridge raw Ethernet (TAP) ----------------
if [ -n "$TAP" ]; then KIND=bridge
elif [ -n "$PORTS" ]; then KIND=ports
else
  _t=$(prompt "Tunnel [p]orts (TCP/UDP) or L2 [b]ridge (raw Ethernet/PPPoE, Linux only)?" "p")
  case "$_t" in b|B|bridge) KIND=bridge; TAP=$(prompt "TAP device name" "zn0") ;; *) KIND=ports ;; esac
fi

ZN_ARGS=""
if [ "$KIND" = bridge ]; then
  [ -z "$TAP" ] && err "no TAP device name given"
  ZN_ARGS=" --tap $TAP"
  [ -n "$BRIDGE" ] && ZN_ARGS="$ZN_ARGS --bridge $BRIDGE"
  [ -n "$TAP_MTU" ] && ZN_ARGS="$ZN_ARGS --tap-mtu $TAP_MTU"
else
  [ -z "$PORTS" ] && PORTS=$(prompt "Ports to forward, space separated as PORT/PROTO (e.g. 443/tcp 80/tcp 51820/udp)" "")
  [ -z "$PORTS" ] && err "no ports given"
  for p in $PORTS; do
    num=${p%/*}; proto=${p#*/}
    case "$num" in ''|*[!0-9]*) err "bad port in '$p'" ;; esac
    case "$proto" in
      tcp) ZN_ARGS="$ZN_ARGS --tcp $num" ;;
      udp) ZN_ARGS="$ZN_ARGS --udp $num" ;;
      *) err "bad protocol in '$p' (use tcp or udp)" ;;
    esac
  done
fi

# --- discovery: fixed address or DHT ----------------------------------------
if [ "$MODE" = client ]; then
  if [ -z "$USE_DHT" ] && [ -z "$SERVER_ADDR" ]; then
    _d=$(prompt "Find the server by [a]ddress or [d]ht discovery (dynamic IP)?" "a")
    case "$_d" in d|D|dht) USE_DHT=1 ;; esac
  fi
  if [ -z "$USE_DHT" ]; then
    [ -z "$SERVER_ADDR" ] && SERVER_ADDR=$(prompt "Server address (HOST or HOST:PORT)" "")
    [ -z "$SERVER_ADDR" ] && err "client needs --server-addr HOST[:PORT] or --dht"
    case "$SERVER_ADDR" in *:*) ;; *) SERVER_ADDR="${SERVER_ADDR}:${CONTROL}" ;; esac
    CONTROL=${SERVER_ADDR##*:}
  fi
elif [ "$MODE" = server ] && [ -z "$USE_DHT" ]; then
  _d=$(prompt "Also publish the address to the DHT for dynamic-IP discovery? (y/n)" "n")
  case "$_d" in y|Y|yes) USE_DHT=1 ;; esac
fi

# --- secret -----------------------------------------------------------------
# Precedence: --secret > a secret already in /etc/zeronat (a re-run must not
# rotate it and break clients) > a freshly generated one.
if [ -z "$SECRET" ]; then
  if SECRET=$(existing_secret); then
    say "reusing existing secret from $ETC_DIR"
  else
    SECRET=$(gen_secret)
  fi
fi

# --- subcommand -------------------------------------------------------------
if [ "$MODE" = server ]; then
  SUBCMD="server --control $CONTROL$ZN_ARGS"
  if [ -n "$USE_DHT" ]; then
    SUBCMD="$SUBCMD --server dht"
    [ -n "$ANNOUNCE_IP" ] && SUBCMD="$SUBCMD --announce-ip $ANNOUNCE_IP"
    [ -n "$ANNOUNCE_PORT" ] && SUBCMD="$SUBCMD --announce-port $ANNOUNCE_PORT"
  fi
elif [ -n "$USE_DHT" ]; then
  SUBCMD="client --server dht$ZN_ARGS"
else
  SUBCMD="client --server $SERVER_ADDR$ZN_ARGS"
fi

# --- summary + confirm ------------------------------------------------------
say ""
say "Plan:"
info "side:    $MODE"
info "method:  $METHOD"
[ "$METHOD" = docker ] && info "deploy:  $DEPLOY"
if [ "$KIND" = bridge ]; then
  info "bridge:  $TAP${BRIDGE:+ -> $BRIDGE}"
else
  info "ports:   $PORTS"
fi
if [ "$MODE" = client ]; then
  if [ -n "$USE_DHT" ]; then info "server:  via DHT"; else info "server:  $SERVER_ADDR"; fi
elif [ -n "$USE_DHT" ]; then
  info "discovery: DHT publish"
fi
if [ "$MODE" = server ] || [ -z "$USE_DHT" ]; then info "control: $CONTROL"; fi
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
    # The bridge template grants CAP_NET_ADMIN and /dev/net/tun, which the TAP
    # device needs; the port-forward template omits them so it starts on hosts
    # without the tun module.
    COMPOSE_SRC="compose.yml"
    [ "$KIND" = bridge ] && COMPOSE_SRC="compose.bridge.yml"
    _c=$(curl -fsSL "$RAW_BASE/$COMPOSE_SRC") || err "could not fetch $COMPOSE_SRC"
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
    DOCKER_TAP=""
    [ "$KIND" = bridge ] && DOCKER_TAP="--cap-add NET_ADMIN --device /dev/net/tun "
    RAN="docker run -d --name zeronat --restart unless-stopped --network host ${DOCKER_TAP}--env-file $ENV_FILE $IMAGE $SUBCMD"
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
  curl -fsSL "$RELEASE_BASE/zeronat-$TARGET" -o "$TMP/zeronat" \
    || err "download failed (no release asset for $TARGET?)"
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
if [ "$KIND" = bridge ]; then FWD="--tap $TAP"; else FWD="--ports \"$PORTS\""; fi

if [ "$MODE" = server ]; then
  say "Run this on the machine behind CG-NAT (the client):"
  if [ -n "$USE_DHT" ]; then
    say "  curl -fsSL $RAW_URL | sh -s -- \\"
    say "    --client --dht --secret $SECRET $FWD"
  else
    HOST=$(pub_ip)
    say "  curl -fsSL $RAW_URL | sh -s -- \\"
    say "    --client --server-addr $HOST:$CONTROL --secret $SECRET $FWD"
    [ "$HOST" = YOUR_SERVER_IP ] && info "(replace YOUR_SERVER_IP with this host's public address)"
  fi
else
  if [ -n "$USE_DHT" ]; then SDISC="--dht"; else SDISC="--control $CONTROL"; fi
  say "Make sure the server runs with the SAME secret:"
  say "  curl -fsSL $RAW_URL | sh -s -- \\"
  say "    --server $SDISC --secret $SECRET $FWD"
fi
