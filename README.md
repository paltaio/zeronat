# zeronat

Minimal encrypted reverse tunnel for services behind CG-NAT. Single static Rust binary, TCP + UDP, Noise-encrypted.

**Usecase**: You have a service behind CG-NAT (home/office) and a cheap cloud VM with a public IP. zeronat exposes your local ports through the VM without creating accounts, no third-party services, just a VPS.

The server runs on a host with a public IP. The client runs behind NAT, dials out, and holds one control connection. Traffic hitting a public port on the server is forwarded to the matching local service on the client. Every connection is authenticated and encrypted with Noise (`NNpsk0`, X25519 + ChaCha20-Poly1305 + BLAKE2s) from a shared secret.

The tunnel runs over UDP/KCP by default, falling back to TCP when the UDP handshake gets no reply. Both share port 2222.

## Install

On the public host (interactive, or pass flags):

```bash
curl -fsSL https://raw.githubusercontent.com/paltaio/zeronat/main/install.sh | sh -s -- --server
```

It picks Docker or a systemd service, generates the secret, asks which ports to forward, and prints the matching command to run on the machine behind CG-NAT. Run `install.sh --help` for all options.

## Usage

```bash
# On the public host:
ZERONAT_SECRET=somelongsecret zeronat server \
  --control 2222 --tcp 443 --tcp 80 --udp 51820

# On the host behind CG-NAT:
ZERONAT_SECRET=somelongsecret zeronat client \
  --server <public-ip>:2222 --tcp 443 --tcp 80 --udp 51820
```

`--tcp 443` maps to `127.0.0.1:443`. Remap with `--tcp 443:127.0.0.1:8443` or point elsewhere with `--tcp 443:10.0.0.5:443`. `--udp` works the same way. The secret can be passed with `--secret` instead of the env var. The client picks the transport with `--transport auto|udp|tcp` (default `auto`). Open the control port (2222 UDP and TCP) on the server's firewall.

## L2 bridge (TAP)

`--tap` relays raw Ethernet frames over the tunnel, joining a TAP on each end into one L2 segment. Carries anything Ethernet, including PPPoE. Both ends need `--tap`; it cannot be combined with `--tcp`/`--udp`.

```bash
# Near the target segment (e.g. the PPPoE concentrator):
ZERONAT_SECRET=s zeronat server --control 2222 --tap zn0 --bridge br0
# Behind CG-NAT, then run e.g. pppd on zn0:
ZERONAT_SECRET=s zeronat client --server <public-ip>:2222 --tap zn0
pppd plugin rp-pppoe.so zn0 user <user>
```

`--bridge <name>` enslaves the TAP to an existing bridge; `--tap-mtu <n>` sets the MTU (default 1400). Needs `CAP_NET_ADMIN`: root, `setcap cap_net_admin+ep zeronat`, or Docker `--cap-add NET_ADMIN --device /dev/net/tun` (plus `--device /dev/ppp` for pppd).

## Build

```bash
cargo build --release    # dynamic binary
./build.sh               # static musl binary, smallest
```

`build.sh` uses the nightly toolchain (`rust-src` component) for a size-optimized static build.

```bash
docker pull ghcr.io/paltaio/zeronat
```

## Scope

Built for a single operator with one shared secret. It is not hardened against a hostile public internet: no connection rate limiting, unbounded session tracking, and a naive single-client control channel.

## License

MIT, Copyright (c) 2026 Palta Studios. See [LICENSE](LICENSE).
