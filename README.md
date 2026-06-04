# zeronat

Minimal encrypted reverse tunnel for services behind CG-NAT. Single static Rust binary, TCP + UDP, Noise-encrypted.

The server runs on a host with a public IP. The client runs behind NAT, dials out, and holds one control connection. Traffic hitting a public port on the server is forwarded to the matching local service on the client. Every connection is authenticated and encrypted with Noise (`NNpsk0`, X25519 + ChaCha20-Poly1305 + BLAKE2s) from a shared secret.

## Usage

```bash
# On the public host:
ZERONAT_SECRET=somelongsecret zeronat server \
  --control 2222 --tcp 443 --tcp 80 --udp 51820

# On the host behind CG-NAT:
ZERONAT_SECRET=somelongsecret zeronat client \
  --server <public-ip>:2222 --tcp 443 --tcp 80 --udp 51820
```

`--tcp 443` maps to `127.0.0.1:443`. Remap with `--tcp 443:127.0.0.1:8443` or point elsewhere with `--tcp 443:10.0.0.5:443`. `--udp` works the same way. The secret can be passed with `--secret` instead of the env var. Open the control port on the server's firewall.

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
