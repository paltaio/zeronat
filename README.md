# zeronat

Minimal encrypted reverse tunnel for services behind CG-NAT. Single static Rust binary, TCP + UDP, Noise-encrypted.

You have a service behind CG-NAT (home/office) and a cheap cloud VM with a public IP. zeronat exposes your local ports through the VM without creating accounts, no third-party services, just a VPS.

The server runs on the public host. The client runs behind NAT, dials out, and holds one control connection. A hit on a public port is forwarded to the matching local service on the client. Every connection is Noise-encrypted (`NNpsk0`, X25519 + ChaCha20-Poly1305 + BLAKE2s) from a shared secret.

## Install

```bash
curl -fsSL https://paltaio.github.io/zeronat/get.sh | sh
```

Picks Docker or a systemd service, generates the secret, asks what to forward, and prints the command to run behind CG-NAT.

## Usage

```bash
# Generate this once, then copy the same value to both hosts.
SEED="$(openssl rand -hex 32)"

# On the public host:
ZERONAT_SEED="$SEED" zeronat server --control 2222 --client home --tcp 443 --udp 51820

# Behind CG-NAT:
ZERONAT_SEED="$SEED" zeronat client --server <public-ip>:2222 --id home --tcp 443 --udp 51820
```

The seed derives every credential: the network secret, the admin secret, the discovery credential, and one credential per client id, so `--client home` on the server and `--id home` on the client agree with nothing else copied. The server accepts only clients it holds a credential for; `--client <id>` is repeatable and the config file takes `[[clients]]` entries. Ids and credentials must both be unique.

A value set on its own wins over the seed: `ZERONAT_SECRET`, `--client <id>:<64-HEX>` (or `ZERONAT_CLIENT_ID` with `ZERONAT_CLIENT_SECRET`), `ZERONAT_ADMIN_SECRET`, `ZERONAT_DISCOVERY_SECRET`. To keep the seed off a client, run `zeronat derive-client <id>` on the server. It prints `ZERONAT_SECRET` and `ZERONAT_CLIENT_SECRET` lines for that client, and `ZERONAT_DISCOVERY_SECRET` with `--dht`; start the client with those in its environment in place of the seed.

`--tcp 443` maps to `127.0.0.1:443`. Remap with `--tcp 443:10.0.0.5:443`; `--udp` works the same. Specs take `+` modifiers: `--tcp 443+proxy` hands the target the real client address in a PROXY protocol v2 header (`--proxy` enables it on every TCP forward), and `+idle=SECS` tunes the per-forward idle window. Open the control port (2222, UDP and TCP) on the server's firewall.

What a service behind zeronat sees, and the PROXY protocol cutover, are covered at https://paltaio.github.io/zeronat/#transparency and https://paltaio.github.io/zeronat/#proxy.

Routing, all-ports forwarding, the TAP bridge, DHT discovery, and the full CLI live at https://paltaio.github.io/zeronat/.

## Release

Bump `version` under `[workspace.package]` in `Cargo.toml` and run `cargo test --workspace` so `Cargo.lock` follows. The tag must match that version; the release workflow checks it.

```bash
git commit Cargo.toml Cargo.lock -m "chore: release v0.27.0"
git tag v0.27.0
git push origin main v0.27.0
```

The tag publishes the release binaries and both images, `ghcr.io/paltaio/zeronat` and `ghcr.io/paltaio/znpppoe`, at `0.27.0`, `0.27`, and `latest`. Pushes to main move `znpppoe:edge`.

## License

MIT, Copyright (c) 2026 Palta Studios. See [LICENSE](LICENSE).
