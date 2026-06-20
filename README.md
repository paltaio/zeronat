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
# On the public host:
ZERONAT_SECRET=somelongsecret zeronat server --control 2222 --tcp 443 --udp 51820

# Behind CG-NAT:
ZERONAT_SECRET=somelongsecret zeronat client --server <public-ip>:2222 --tcp 443 --udp 51820
```

`--tcp 443` maps to `127.0.0.1:443`. Remap with `--tcp 443:10.0.0.5:443`; `--udp` works the same. Open the control port (2222, UDP and TCP) on the server's firewall.

Routing, all-ports forwarding, the TAP bridge, DHT discovery, and the full CLI live at https://paltaio.github.io/zeronat/.

## License

MIT, Copyright (c) 2026 Palta Studios. See [LICENSE](LICENSE).
