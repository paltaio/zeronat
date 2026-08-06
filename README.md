# zeronat

Encrypted reverse tunnel for services behind CG-NAT. Single Rust binary, TCP and UDP, Noise-encrypted.

zeronat exposes services behind CG-NAT through a public Linux host. It needs no account or hosted control plane.

The server runs on the public host. The client dials out from behind NAT and holds one control connection. Traffic on a public port is forwarded to the matching local service. Noise authenticates and encrypts each connection. The server keeps its private identity secret, each client has its own credential, and remote administration uses a separate secret.

## Install

```bash
curl -fsSL https://paltaio.github.io/zeronat/get.sh | sh
```

The installer configures Docker or systemd, generates 32-byte credentials, and prints a client enrollment command. The launcher verifies the signed release manifest and installer digest before running the downloaded binary.

## Usage

```bash
# On the public host:
curl -fsSL https://paltaio.github.io/zeronat/get.sh | \
  sh -s -- --server --ports "443/tcp 51820/udp" -y

# On the host behind CG-NAT, run the enrollment command printed above.
# Enter ZERONAT_CLIENT_SECRET from the server's /etc/zeronat/.env when prompted.
```

Every secret and public identity is exactly 64 hexadecimal characters encoding 32 bytes. `--tcp 443` maps to `127.0.0.1:443`. Remap with `--tcp 443:10.0.0.5:443`; `--udp` works the same. Specs take `+` modifiers: `--tcp 443+proxy` sends a PROXY protocol v2 header to the target, and `+idle=SECS` sets the per-forward idle window. Open the control port (2222, UDP and TCP) on the server firewall.

What a service behind zeronat sees, and the PROXY protocol cutover, are covered at https://paltaio.github.io/zeronat/#transparency and https://paltaio.github.io/zeronat/#proxy.

Routing, all-ports forwarding, TAP, DHT discovery, container privileges, verified upgrades, and the full CLI are documented at https://paltaio.github.io/zeronat/.

## License

MIT, Copyright (c) 2026 Palta Studios. See [LICENSE](LICENSE).
