# znpppoe

Spawn N userspace PPPoE sessions over a single zeronat tunnel and expose each one
as a SOCKS5 egress. The PPP link, IP assignment, and TCP/IP stack all run in this
process; nothing touches the kernel, so the container needs no `NET_ADMIN` and no
`/dev/net/tun`.

A zeronat server bridges the tunnel to the real PPPoE segment (`zeronat server
--tap <nic>` on a NIC that reaches the BRAS). Each session negotiates its own
PPPoE session with a distinct MAC and gets its own ISP-assigned IP; inbound L2
frames are demultiplexed back to the right session by destination MAC.

## Run

```
docker build -f crates/znpppoe/Dockerfile -t znpppoe .

docker run --rm -p 127.0.0.1:1080:1080 \
  -e ZN_SECRET=0000 \
  -e ZN_USER=someuser -e ZN_PASSWORD=somepassword \
  -e ZN_PROXY_USER=proxy -e ZN_PROXY_PASS=proxypass \
  znpppoe --host 192.168.1.100:2222 --connections 50 --socks-listen 0.0.0.0:1080
```

The default bind is `127.0.0.1`; the container needs `0.0.0.0` so Docker can
reach it, so publish it only to the host loopback (`-p 127.0.0.1:1080:1080`).
Exposing it on a public interface makes it an egress relay over your
ISP-attributable IPs, gated only by the proxy password.

Clients authenticate with `ZN_PROXY_PASS`; the username selects the egress
session:

```
curl --socks5 proxy_pppoe0:proxypass@127.0.0.1:1080 https://ifconfig.me
curl --socks5 proxy_pppoe7:proxypass@127.0.0.1:1080 https://ifconfig.me
```

`_pppoe0` egresses through session 0, `_pppoe7` through session 7, each with its
own ISP IP.

## Flags and environment

- `--host IP:PORT` zeronat server control endpoint (or `--dht`).
- `--connections N` number of PPPoE sessions (default 1).
- `--socks-listen ADDR` SOCKS5 bind address (default `127.0.0.1:1080`).
- `--pppoe-mtu N` requested PPP MTU (default 1492).
- `ZN_SECRET` tunnel secret.
- `ZN_USER`/`ZN_PASSWORD` PPPoE login; `ZN_SERVICE` optional PPPoE service name.
- `ZN_PROXY_USER`/`ZN_PROXY_PASS` SOCKS5 credentials (separate from the PPPoE
  login).

## Limits

- Running N sessions on one credential only works if the ISP permits concurrent
  PPPoE sessions for that login; otherwise give each session its own credential.
- Pass `--dht` instead of `--host` to find the server by DHT (derived from
  `ZN_SECRET`, the same identity the server announces under).
- Domain SOCKS targets are resolved with the container's resolver, so the DNS
  lookup does not carry the PPPoE source address (the TCP egress does). The
  `scratch` image carries no `/etc/resolv.conf`, so domain resolution relies on
  the runtime injecting one (Docker does); IP targets work regardless.
