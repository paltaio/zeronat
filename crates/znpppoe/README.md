# znpppoe

Spawn N userspace PPPoE sessions over a single zeronat tunnel and expose each one
as a SOCKS5 and HTTP CONNECT egress. The PPP link, IP assignment, and TCP/IP stack
all run in this process; nothing touches the kernel, so the container needs no
`NET_ADMIN` and no `/dev/net/tun`.

A zeronat server bridges the tunnel to the real PPPoE segment (`zeronat server
--tap <nic>` on a NIC that reaches the BRAS). Each session negotiates its own
PPPoE session with a distinct MAC and gets its own ISP-assigned IP; inbound L2
frames are demultiplexed back to the right session by destination MAC.

## Run

```
docker build -f crates/znpppoe/Dockerfile -t znpppoe .

docker run --rm -p 127.0.0.1:1080:1080 -p 127.0.0.1:8081:8081 \
  -e ZN_SECRET=0000 \
  -e ZN_USER=someuser -e ZN_PASSWORD=somepassword \
  -e ZN_PROXY_USER=proxy -e ZN_PROXY_PASS=proxypass \
  znpppoe --host 192.168.1.100:2222 --connections 50 \
  --socks-listen 0.0.0.0:1080 --http-listen 0.0.0.0:8081
```

Both proxies bind `127.0.0.1` by default; the container needs `0.0.0.0` so Docker
can reach it, so publish only to the host loopback. Exposing either on a public
interface makes it an egress relay over your ISP-attributable IPs, gated only by
the proxy password.

Two front ends, same auth: SOCKS5 (for clients that speak SOCKS) and HTTP CONNECT
(for the many HTTP clients that do not). Clients authenticate with `ZN_PROXY_PASS`
(the HTTP proxy via `Proxy-Authorization: Basic`); the username picks the egress:

- `proxy` round-robins over the live sessions, one IP per connection.
- `proxy_pppoe<K>` pins session K (a specific ISP IP).
- `proxy_s<token>` is sticky: the same token always maps to the same session, so a
  job's connections share one IP. Vary the token to spread jobs across IPs.

```
curl --socks5 proxy:proxypass@127.0.0.1:1080 https://ifconfig.me        # socks, rotates
curl --proxy http://proxy_sjob42:proxypass@127.0.0.1:8081 https://ifconfig.me  # http, sticky
```

## Flags and environment

- `--host IP:PORT` zeronat server control endpoint (or `--dht`).
- `--connections N` number of PPPoE sessions (default 1).
- `--socks-listen ADDR` SOCKS5 bind address (default `127.0.0.1:1080`).
- `--http-listen ADDR` HTTP CONNECT bind address (default `127.0.0.1:8081`).
- `--pppoe-mtu N` requested PPP MTU (default 1280; raise it only on an underlay with a larger usable MTU).
- `--sock-rx KIB` per-connection TCP receive buffer (default 256); it sets the advertised window, so raise it for high bandwidth-delay paths. Below 64 disables window scaling.
- `--sock-tx KIB` per-connection TCP send buffer (default 64).
- `--max-conns N` ceiling on concurrent proxied connections (default 1024); bounds total buffer memory.
- `ZN_SECRET` tunnel secret.
- `ZN_USER`/`ZN_PASSWORD` PPPoE login; `ZN_SERVICE` optional PPPoE service name.
- `ZN_PROXY_USER`/`ZN_PROXY_PASS` proxy credentials (separate from the PPPoE
  login).

## Limits

- Running N sessions on one credential only works if the ISP permits concurrent
  PPPoE sessions for that login; otherwise give each session its own credential.
- Pass `--dht` instead of `--host` to find the server by DHT (derived from
  `ZN_SECRET`, the same identity the server announces under).
- Domain targets are resolved with the container's resolver, so the DNS lookup
  does not carry the PPPoE source address (the TCP egress does). The
  `scratch` image carries no `/etc/resolv.conf`, so domain resolution relies on
  the runtime injecting one (Docker does); IP targets work regardless.
