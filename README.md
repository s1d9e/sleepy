<div align="center">
# `SLEEPY`

### Covert DNS-over-HTTPS Tunnel

![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-00ff88?style=flat-square)
![Status](https://img.shields.io/badge/Status-Alpha-orange?style=flat-square)

```
  ── SLEEPY ──
  "It looks like DNS. It acts like DNS.
   But it carries your secrets."
```

</div>

---

## What it does

Sleepy is a **covert tunneling tool** that hides arbitrary TCP traffic inside DNS-over-HTTPS (DoH) queries. It masquerades as normal Cloudflare/Google DNS traffic, making it nearly invisible to network monitoring.

> **Authorized use only.** This tool is intended for authorized penetration
> testing, red-team operations, and research. Do not use it on networks you
> do not have permission to test.

## How it works

```
┌──────────┐         ┌───────────┐         ┌──────────────┐
│  Client  │──DoH──▶ │  Resolver │──DNS──▶ │   Sleepy     │
│ (tunnel) │◀──DoH── │ (CF/GG)  │◀──DNS── │   Server     │
└──────────┘         └───────────┘         └──────────────┘
   SSH/SOCKS        looks like DNS         decodes tunnel
   through DoH       to IDS/WAF             back to TCP
```

Uplink frames travel in the query NAME (DNS-safe base32 labels); downlink
frames travel in TXT records of the response. Every exchange is a valid
RFC 8484 DoH transaction.

## Features

| Feature | Description |
|---|---|
| **DoH transport** | Traffic looks like ordinary DNS-over-HTTPS queries |
| **Encrypted** | ChaCha20-Poly1305 with forward secrecy (X25519 + HKDF) |
| **Authenticated** | PSK-authenticated handshake resists MITM and replay |
| **Multiplexed** | Many TCP streams over one paced DoH cadence |
| **Burst cadence** | Mimics human browsing; no machine-regular heartbeat |
| **Decoy resolver** | Answers foreign queries like a real DNS resolver |
| **SOCKS5 proxy** | Run any TCP app through the tunnel |
| **Auto chunking** | Frames split to fit DNS name / TXT size limits |
| **Auto-reconnect** | Exponential-backoff re-handshake survives outages |
| **Length hiding** | Optional padding so record size leaks less (`-padding`) |
| **Autocert** | Let's Encrypt certs, auto-renewed (`-autocert`) |

## Architecture

```
cmd/
  server/       DoH server + decoy resolver + TCP relay
  client/       SOCKS5 local proxy over the tunnel
internal/
  crypto/       X25519 handshake, HKDF, ChaCha20-Poly1305 AEAD
  protocol/     frame mux + DNS codec (name / TXT)
  doh/          DoH transport + burst scheduler
  pad/          length-hiding padding (bucketed)
  socks/        SOCKS5 server (RFC 1928)
  tunnel/       glues DoH + mux + TCP endpoints
```

## Install

```bash
git clone https://github.com/s1d9e/sleepy.git
cd sleepy
make build          # produces bin/sleepy-server and bin/sleepy-client
```

## Usage

```bash
# Start server with a Let's Encrypt certificate (port 80 reachable for HTTP-01)
./bin/sleepy-server \
  --domain tunnel.example.com \
  --secret-key "$(openssl rand -hex 32)" \
  --listen :443 \
  --autocert --email ops@example.com

# …or with an existing certificate
./bin/sleepy-server \
  --domain tunnel.example.com \
  --secret-key "<passphrase>" \
  --listen :443 \
  --cert fullchain.pem --key privkey.pem

# Start client (add --padding to match a server started with --padding)
./bin/sleepy-client \
  --server tunnel.example.com \
  --secret-key "<same passphrase>" \
  --listen 127.0.0.1:1080

# Use as a SOCKS5 proxy
curl --socks5-hostname 127.0.0.1:1080 https://target.internal/
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@target
```

## Security notes

- The pre-shared key is a **passphrase**; it is run through HKDF to derive a
  32-byte PSK. Use a high-entropy secret.
- Each session performs an **ephemeral X25519 handshake** authenticated by
  the PSK, giving forward secrecy and mutual authentication.
- Records are sealed with **ChaCha20-Poly1305**; nonces are deterministic
  (4-byte random prefix + 64-bit counter) and records carry an anti-replay
  sequence number.
- `-padding` **must match on both sides** (it is not negotiated on the wire).
  It inflates every frame to a size bucket so an observer correlating query
  names cannot infer exact payload sizes.
- The client **auto-reconnects**: transient transport failures retry the same
  sealed record (the server's anti-replay window de-duplicates), and a dead
  session triggers a fresh handshake with exponential backoff.
- Use `-insecure` on the client **only** in a lab with a self-signed cert.

## Development

```bash
make race    # run all tests with the race detector
make vet     # go vet
make lint    # golangci-lint if installed
```

## Roadmap

- [x] DoH client/server core
- [x] ChaCha20-Poly1305 encryption layer (X25519 + HKDF, forward secrecy)
- [x] SOCKS5 proxy mode
- [x] Multiplexing (many TCP streams over one cadence)
- [x] Burst cadence with jitter (no heartbeat fingerprint)
- [x] Decoy resolver (answers foreign queries like a real resolver)
- [ ] Domain fronting support
- [ ] Auto-reconnect logic
- [ ] Traffic obfuscation (timing jitter refinement, padding profiles)
- [ ] Cloudflare Workers backend
- [ ] Docker deployment

## License

MIT
