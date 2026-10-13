<div align="center">

```
▄▄▄▄▄  ▄▄                         
 ██▀▀▀▀█▄ ██                        
 ▀██▄  ▄▀ ██                        
   ▀██▄▄  ██ ▄█▀█▄ ▄█▀█▄ ████▄ ██ ██
 ▄   ▀██▄ ██ ██▄█▀ ██▄█▀ ██ ██ ██▄██
 ▀██████▀▄██▄▀█▄▄▄▄▀█▄▄▄▄████▀▄▄▀██▀
                         ██      ██ 
                         ▀     ▀▀▀  
   "It looks like DNS. It acts like DNS.
    But it carries your secrets."
```
### Covert DNS-over-HTTPS Tunnel

![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-00ff88?style=flat-square)
![Tests](https://img.shields.io/badge/tests-%E2%9C%93%20race%20green?style=flat-square&logo=github&logoColor=white)
![Status](https://img.shields.io/badge/status-alpha-orange?style=flat-square)

**by [`s1d9e`](https://github.com/s1d9e)**
</div>

---

## ⚠️ Disclaimer

> [!WARNING]
> **For educational purposes and authorized security testing only.**
>
> **Sleepy** is a free and open-source project developed and maintained by
> **[`s1d9e`](https://github.com/s1d9e)**.
>
> It is published **as is**, **without warranty of any kind**, and the author
> is **not responsible, liable, or accountable** for any direct or indirect
> damage, data loss, service disruption, legal action, or other consequence
> resulting from the use, misuse, or inability to use this software.
>
> By downloading, building, running, or distributing Sleepy you **accept full
> responsibility** for your actions and agree to use it **only**:
>
> - on systems and networks you own, or
> - on systems and networks for which you hold **explicit written
>   authorization** to test.
>
> Unauthorized access, interception of communications, or exfiltration of data
> is **illegal** in most jurisdictions. It is **your sole responsibility** to
> determine whether your use complies with applicable local laws and
> regulations — **the author assumes none of that responsibility.**
>
> **If you do not agree to these terms, do not use this software.**

---

## Table of contents

- [⚠️ Disclaimer](#disclaimer)
- [Overview](#overview)
- [Threat model](#threat-model)
- [How it works](#how-it-works)
- [Wire protocol](#wire-protocol)
- [Cryptography](#cryptography)
- [Traffic-analysis resistance](#traffic-analysis-resistance)
- [Architecture](#architecture)
- [Features](#features)
- [Install](#install)
- [Usage](#usage)
- [Flag reference](#flag-reference)
- [Performance](#performance)
- [Detection considerations](#detection-considerations)
- [Security notes](#security-notes)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

Sleepy is a **covert tunneling tool** that carries arbitrary TCP traffic
inside DNS-over-HTTPS (DoH) transactions. To anything inspecting the wire,
the client is a normal host resolving names through a public DoH resolver
(`cloudflare-dns.com`, `dns.google`, …) — every request is a byte-perfect
RFC 8484 exchange. To the operator, it is a SOCKS5 proxy that any TCP
application can be pointed at.

The design optimizes for a **high-level penetration-testing** scenario: an
egress-filtered or monitored network where arbitrary outbound TCP is blocked
or scrutinized, but DNS — and specifically DoH toward a reputable resolver —
is permitted and rarely decoded past the TLS layer.

> **Authorized use only.** See the [Disclaimer](#disclaimer) — this tool is
> for authorized penetration testing and research, on systems you have
> permission to test.

## Threat model

Sleepy is built to raise the cost of detection, not to be undetectable.
Being explicit about the boundary matters more than a marketing claim:

| Adversary | Posture |
|---|---|
| **Passive network monitor / NDR** that sees only metadata (SNI, sizes, timing) | Primary target. Traffic is TLS-wrapped, size-bucketed, and paced with a non-regular cadence to blend with ordinary DoH. |
| **Deep packet inspection** of the DoH body | Sees valid DNS messages that decrypt to nothing without the PSK. Payload content is protected by ChaCha20-Poly1305. |
| **Active MITM** (rogue resolver / on-path attacker) | Resisted: the PSK-authenticated handshake binds both peers; replayed or tampered records are rejected by the AEAD and anti-replay window. |
| **Global passive adversary** correlating client ↔ authoritative resolver traffic | **Out of scope.** Timing/volume correlation across the DoH relay defeats any transport that is not a low-latency cover channel. |
| **Host-based inspection** (EDR, endpoint logs) | **Out of scope.** The client is a plain local binary listening on a SOCKS port. |

**What Sleepy hides:** *what* you say, and *to whom* at the application layer.
**What it does not hide:** *that* a persistent, bursty DoH conversation exists,
and its approximate volume.

## How it works

```
   ┌────────┐   TLS/DoH    ┌─────────────┐   DNS     ┌──────────────┐   TCP    ┌────────┐
   │ Client │─────────────▶│  Resolver   │──────────▶│ Sleepy Server│─────────▶│ Target │
   │        │◀─────────────│ (CF / Google)│◀──────────│              │◀─────────│        │
   └────────┘              └─────────────┘           └──────────────┘          └────────┘
       │                          │                          │
  SOCKS5 local              looks like ordinary         decodes the tunnel
  SSH, curl, …              DoH to an IDS/WAF           back into TCP flows
```

1. **Handshake.** The client opens a session label (e.g. `2pr8t8xm`) and
   performs an ephemeral X25519 handshake authenticated by the pre-shared
   key. Both peers derive directional traffic keys.
2. **Uplink.** Local TCP bytes are chunked, framed, encrypted, base32-encoded
   and embedded in the **query NAME** of a DoH request.
3. **Downlink.** The server's response carries encrypted frames in the
   **TXT record(s)** of the DNS answer.
4. **Multiplexing.** Many concurrent TCP streams interleave over the same
   paced cadence, identified by a 16-bit stream ID.
5. **Pacing.** The scheduler issues exchanges in *bursts* that decay to a
   slow baseline, with randomized jitter — imitating a human loading a page
   rather than a machine heartbeat.

## Wire protocol

### Frame format

Every stream PDU is framed with an 8-byte header before encryption:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Stream ID (u16)      | Flags  (u8)   | Rsvd  (u8)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Payload Length (u16)      | Rsvd  (u16)    | Payload ...   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Width | Notes |
|---|---|---|
| Stream ID | 16-bit BE | Non-zero; odd/even allocated per direction. `0` is invalid. |
| Flags | 8-bit | `SYN=0x01` open stream (payload = dial target), `FIN=0x02` half-close, `RST=0x04` reset, `0x00` = data. |
| Reserved | 8 + 16-bit | Zero; reserved for future framing. |
| Payload Length | 16-bit BE | Payload is `≤ MaxPayload = 1024` bytes. |

Frame payload ≤ **1024 B** so a full frame fits comfortably inside a single
TXT record together with sealing overhead.

### DNS encoding

**Uplink (query NAME).** The sealed record is base32-encoded (lowercase,
unpadded, alphabet `[a-z2-7]`) and split into labels of ≤ 63 bytes:

```
<l1>.<l2>…<ln>.<session>.<tunnel-domain>
└────────── base32 record ──────────┘  └ routing ┘  └ operator domain ┘
```

The whole name must stay ≤ **253 bytes**, which hard-caps the usable
payload per query. Given a session label and domain, the codec derives the
exact budget (`MaxNamePayload`) and the chunker sizes frames to fit it —
~**109 B** of uplink payload per query for a typical
`tunnel.example.com` deployment.

**Downlink (TXT records).** The sealed record travels in TXT RDATA, which
tolerates ~1024–1600 B per RR without fragmentation concerns under DoH.
This asymmetry is why downlink throughput is several times uplink
throughput at the same cadence.

Both directions share one base32 codec, so a single decoder serves either
side. The response also answers the exact question that was asked, so the
transaction is indistinguishable from a real DoH lookup at the resolver.

## Cryptography

### Handshake (mutual authentication via PSK)

```
Client ──▶ Server:  magic ‖ client_ephemeral_pub(32) ‖ HMAC-SHA256(psk, magic‖client_ephemeral_pub)
Server ──▶ Client:  magic ‖ server_ephemeral_pub(32) ‖ HMAC-SHA256(psk, magic‖server_ephemeral_pub‖client_ephemeral_pub)
```

- `magic = "SLPY0001"` (8 B) lets the server tell a fresh handshake from a
  data record even under an existing session label (re-handshake after an
  outage). A data record opens with an 8-byte sequence number, so a collision
  would additionally require a valid trailing HMAC — practically impossible.
- Handshake message size is a constant **72 B** (`8 + 32 + 32`).
- The passphrase is stretched with **HKDF-SHA256** into a 32-byte PSK
  (`crypto.DerivePSK`), so a human-chosen secret is never used raw.

### Key schedule

```
                       X25519(client_eph_priv, server_eph_pub)
                                     │  shared_secret
                                     ▼
   HKDF-SHA256( ikm = shared_secret, salt = client_pub ‖ server_pub )
                                     │
        ┌────────────────────────────┴───────────────────────────┐
        ▼                                                        ▼
  client→server key + nonce prefix                        server→client key + nonce prefix
```

- **Ephemeral X25519** per session ⇒ **forward secrecy**: compromising the
  long-term PSK later does not decrypt recorded traffic.
- The salt binds **both** public keys, so neither side can be desynced or
  downgraded by a manipulated transcript.
- HKDF output splits into **independent directional keys** and per-direction
  **nonce prefixes**, so the two directions never share a key or nonce space.

### Record format and nonce discipline

```
sealed = seq(u64 BE) ‖ ciphertext ‖ poly1305_tag(16)
              │                             │
              └── AAD ──────────────────────┘  ChaCha20-Poly1305
nonce = nonce_prefix(4) ‖ counter
```

| Property | Choice | Rationale |
|---|---|---|
| AEAD | ChaCha20-Poly1305 | Fast without AES-NI, constant-time, ubiquitous in Go. |
| Nonce | 4-byte random prefix + 64-bit counter | Deterministic per direction; prefix separates key/nonce spaces. |
| AAD | the 8-byte sequence number | Binds ciphertext to its position ⇒ truncation/reordering is detected. |
| Replay | 64-bit seq + per-session window | Re-sent frames (auto-reconnect retries the *same* sealed record) are de-duplicated. |
| Key separation | `Sealer` / `Opener` per direction | Neither direction's key can decrypt the other. |

The client **auto-reconnects**: transient transport failures retry the same
sealed record (the server's anti-replay window de-duplicates it), and a
dead session triggers a fresh handshake under the same label with
exponential backoff.

## Traffic-analysis resistance

This is where a covert tunnel is actually won or lost.

### Burst cadence with decay

A naive tunnel emits one query on a fixed interval — a dead giveaway, since
humans do not resolve names at 1.000 Hz. Sleepy's scheduler instead models
a **page load**: a burst of rapid exchanges that *decays* back to a slow
idle baseline, with per-interval **jitter** so no two gaps are equal.

```
        burst (fast)                          decay              baseline (idle)
   ──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌────────┐ ┌──────────────┐ ┌────────────────────
     └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘        └─┘              └─┘
     ◀── BurstSteps ──▶◀── exponential back-off ──▶◀── keepalive ──▶
```

- The burst is **re-armed from the real backlog**: if frames are queued, the
  next tick schedules another exchange instead of collapsing to the idle
  rate, so sustained transfers hold the burst rate.
- The downlink **self-clocks**: a non-empty response re-arms a burst, so a
  download is not throttled by an empty uplink queue.
- The interval **decays** over `BurstSteps` ticks back to the baseline,
  clamped so backlog can never push the cadence *slower* than idle.

### Cadence profiles

Operator-selectable via `-cadence` on the client — an explicit trade between
throughput and fingerprint:

| Profile | Idle | Burst | Steps | Jitter | Character |
|---|---|---|---|---|---|
| `stealth` | 3000 ms | 250 ms | 8 | 0.50 | Sparse, irregular — hardest to flag, slowest. |
| `balanced` *(default)* | 1500 ms | 100 ms | 12 | 0.40 | Human-like browsing cadence. |
| `fast` | 500 ms | 15 ms | 32 | 0.15 | Machine-regular — fastest, easiest for an NDR to flag. |

### Length-hiding padding (`-padding`)

Without padding, the encrypted record size leaks the underlying frame size —
an observer correlating query-name lengths can fingerprint message types
(keystroke vs. file chunk). Padding inflates every record to a **size
bucket** drawn from a small discrete set, collapsing the granularity of the
leak from "any byte count" to "one of N buckets."

- The uplink bucket set is derived from the DNS-name budget and **always
  includes the budget ceiling**, so a full-size frame always has a bucket to
  land in (frame → pad → seal still fits the 253-byte name exactly).
- The length prefix sits **inside** the AEAD plaintext, so padding is
  indistinguishable from payload once encrypted; the receiver strips it
  self-descriptively.
- **`-padding` must match on both sides** — it is not negotiated on the
  wire.

### Decoy resolver

Queries outside the tunnel domain are handled like a real resolver: they are
forwarded to an upstream DoH provider (`-upstream`), so a curious client
resolving `example.com` through the tunnel sees a normal answer — not
NXDOMAIN. Set `-upstream ""` to refuse foreign queries instead.

## Architecture

```
cmd/
  server/       DoH front-end: handshake, frame dispatch, decoy resolver, TCP relay
  client/       SOCKS5 local proxy, burst scheduler, auto-reconnect
internal/
  crypto/       X25519 handshake, HKDF key schedule, ChaCha20-Poly1305 AEAD
  protocol/     stream multiplexer + DNS codec (query NAME / TXT)
  doh/          DoH transport, cadence scheduler, profiles, reconnect
  pad/          length-hiding padding (bucketed)
  socks/        SOCKS5 server (RFC 1928)
  tunnel/       glues DoH + mux + TCP endpoints; benchmark harness
```

**Layer stack (uplink):**

```
TCP bytes  →  stream chunker (≤ MaxUplinkPayload)
           →  mux frame        (8-B header + payload)
           →  pad.Pad          (bucket + 2-B length prefix)   [optional]
           →  AEAD.Seal        (seq ‖ ciphertext ‖ tag)
           →  base32 + labels  →  query NAME  →  DoH POST
```

## Features

| Feature | Description |
|---|---|
| **DoH transport** | Traffic looks like ordinary RFC 8484 DNS-over-HTTPS |
| **Encrypted** | ChaCha20-Poly1305 with forward secrecy (ephemeral X25519 + HKDF) |
| **Authenticated** | PSK-authenticated handshake resists MITM, spoofing and replay |
| **Multiplexed** | Many concurrent TCP streams over one paced cadence |
| **Burst cadence** | Human-like bursts with decay + jitter; no machine heartbeat |
| **Cadence profiles** | `stealth` / `balanced` / `fast` — throughput vs. fingerprint |
| **Decoy resolver** | Answers foreign queries like a real DNS resolver |
| **SOCKS5 proxy** | Run any TCP app through the tunnel |
| **Auto chunking** | Frames split to fit DNS name / TXT size limits |
| **Backpressure** | A full uplink queue throttles the writer instead of dropping frames |
| **Auto-reconnect** | Exponential-backoff re-handshake survives outages |
| **Length hiding** | Optional bucketed padding (`-padding`, symmetric) |
| **Autocert** | Let's Encrypt certificates, auto-renewed (`-autocert`) |
| **Docker** | Containerized deployment (`make docker`) |

## Install

```bash
git clone https://github.com/s1d9e/sleepy.git
cd sleepy
make build          # → bin/sleepy-server and bin/sleepy-client
```

Requires Go 1.26+.

## Usage

### 1. Start the server

```bash
# Let's Encrypt (port 80 reachable for HTTP-01)
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

# Refuse foreign (decoy) queries instead of forwarding them
./bin/sleepy-server --domain tunnel.example.com --secret-key "…" --upstream ""
```

### 2. Start the client

```bash
./bin/sleepy-client \
  --server tunnel.example.com \
  --secret-key "<same passphrase>" \
  --listen 127.0.0.1:1080 \
  --cadence balanced

# Add --padding to match a server started with --padding
#   --endpoint https://…   override the DoH URL (default https://<server>/dns-query)
#   --insecure             skip TLS verification (self-signed lab only)
```

### 3. Route traffic through it

```bash
# HTTP(S) via SOCKS5
curl --socks5-hostname 127.0.0.1:1080 https://target.internal/

# SSH via SOCKS5
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@target

# Full applications that speak SOCKS5 (proxychains, browsers, …)
proxychains4 nmap -sT -Pn 10.0.0.0/24
```

## Flag reference

### `sleepy-server`

| Flag | Default | Description |
|---|---|---|
| `-domain` | *(required)* | Tunnel domain, e.g. `tunnel.example.com`. |
| `-secret-key` | *(required)* | Passphrase; stretched via HKDF to a 32-byte PSK. |
| `-listen` | `:443` | Address to listen on. |
| `-cert` / `-key` | — | TLS PEM pair; serves TLS directly when both are set. |
| `-autocert` | `false` | Obtain/renew a Let's Encrypt cert (needs port 80 for HTTP-01). |
| `-autocert-cache` | `autocert-cache` | Directory caching autocert certificates. |
| `-email` | — | Contact email for the Let's Encrypt account. |
| `-upstream` | `https://cloudflare-dns.com/dns-query` | Decoy resolver upstream; **empty refuses** foreign queries. |
| `-padding` | `false` | Length-hide frames (must match the client's `-padding`). |

### `sleepy-client`

| Flag | Default | Description |
|---|---|---|
| `-server` | *(required)* | Tunnel domain, e.g. `tunnel.example.com`. |
| `-secret-key` | *(required)* | Passphrase (must match the server's). |
| `-listen` | `127.0.0.1:1080` | Local SOCKS5 listen address. |
| `-endpoint` | `https://<server>/dns-query` | Override the DoH URL. |
| `-session` | *(random)* | Session label embedded in the query name. |
| `-cadence` | `balanced` | Pacing profile: `stealth` \| `balanced` \| `fast`. |
| `-padding` | `false` | Length-hide frames (must match the server's `-padding`). |
| `-insecure` | `false` | Skip TLS certificate verification (**lab only**). |

## Performance

Throughput is gated by the **scheduler cadence** (one DoH exchange per
frame) and the **DNS name budget** (~109 B of uplink payload per query), not
by the network. Measured on loopback, 16 KiB transfers, one benchmark run
per cadence profile:

| Profile | Uplink | Downlink | Cadence |
|---|---|---|---|
| `stealth` | ~2.6 Kbps | ~9.2 Kbps | 3000 ms idle, 250 ms burst, 0.5 jitter |
| `balanced` *(default)* | ~5.3 Kbps | ~21.8 Kbps | 1500 ms idle, 100 ms burst, 0.4 jitter |
| `fast` | ~12.7 Kbps | ~88.4 Kbps | 500 ms idle, 15 ms burst, 0.15 jitter |

The downlink is ~7× faster than uplink at the same cadence because each
response carries a full TXT record (~1024 B) while a query NAME only fits
~109 B — so `fast` downlink approaches the ~96 Kbps design target while the
uplink cannot (the name budget is a hard ceiling).

**16 KiB numbers are tail-dominated.** Each burst ends with a decay ramp back
to the idle baseline, and for a small transfer that ramp is most of the
elapsed time. A *sustained* transfer (larger than the 256-frame uplink
queue, ~28 KiB) keeps the queue saturated so the tail is amortized: the same
`fast` profile measures **~37.7 Kbps uplink** at 128 KiB vs ~12.7 Kbps at
16 KiB. In an end-to-end run against a real HTTP target over SOCKS, a
9 MB download sustained **~32 KB/s (~258 Kbps)** downlink, byte-perfect
(md5-verified).

Both directions are **burst-gated**: the client re-arms the burst from its
uplink backlog and self-clocks on non-empty downlink responses, so sustained
transfers hold the burst rate instead of collapsing to the baseline
keepalive. A full uplink queue **backpressures** the writer (the TCP read
from the SOCKS client throttles) rather than dropping frames.

The tunnel is **RTT-bound** (one frame per request/response): real-world
throughput scales inversely with network latency. `fast` trades a
machine-regular cadence — easier for an NDR to flag — for ~10× throughput.

Reproduce with the built-in benchmark:

```bash
# default 16 KiB transfers, all profiles
go test ./internal/tunnel/ -bench 'Throughput|Latency' -benchtime 1x -v

# sustained (steady-state) throughput
SLEEPY_BENCH_BYTES=131072 go test ./internal/tunnel/ -bench 'UplinkThroughput/fast' -benchtime 1x -v
```

## Detection considerations

For blue-team context and honest red-team planning — what an analyst can
still see:

| Signal | Why it exists | Mitigation / residual risk |
|---|---|---|
| Persistent DoH toward one endpoint | The tunnel needs a long-lived conversation | Looks like a normal DoH client; volume/timing is the tell. |
| Query-name length distribution | Uplink payload is size-bounded | Bucketed padding (`-padding`) collapses sizes to a discrete set. |
| Query rate | One exchange per frame | Cadence profiles + jitter; `fast` is measurably machine-like. |
| TXT-record responses with high entropy | Downlink rides in TXT | Encrypted; distinguishable only by entropy/size, not content. |
| Name labels that never resolve elsewhere | Base32 blobs under the tunnel domain | Only visible if the analyst controls/resolves that domain. |

**Practical guidance:** prefer `balanced` (or `stealth`) on any network with
a mature NDR; reserve `fast` for lab throughput or low-scrutiny links. Always
decide `-padding` deliberately — it is a fingerprint/overhead trade, and it
must match on both ends.

## Security notes

- The pre-shared key is a **passphrase**, stretched through HKDF to a
  32-byte PSK. Use a high-entropy secret.
- Each session performs an **ephemeral X25519 handshake** authenticated by
  the PSK, giving forward secrecy and mutual authentication.
- Records are sealed with **ChaCha20-Poly1305**; nonces are deterministic
  (4-byte random prefix + 64-bit counter), and the sequence number doubles
  as AAD for anti-replay and truncation detection.
- `-padding` **must match on both sides** (it is not negotiated on the wire).
- The client **auto-reconnects** with exponential backoff; retries reuse the
  same sealed record so the server's replay window de-duplicates them.
- Use `-insecure` on the client **only** in a lab with a self-signed cert.
- This tool does **not** defend against endpoint compromise, global
  traffic correlation, or an adversary who can read the query names at the
  authoritative resolver. See [Threat model](#threat-model).

## Development

```bash
make build   # build both binaries (version-stamped via git describe)
make test    # go test ./... -count=1
make race    # full suite under the race detector
make vet     # go vet
make lint    # golangci-lint if installed, else go vet
make docker  # container image tagged with the git version
```

Continuous validation used during development: `gofmt -l .` clean,
`go vet ./...` clean, and the whole suite green under `-race`.

## Roadmap

- [x] DoH client/server core
- [x] ChaCha20-Poly1305 encryption layer (ephemeral X25519 + HKDF, forward secrecy)
- [x] SOCKS5 proxy mode
- [x] Multiplexing (many TCP streams over one cadence)
- [x] Burst cadence with decay + jitter (no heartbeat fingerprint)
- [x] Decoy resolver (answers foreign queries like a real resolver)
- [x] Auto-reconnect (exponential backoff, replay-safe record retry)
- [x] Cadence profiles (`stealth` / `balanced` / `fast`)
- [x] Throughput benchmark + regression suite
- [x] Docker deployment
- [ ] Domain fronting — *deliberately deferred: it would move the transport
      off a DoH-lookalike endpoint onto a fronted host, an OPSEC regression*
- [ ] Cloudflare Workers backend — *deferred: `workers.dev` is easier to
      takedown and less DoH-plausible than a real resolver endpoint*
- [ ] Padding profiles (per-cadence bucket sets)

## License

MIT
