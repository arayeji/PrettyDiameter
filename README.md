# PrettyDiameter

PrettyDiameter is a production-oriented fork of [freeDiameter](https://github.com/freeDiameter/freeDiameter) focused on **Diameter Routing Agent (DRA)** deployments: per-peer SCTP bind and listen modes, safer relay behavior, HTTP route statistics, and operator-ready configuration samples.

## License

This project retains the **freeDiameter BSD license** (see [LICENSE](LICENSE)). PrettyDiameter changes are offered under the same terms. Copyright for upstream code remains with WIDE Project and NICT; PrettyDiameter additions are documented in commit history.

## Features

| Feature | What it does |
|---------|----------------|
| **Per-peer SCTP source bind** | `SrcIP`, `SrcPort`, `LocalHost`, `LocalRealm` on `ConnectPeer` for stable outbound four-tuples and per-link Origin-Host |
| **Per-peer listen mode** | `Mode = client \| server \| both` — listen on `SrcIP`+`SrcPort` for inbound peers without using the global `Port` |
| **DRA relay routing fixes** | `LocalHost` no longer treated as global Identity for local delivery / loop detection; answers return to the correct peer |
| **dra_rtstats** | HTTP UI: per-peer message counters, optional `route_match` reporting, optional `dh_replace` |
| **Routing config samples** | Commented `rt_default` snippets: realm routing, DH→MME, IMSI prefix steering |
| **Hot routing reload** | `kill -USR1 $(pgrep -x freeDiameterd)` reloads `rt_default` without restarting peers |
| **PCAP analysis helpers** | Optional Python tools for IMSI / GTP / PFCP correlation in lab troubleshooting |

## Architecture (where this fits)

```text
  [MME]──S6a──┐                    ┌──S6a──[HSS]
              │    PrettyDiameter  │
  [DRA peer]──┼──── (relay) ──────┼──[HSS]
              │    • rt_default    │
              │    • dra_rtstats   │
              └────────┬───────────┘
                       │ N4 (PFCP) / GTP — outside Diameter; use PCAP tools
                 [SGW-C / UPF]
```

### Per-peer SCTP bind and listen

Used on `ConnectPeer` links when the operator requires:

- A **fixed local IP and port** on the wire (firewall / whitelist / no SNAT)
- A **different Origin-Host** per link (presentation) while keeping one global DRA `Identity`
- **Server-side acceptance** on a dedicated local socket instead of (or in addition to) the global listener

```
ConnectPeer = "remote-hss.example.com" {
    ConnectTo = "203.0.113.10";   /* client / both */
    Port = 3868;
    SrcIP = "198.51.100.5";
    SrcPort = 4012;
    Mode = both;                  /* client | server | both — omit to auto-detect */
    LocalHost = "dra-link1.example.com";
};
```

| Mode | Outbound `ConnectTo` | Listen on `SrcIP`+`SrcPort` |
|------|----------------------|------------------------------|
| `client` (default when only `ConnectTo` is set) | yes | no |
| `server` | no | yes |
| `both` | yes | yes |
| *(omit `Mode`)* | auto from config | auto from config |
| *(no `ConnectTo`, no `SrcIP`+`SrcPort`)* | no | inbound on **global** `Port` only |

The global `Port` / `ListenOn` listener is unchanged. Per-peer listeners accept only CERs whose Origin-Host matches the `ConnectPeer` Diameter-Id.

### Relay routing

- **Destination-Host** matching uses **ConnectPeer Diameter-Id** (+100 `FINALDEST`).
- **Destination-Realm** rules in `rt_default` can still outscore MME if HSS has `DR=… += 100` and MME only has +100 — use `DH=` rules in `doc/dra_rt-dh-mme-routing.snippet`.
- **`LocalHost`** affects CER/CEA and outbound Origin-Host on that link only; it is **not** a separate routing target.
- **`dh_replace`** (in `dra_rtstats`) can rewrite presented Destination-Host before routing-out when upstream echoes a relay identity.

### dra_rtstats

Load as extension; serves HTML on configured `Port` (default 8088). Use for:

- Link up/down and message mix (AIR, ULR, CLR, …)
- Verifying `route_match` rules vs actual next-hop peer
- Optional `dh_replace` before routing-out (rewrite presented DH to real MME peer)

### Routing reload (no peer restart)

After editing `dra_rt.conf` (loaded by `rt_default`):

```bash
kill -USR1 $(pgrep -x freeDiameterd)
```

Reloads routing rules only; Diameter peer connections stay up. Changing `ConnectPeer` blocks or the main `dra.conf` still requires a daemon restart.

## Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=MaxPerformance ..
cmake --build . -j$(nproc)
cmake --install .
```

Enable extensions in `CMakeLists.txt` / build options as per upstream freeDiameter, including `dra_rtstats`.

## Configuration

| File | Purpose |
|------|---------|
| `doc/sctp-per-peer-src-bind.patch-notes.md` | Per-peer SCTP / LocalHost / Mode reference |
| `doc/dra_rtstats.conf.sample` | HTTP stats and optional `route_match` / `dh_replace` |
| `doc/dra_rt-realm-routing.snippet` | Example `DR=` rules for `rt_default` |
| `doc/dra_rt-dh-mme-routing.snippet` | Example `DH=` rules when HSS wins on realm |
| `doc/deploy-dra-server.sh` | Generic build/install example |

## PCAP tools (optional)

```bash
pip install scapy
python tools/analyze_imsi_pcap.py capture.pcap 999011234567890
python tools/analyze_imsi_gtp_pfcp_teid.py capture.pcap 999011234567890
```

Requires explicit PCAP path and IMSI; no operator network data is stored in the repository.

## Upstream

Based on freeDiameter master. PrettyDiameter is maintained as a separate GitHub project ([arayeji/PrettyDiameter](https://github.com/arayeji/PrettyDiameter)) for DRA-focused improvements without replacing the upstream project.
