# PrettyDiameter

PrettyDiameter is a production-oriented fork of [freeDiameter](https://github.com/freeDiameter/freeDiameter) focused on **Diameter Routing Agent (DRA)** deployments: fixed SCTP source binding per peer, safer relay behavior, HTTP route statistics, and operator-ready configuration samples.

## License

This project retains the **freeDiameter BSD license** (see [LICENSE](LICENSE)). PrettyDiameter changes are offered under the same terms. Copyright for upstream code remains with WIDE Project and NICT; PrettyDiameter additions are documented in commit history.

## Features

| Feature | Branch | What it does |
|---------|--------|----------------|
| **Per-peer SCTP source bind** | `feature/per-peer-sctp-src-bind` | `SrcIP`, `SrcPort`, `LocalHost`, `LocalRealm` on `ConnectPeer` for stable outbound four-tuples and per-link Origin-Host |
| **DRA relay routing fixes** | `feature/per-peer-sctp-src-bind` | `LocalHost` no longer treated as global Identity for local delivery / loop detection; answers return to correct peer |
| **dra_rtstats** | `feature/dra-rtstats` | HTTP UI: per-peer message counters, optional `route_match` reporting, optional `dh_replace` |
| **Routing config samples** | `feature/dra-routing-samples` | Commented `rt_default` snippets: realm routing, DH→MME, IMSI prefix steering |
| **PCAP analysis helpers** | `feature/pcap-analysis-tools` | Optional Python tools for IMSI / GTP / PFCP correlation in lab troubleshooting |

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

### Per-peer SCTP bind (`SrcIP` / `SrcPort` / `LocalHost`)

Used on **outbound** `ConnectPeer` links when the operator requires:

- A **fixed local IP and port** on the wire (firewall / whitelist / no SNAT)
- A **different Origin-Host** per link (presentation) while keeping one global DRA `Identity`

Does **not** add client/server modes: freeDiameter still **listens globally** and **connects** via `ConnectTo` (see `doc/freediameter.conf.sample`).

### Relay routing

- **Destination-Host** matching uses **ConnectPeer Diameter-Id** (+100 `FINALDEST`).
- **Destination-Realm** rules in `rt_default` can still outscore MME if HSS has `DR=… += 100` and MME only has +100 — use `DH=` rules in `doc/dra_rt-dh-mme-routing.snippet`.
- **`LocalHost`** affects CER/CEA and outbound Origin-Host on that link only; it is **not** a separate routing target.

### dra_rtstats

Load as extension; serves HTML on configured `Port` (default 8088). Use for:

- Link up/down and message mix (AIR, ULR, CLR, …)
- Verifying `route_match` rules vs actual next-hop peer
- Optional `dh_replace` before routing-out (rewrite presented DH to real MME peer)

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
| `doc/sctp-per-peer-src-bind.patch-notes.md` | Per-peer SCTP / LocalHost reference |
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

Requires explicit PCAP path and IMSI; no operator data is stored in the repository.

## Upstream

Based on freeDiameter master. PrettyDiameter is maintained as a separate GitHub project for DRA-focused improvements without replacing the upstream project.
