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
| **dra_peerctl** | HTTP API: list/add/remove peers, export running `ConnectPeer` config — no full restart |
| **Routing config samples** | Commented `rt_default` snippets: realm routing, DH→MME, IMSI prefix steering |
| **Hot extension reload** | `SIGUSR1` reloads **extension** config files (e.g. `rt_default` routing rules) without dropping peer links |
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

**Runtime listener control** (after `fd_core_start()`, without restarting the daemon):

```c
struct peer_hdr *ph = ...; /* from fd_peer_getbyid() or fd_peer_add() */
fd_peer_listen_start(ph);  /* open SrcIP+SrcPort listener(s) */
fd_peer_listen_stop(ph);   /* close listener(s); outbound link stays up if connected */
```

`fd_peer_add()` at runtime (e.g. from a management extension) starts listeners automatically when `Mode` includes server. Editing `ConnectPeer` blocks in `dra.conf` still requires a daemon restart — only the listener sockets can be added/removed hot.

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

### Configuration reload (SIGUSR1)

**No — not all configs, and not peers.** `SIGUSR1` reloads only extensions that register a reload callback. The main `freeDiameter.conf`, `ConnectPeer` blocks, and peer links are **not** hot-reloadable.

```bash
kill -USR1 $(pgrep -x freeDiameterd)
# or: systemctl kill -s USR1 freediameter-dra.service
```

| Config | File (typical) | Hot reload? | Notes |
|--------|----------------|-------------|-------|
| **Routing rules** | `dra_rt.conf` via `rt_default` | **Yes** | DR/DH/un= scoring; peers stay up |
| **Route rewrite** | `rt_rewrite.conf` | **Yes** | If extension loaded |
| **Realm regex routing** | `rt_ereg.conf` | **Yes** | If extension loaded |
| **ACL whitelist** | `acl_wl.conf` | **Yes** | If extension loaded |
| **Debug log level** | `dbg_loglevel.conf` | **Yes** | If extension loaded |
| **Deny by size** | `rt_deny_by_size.conf` | **Yes** | If extension loaded |
| **dra_rtstats** | `dra_rtstats.conf` | **No** | `route_match`, `dh_replace`, labels — restart required |
| **Main daemon config** | `dra.conf` | **No** | Identity, Port, ListenOn, TLS, LoadExtension, … |
| **ConnectPeer / peers** | `dra.conf` | **No** | Edit file on disk — use **dra_peerctl** to apply live |
| **Per-peer listeners** | runtime API | **Yes** | `fd_peer_listen_start()` / `fd_peer_listen_stop()` |
| **Peer add/remove/swap** | **dra_peerctl** | **Yes** | `POST /add`, `POST /remove`, `GET /dump` |

Peer connections are unchanged by `SIGUSR1`. A full `systemctl restart` tears down all Diameter links (brief outage). Plan peer or `ConnectPeer` changes in a maintenance window.

The **reload** link on the dra_rtstats HTML page only refreshes the stats view; it does not reload any config file.

### dra_peerctl (hot peer swap)

Load `dra_peerctl.fdx` (default HTTP `127.0.0.1:9069`). Swap one peer without restarting the daemon:

```bash
# Enable in dra.conf:
# LoadExtension = "/usr/local/lib/freeDiameter/dra_peerctl.fdx" : "/etc/freeDiameter/dra_peerctl.conf";

tools/dra-peerctl.sh list
tools/dra-peerctl.sh dump /tmp/running-peers.conf    # save live ConnectPeer blocks
tools/dra-peerctl.sh remove old-peer.example.net
tools/dra-peerctl.sh add doc/dra_peer-snippet.sample
```

Or with curl — see `doc/dra_peerctl.conf.sample`.

**Export (`GET /dump`)** writes Identity, Realm, Port, ListenOn, and every running `ConnectPeer` block (including runtime state comments). Use this to snapshot live config before changes. It does not export `LoadExtension` lines or extension configs (`dra_rt.conf` remains separate — reload with `SIGUSR1`).

**Add** accepts a key=value snippet file (`doc/dra_peer-snippet.sample`). **Remove** sends DPR and waits up to ~16s; use `force=1` if the peer is stuck.

## Installation (production)

### Prerequisites

| Requirement | Notes |
|-------------|--------|
| Linux (x86_64) | Tested on Ubuntu/Debian-style systems |
| Build tools | `cmake`, `gcc`/`g++`, `make`, `git`, `bison`, `flex` |
| SCTP | `libsctp-dev` (or distro equivalent) — required by CMake |
| TLS (optional) | `libgnutls28-dev` if you use Diameter over TLS |
| Root for install | `cmake --install` writes to `/usr/local` by default |

```bash
# Debian/Ubuntu example
sudo apt-get install -y build-essential cmake git bison flex \
  libsctp-dev libgnutls28-dev
```

### Clone, build, and install

```bash
git clone https://github.com/arayeji/PrettyDiameter.git
cd PrettyDiameter
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=MaxPerformance ..
cmake --build . -j"$(nproc)"
sudo cmake --install .
```

This installs:

| Path | Content |
|------|---------|
| `/usr/local/bin/freeDiameterd` | Daemon binary |
| `/usr/local/lib/libfdcore.so*` | Core library (peer modes, export API, …) |
| `/usr/local/lib/freeDiameter/*.fdx` | Extensions including `dra_rtstats.fdx`, `dra_peerctl.fdx` |
| `/usr/local/include/freeDiameter/` | Headers |

Quick scripted install (same steps):

```bash
SRC_ROOT=/path/to/PrettyDiameter bash doc/deploy-dra-server.sh
```

### systemd service

Create `/etc/systemd/system/freediameter-dra.service`:

```ini
[Unit]
Description=freeDiameter DRA
After=network.target

[Service]
ExecStart=/usr/local/bin/freeDiameterd -c /etc/freeDiameter/dra.conf
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now freediameter-dra.service
sudo systemctl status freediameter-dra.service
```

### Main configuration (`/etc/freeDiameter/dra.conf`)

Copy your operator `dra.conf` or start from upstream `doc/` samples. Minimum for a DRA relay:

```conf
Identity = "dra.example.com";
Realm = "example.com";
Port = 3868;

ListenOn = "203.0.113.1";

# Dictionaries
LoadExtension = "/usr/local/lib/freeDiameter/dict_dcca.fdx";
LoadExtension = "/usr/local/lib/freeDiameter/dict_dcca_3gpp.fdx";
LoadExtension = "/usr/local/lib/freeDiameter/dict_nasreq.fdx";
LoadExtension = "/usr/local/lib/freeDiameter/dict_rfc5777.fdx";

# Routing + stats + peer control
LoadExtension = "/usr/local/lib/freeDiameter/rt_default.fdx" : "/etc/freeDiameter/dra_rt.conf";
LoadExtension = "/usr/local/lib/freeDiameter/dra_rtstats.fdx" : "/etc/freeDiameter/dra_rtstats.conf";
LoadExtension = "/usr/local/lib/freeDiameter/dra_peerctl.fdx" : "/etc/freeDiameter/dra_peerctl.conf";

ConnectPeer = "hss.example.net" {
    ConnectTo = "203.0.113.10";
    Port = 3868;
};
```

Validate syntax before restart (config parse only — do **not** leave this running in foreground on a live node):

```bash
sudo freeDiameterd -c /etc/freeDiameter/dra.conf &
sleep 2 && sudo kill $!   # or use your operator's config-check wrapper
```

### Extension configs

```bash
sudo install -d /etc/freeDiameter
sudo install -m 644 doc/dra_rtstats.conf.sample /etc/freeDiameter/dra_rtstats.conf
sudo install -m 644 doc/dra_peerctl.conf.sample /etc/freeDiameter/dra_peerctl.conf
# Edit dra_rt.conf routing rules for your network (see doc/*.snippet)
```

Enable `dra_peerctl` on an existing install:

```bash
sudo bash doc/enable-dra-peerctl.sh /etc/freeDiameter/dra.conf doc/dra_peerctl.conf.sample
sudo systemctl restart freediameter-dra.service
```

### Upgrade (new PrettyDiameter release)

```bash
cd PrettyDiameter && git pull
cd build && cmake --build . -j"$(nproc)"
sudo cmake --install .
sudo systemctl restart freediameter-dra.service
```

Peer links drop briefly on restart. For routing-only changes use `SIGUSR1` (below). For single-peer changes use `dra_peerctl` (below) without restart.

## Operations and usage

### Route statistics (`dra_rtstats`)

Default HTTP port **8088** (override in `dra_rtstats.conf`). Open in a browser or curl:

```bash
curl -s http://127.0.0.1:8088/ | head
```

Shows per-peer counters, link state, and optional `route_match` / `dh_replace` reporting. Config changes in `dra_rtstats.conf` require a daemon **restart**.

### Export running config (`dra_peerctl`)

The on-disk `dra.conf` can drift from live state (peers added at runtime, listener flags, etc.). **Export what is actually running:**

```bash
# Helper (from repo checkout)
tools/dra-peerctl.sh dump /tmp/running-dra.conf

# curl
curl -sf http://127.0.0.1:9069/dump -o /tmp/running-dra.conf

# List peers + PSM state
curl -sf http://127.0.0.1:9069/list
tools/dra-peerctl.sh list
```

Output includes `Identity`, `Realm`, `Port`, `ListenOn`, and every `ConnectPeer { … }` block with a `# state: …` comment. **Not exported:** `LoadExtension` lines, TLS certs, or extension configs (`dra_rt.conf` — reload separately).

Default bind is **127.0.0.1:9069** (localhost only). Change `Bind` / `Port` in `dra_peerctl.conf` only if you add firewall controls.

### Hot peer swap (no full restart)

Replace one peer while others stay up:

```bash
# 1. Snapshot current runtime config
tools/dra-peerctl.sh dump /tmp/before-swap.conf

# 2. Remove old peer (sends DPR, waits ~16s)
tools/dra-peerctl.sh remove old-peer.example.net

# 3. Add replacement from snippet file
tools/dra-peerctl.sh add doc/dra_peer-snippet.sample

# 4. Verify
tools/dra-peerctl.sh list
tools/dra-peerctl.sh dump /tmp/after-swap.conf
```

Snippet format (`doc/dra_peer-snippet.sample`):

```conf
DiameterId = "remote-hss.example.net";
ConnectTo = "203.0.113.10";
Port = 3868;
SrcIP = "198.51.100.5";
SrcPort = 4012;
Mode = both;
LocalHost = "dra-link1.example.net";
```

If remove times out (peer stuck in closing state):

```bash
curl -sf -X POST 'http://127.0.0.1:9069/remove?peer=old-peer.example.net&force=1'
```

### HTTP API reference (`dra_peerctl`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Short help |
| `GET` | `/list` | Tab-separated: Diameter-Id, state, mode |
| `GET` | `/dump` | Full running config (freeDiameter syntax) |
| `POST` | `/remove?peer=ID&force=0\|1` | Remove peer by Diameter-Id |
| `POST` | `/add` | Body = key=value snippet (see sample file) |

### Routing reload (`SIGUSR1`)

See table in [Configuration reload](#configuration-reload-sigusr1) above. Quick reference:

```bash
sudo kill -USR1 $(pgrep -x freeDiameterd)
# or: sudo systemctl kill -s USR1 freediameter-dra.service
```

Reloads `dra_rt.conf` and other extension configs that support hot reload. **Does not** reload `ConnectPeer` blocks — use `dra_peerctl` or restart.

## Build (development)

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
| `doc/dra_peerctl.conf.sample` | Peer control HTTP API |
| `doc/dra_peer-snippet.sample` | Key=value file for `dra_peerctl add` |
| `doc/dra_rt-realm-routing.snippet` | Example `DR=` rules for `rt_default` |
| `doc/dra_rt-dh-mme-routing.snippet` | Example `DH=` rules when HSS wins on realm |
| `doc/deploy-dra-server.sh` | Generic build/install example |
| `doc/enable-dra-peerctl.sh` | Add `dra_peerctl` LoadExtension to existing `dra.conf` |

## PCAP tools (optional)

```bash
pip install scapy
python tools/analyze_imsi_pcap.py capture.pcap 999011234567890
python tools/analyze_imsi_gtp_pfcp_teid.py capture.pcap 999011234567890
```

Requires explicit PCAP path and IMSI; no operator network data is stored in the repository.

## Upstream

Based on freeDiameter master. PrettyDiameter is maintained as a separate GitHub project ([arayeji/PrettyDiameter](https://github.com/arayeji/PrettyDiameter)) for DRA-focused improvements without replacing the upstream project.
