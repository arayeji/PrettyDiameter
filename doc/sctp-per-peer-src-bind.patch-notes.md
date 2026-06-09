# Per-peer SCTP source bind (SrcIP / SrcPort)

## Configuration (ConnectPeer block)

```
ConnectPeer = "peer.example.com" {
    ConnectTo = "203.0.113.10";
    Port = 3868;
    SrcIP = "198.51.100.5";   /* optional, repeatable for multi-address / one port */
    SrcPort = 4012;           /* optional, 1..65535; 0/absent = ephemeral (default) */
    Mode = client;            /* client | server | both — default: infer from ConnectTo / SrcIP+SrcPort */
    LocalHost = "dra-link1.example.com";  /* optional Origin-Host for this link only */
    LocalRealm = "operator.example.com";  /* optional Origin-Realm; else global Realm */
    No_TLS;
    Realm = "epc.mnc001.mcc999.3gppnetwork.org";
};
```

- **Mode**: `client` (outbound only), `server` (listen on `SrcIP`+`SrcPort` only), `both`, or omit to auto-detect from `ConnectTo` / `SrcIP`+`SrcPort`.
- **Runtime**: `fd_peer_listen_start()` / `fd_peer_listen_stop()` add or remove listeners without a full daemon restart (outbound links unaffected).
- **SrcPort**: binds the outbound SCTP client socket to this local port before `sctp_connectx()`, so the kernel association matches wire traffic (no SNAT required). With `Mode = server | both`, also opens a dedicated listener on this port bound to the listed `SrcIP` address(es).
- **SrcIP**: binds only the listed local address(es) for this peer; overrides global `ListenOn` for that association. Repeat `SrcIP` for legitimate single-port multihoming (several IPs, one `SrcPort`).
- **Two remote ports**: use two `ConnectPeer` entries (two associations), each with its own `SrcIP`/`SrcPort`/`ConnectTo`/`Port`.

Validation at parse time: `SrcPort` in 1..65535; `SrcIP` must resolve numerically and match a host interface or `ListenOn` address.

## ABI / struct changes (`libfdcore.h`)

- `struct peer_info.config`: added `uint16_t pic_src_port` (0 = ephemeral), `pic_local_host`, `pic_local_realm`.
- New API: `fd_msg_add_origin_peer()`.
- `struct peer_info`: added `struct fd_list pi_src_endpoints` (local bind addresses).
- New API: `int fd_ep_is_local(sSA * sa, socklen_t sl, struct fd_list * conf_eps);`
- Internal: `fd_sctp_client()` and `fd_cnx_cli_connect_sctp()` take an extra `uint16_t src_port` argument.

Extension ABI and the SCTP server/listen path are unchanged.

**Note:** `Host-IP-Address` in CER/CEA must use `FD_IS_LIST_EMPTY()` on `pi_src_endpoints`, not a null check on `next` (an empty list’s `next` points at the head).

**DRA / LocalHost:** `LocalHost` affects **Origin-Host** (and CER Host-IP) on that link only. **Relay routing** still treats only global `Identity` / `Realm` as “for me” on `Destination-Host` / `Route-Record`. If a remote peer learns your presented Origin-Host and echoes it in `Destination-Host`, use `rt_default` `DH=` rules or `dra_rtstats` `dh_replace` to steer to the real MME `ConnectPeer`.

## Production build (required for DRA load)

Root `CMakeLists.txt` (upstream freeDiameter) defaults to **Debug** when `CMAKE_BUILD_TYPE` is not set. For production relay load, configure explicitly:

```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
# or maximum silence (strips trace macros at compile time):
cmake -DCMAKE_BUILD_TYPE=MaxPerformance ..
```

Then `cmake --build . -j$(nproc)` and install.

## Relay statistics (`dra_rtstats` extension)

```text
LoadExtension = "/usr/local/lib/freeDiameter/dra_rtstats.fdx" : "/etc/freeDiameter/dra_rtstats.conf";
```

Open `http://<dra-host>:8088/` for per-peer counters and optional route-match reporting. Sample: `doc/dra_rtstats.conf.sample`.
