#!/usr/bin/env python3
"""Analyze one IMSI in a pcap including TCP Diameter (Open5GS style)."""
import sys
from collections import defaultdict
from datetime import datetime, timezone
from scapy.all import rdpcap, IP, IPv6, TCP, Raw

AVP = {
    (0, 1): "User-Name",
    (0, 263): "Session-Id",
    (0, 264): "Origin-Host",
    (0, 296): "Origin-Realm",
    (0, 293): "Destination-Host",
    (0, 283): "Destination-Realm",
    (0, 268): "Result-Code",
    (10415, 1407): "Visited-PLMN-Id",
    (10415, 1408): "Requested-EUTRAN-Authentication-Info",
    (10415, 1414): "Authentication-Info",
}
CMD = {257: "CER/CEA", 280: "DWR/DWA", 316: "ULR/ULA", 317: "CLR/CLA", 318: "AIR/AIA"}
RC = {2001: "SUCCESS", 5001: "USER_UNKNOWN", 5004: "ROAMING_NOT_ALLOWED", 5012: "UNABLE_TO_COMPLY", 3002: "UNABLE_TO_DELIVER"}


def tsfmt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def plmn(h):
    b = bytes.fromhex(h)
    if len(b) < 3:
        return h
    d1, d2, d3 = b[0], b[1], b[2]
    mcc = f"{(d1 & 0x0f)}{((d1 >> 4) & 0x0f)}{(d2 & 0x0f)}"
    mnc = f"{(d3 & 0x0f)}{((d3 >> 4) & 0x0f)}"
    if (d2 >> 4) & 0x0f != 0xF:
        mnc += str((d2 >> 4) & 0x0f)
    return f"{mcc}/{mnc}"


def parse_avps(body, off=20):
    out = {}
    while off + 8 <= len(body):
        code = int.from_bytes(body[off : off + 4], "big")
        flags = body[off + 4]
        alen = int.from_bytes(body[off + 5 : off + 8], "big")
        if alen < 8 or off + 8 + alen > len(body):
            break
        vend = 0
        voff = 8
        if flags & 0x80:
            vend = int.from_bytes(body[off + 8 : off + 12], "big")
            voff = 12
        val = body[off + voff : off + 8 + alen]
        key = (vend, code)
        if key in AVP and key != (0, 268):
            out[AVP[key]] = val.decode("utf-8", "replace")
        elif key == (0, 268) and len(val) >= 4:
            out["Result-Code"] = int.from_bytes(val[:4], "big")
        elif key == (10415, 1407):
            out["PLMN"] = plmn(val.hex())
        elif flags & 0x40:
            out.update(parse_avps(val, 0))
        off += 8 + alen + ((4 - (alen % 4)) % 4)
    return out


def iter_msgs(buf):
    off = 0
    while off + 20 <= len(buf):
        if buf[off] != 1:
            off += 1
            continue
        mlen = int.from_bytes(buf[off + 1 : off + 4], "big")
        if mlen < 20 or off + mlen > len(buf):
            off += 1
            continue
        yield buf[off : off + mlen]
        off += mlen


def analyze(pcap, imsi):
    needle = imsi.encode()
    pkts = rdpcap(pcap)
    streams = defaultdict(bytearray)
    meta = defaultdict(list)

    for pkt in pkts:
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        tcp = pkt.getlayer(TCP) if ip else None
        raw = pkt.getlayer(Raw)
        if not (ip and tcp and raw):
            continue
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        chunk = bytes(raw.load)
        base = len(streams[key])
        streams[key].extend(chunk)
        meta[key].append((float(pkt.time), base, base + len(chunk)))

    events = []
    for key, buf in streams.items():
        src, sport, dst, dport = key
        for msg in iter_msgs(buf):
            if needle not in msg:
                continue
            cmd = int.from_bytes(msg[5:8], "big")
            req = bool(msg[4] & 0x80)
            hop = int.from_bytes(msg[12:16], "big")
            avps = parse_avps(msg)
            ts = None
            pos = bytes(buf).find(msg)
            for t, a, b in meta[key]:
                if a <= pos < b:
                    ts = t
                    break
            events.append(
                {
                    "ts": ts or 0.0,
                    "src": src,
                    "dst": dst,
                    "sport": sport,
                    "dport": dport,
                    "cmd": cmd,
                    "req": req,
                    "hop": hop,
                    "avps": avps,
                    "raw": msg,
                }
            )

    # Also collect answers on same TCP stream near IMSI events (by hop)
    hops = {e["hop"] for e in events if e["req"]}
    for key, buf in streams.items():
        src, sport, dst, dport = key
        for msg in iter_msgs(buf):
            cmd = int.from_bytes(msg[5:8], "big")
            req = bool(msg[4] & 0x80)
            hop = int.from_bytes(msg[12:16], "big")
            if req or hop not in hops:
                continue
            avps = parse_avps(msg)
            pos = bytes(buf).find(msg)
            ts = None
            for t, a, b in meta[key]:
                if a <= pos < b:
                    ts = t
                    break
            events.append(
                {
                    "ts": ts or 0.0,
                    "src": src,
                    "dst": dst,
                    "sport": sport,
                    "dport": dport,
                    "cmd": cmd,
                    "req": req,
                    "hop": hop,
                    "avps": avps,
                    "raw": msg,
                }
            )

    # dedupe
    seen = set()
    uniq = []
    for e in sorted(events, key=lambda x: (x["ts"], x["req"])):
        sig = (e["hop"], e["req"], e["cmd"], e["src"], e["dst"])
        if sig in seen:
            continue
        seen.add(sig)
        uniq.append(e)

    print(f"PCAP: {pcap}")
    print(f"IMSI: {imsi}  events: {len(uniq)}")
    if not uniq:
        return

    print(f"Span: {tsfmt(uniq[0]['ts'])} -> {tsfmt(uniq[-1]['ts'])}")
    print()
    for i, e in enumerate(uniq):
        a = e["avps"]
        cname = CMD.get(e["cmd"], f"CMD{e['cmd']}")
        dirn = "REQ" if e["req"] else "ANS"
        rc = a.get("Result-Code")
        extra = ""
        if rc is not None:
            extra = f" RC={rc} ({RC.get(rc, '?')})"
        print(
            f"{i+1:2d} {tsfmt(e['ts'])} {e['src']}:{e['sport']} -> "
            f"{e['dst']}:{e['dport']} {cname} {dirn} hop=0x{e['hop']:x}{extra}"
        )
        for k in ("User-Name", "Origin-Host", "Origin-Realm", "Destination-Host", "Destination-Realm", "PLMN"):
            if k in a:
                print(f"      {k}: {a[k]}")

    print("\n=== Outcome ===")
    reqs = [e for e in uniq if e["req"] and e["cmd"] == 318]
    for r in reqs:
        ans = next((e for e in uniq if not e["req"] and e["cmd"] == 318 and e["hop"] == r["hop"]), None)
        if ans:
            rc = ans["avps"].get("Result-Code", "?")
            print(f"AIR hop=0x{r['hop']:x}: {RC.get(rc, rc)} (from {ans['src']} -> {ans['dst']})")
        else:
            print(f"AIR hop=0x{r['hop']:x}: no answer in capture")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: analyze_imsi_tcp.py <capture.pcap> <imsi>", file=sys.stderr)
        sys.exit(2)
    analyze(sys.argv[1], sys.argv[2])
