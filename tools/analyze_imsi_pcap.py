#!/usr/bin/env python3
"""Find one IMSI in a Diameter/SCTP pcap and print a timeline."""
import sys
from datetime import datetime, timezone
from scapy.all import rdpcap, SCTP, IP, IPv6

AVP_NAMES = {
    (0, 1): "User-Name",
    (0, 263): "Session-Id",
    (0, 264): "Origin-Host",
    (0, 296): "Origin-Realm",
    (0, 293): "Destination-Host",
    (0, 283): "Destination-Realm",
    (0, 268): "Result-Code",
    (10415, 1407): "Visited-PLMN-Id",
}
CMD = {
    257: "CER/CEA",
    280: "DWR/DWA",
    316: "ULR/ULA",
    317: "CLR/CLA",
    318: "AIR/AIA",
    319: "IDR/IDA",
    321: "DSR/DSA",
}
RC_DESC = {
    2001: "DIAMETER_SUCCESS",
    5001: "USER_UNKNOWN",
    5004: "ROAMING_NOT_ALLOWED",
    5012: "UNABLE_TO_COMPLY",
    3002: "UNABLE_TO_DELIVER",
    3004: "TOO_BUSY",
}


def tsfmt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def plmn_decode(h):
    b = bytes.fromhex(h)
    if len(b) < 3:
        return h
    d1, d2, d3 = b[0], b[1], b[2]
    mcc = f"{(d1 & 0x0f)}{((d1 >> 4) & 0x0f)}{((d2) & 0x0f)}"
    mnc = f"{(d3 & 0x0f)}{((d3 >> 4) & 0x0f)}"
    if (d2 >> 4) & 0x0f != 0xF:
        mnc += str((d2 >> 4) & 0x0f)
    return f"{mcc}/{mnc}"


def parse_avps(body, off=20, depth=0, imsi_needle=b""):
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
        name = AVP_NAMES.get(key, f"AVP_{vend}:{code}")
        if key == (0, 268) and len(val) >= 4:
            out["Result-Code"] = int.from_bytes(val[:4], "big")
        elif key == (10415, 1407):
            out["Visited-PLMN-Id"] = val.hex()
            out["PLMN"] = plmn_decode(val.hex())
        elif key == (0, 1):
            s = val.decode("utf-8", "replace")
            if imsi_needle in val or not out.get("User-Name"):
                out["User-Name"] = s
        elif key in ((0, 264), (0, 296), (0, 293), (0, 283), (0, 263)):
            out[name] = val.decode("utf-8", "replace")
        elif depth < 4:
            nested = parse_avps(val, 0, depth + 1, imsi_needle)
            for nk, nv in nested.items():
                out.setdefault(nk, nv)
        pad = (4 - (alen % 4)) % 4
        off += 8 + alen + pad
    return out


def iter_diameter(pkts, needle):
    for pkt in pkts:
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        sctp = pkt.getlayer(SCTP) if ip else None
        if not (ip and sctp):
            continue
        payload = bytes(sctp.payload) if sctp.payload else b""
        off = 0
        while off + 4 <= len(payload):
            ctype = payload[off]
            length = int.from_bytes(payload[off + 2 : off + 4], "big")
            if length < 4:
                break
            chunk = payload[off : off + length]
            if ctype == 0 and length >= 16:
                ppid = int.from_bytes(chunk[12:16], "big")
                data = chunk[16:]
                if ppid == 46 and len(data) >= 20 and data[0] == 1 and needle in data:
                    yield pkt, ip, sctp, data
            off += (length + 3) & ~3


def analyze(pcap, imsi):
    needle = imsi.encode()
    pkts = rdpcap(pcap)
    events = []
    for pkt, ip, sctp, data in iter_diameter(pkts, needle):
        cmd = int.from_bytes(data[5:8], "big")
        req = bool(data[4] & 0x80)
        err = bool(data[4] & 0x20)
        app = int.from_bytes(data[8:12], "big")
        hop = int.from_bytes(data[12:16], "big")
        e2e = int.from_bytes(data[16:20], "big")
        mlen = int.from_bytes(data[1:4], "big")
        avps = parse_avps(data[:mlen], imsi_needle=needle)
        events.append(
            {
                "ts": float(pkt.time),
                "src": ip.src,
                "dst": ip.dst,
                "sport": sctp.sport,
                "dport": sctp.dport,
                "cmd": cmd,
                "req": req,
                "err": err,
                "app": app,
                "hop": hop,
                "e2e": e2e,
                "avps": avps,
            }
        )

    events.sort(key=lambda x: x["ts"])
    print(f"PCAP: {pcap}")
    print(f"Packets: {len(pkts)}  IMSI {imsi} Diameter events: {len(events)}")
    if not events:
        raw_hits = 0
        for pkt in pkts:
            if needle in bytes(pkt):
                raw_hits += 1
        print(f"Raw packet hits (any layer): {raw_hits}")
        return
    print(f"Span: {tsfmt(events[0]['ts'])} -> {tsfmt(events[-1]['ts'])}")
    print()
    for i, e in enumerate(events):
        a = e["avps"]
        cname = CMD.get(e["cmd"], f"CMD{e['cmd']}")
        dirn = "REQ" if e["req"] else "ANS"
        rc = a.get("Result-Code")
        extra = ""
        if rc is not None:
            extra = f" RC={rc} ({RC_DESC.get(rc, '?')})"
        if e["err"]:
            extra += " [E-bit set]"
        print(
            f"{i + 1:2d} {tsfmt(e['ts'])} {e['src']}:{e['sport']} -> "
            f"{e['dst']}:{e['dport']} {cname} {dirn}{extra}"
        )
        for k in (
            "User-Name",
            "Origin-Host",
            "Origin-Realm",
            "Destination-Host",
            "Destination-Realm",
            "PLMN",
            "Session-Id",
        ):
            if k in a:
                print(f"      {k}: {a[k]}")

    print("\n=== Request / Answer pairing ===")
    for e in events:
        if not e["req"] or e["cmd"] not in (316, 317, 318, 319, 321):
            continue
        ans = next(
            (
                x
                for x in events
                if not x["req"] and x["cmd"] == e["cmd"] and x["hop"] == e["hop"]
            ),
            None,
        )
        cname = CMD.get(e["cmd"], "?")
        if ans:
            rc = ans["avps"].get("Result-Code", "?")
            desc = RC_DESC.get(rc, "?") if isinstance(rc, int) else "?"
            print(f"  {cname} hop=0x{e['hop']:x}: answer RC={rc} ({desc})")
        else:
            print(f"  {cname} hop=0x{e['hop']:x}: NO ANSWER in capture")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: analyze_imsi_pcap.py <capture.pcap> <imsi>", file=sys.stderr)
        sys.exit(2)
    pcap = sys.argv[1]
    imsi = sys.argv[2]
    analyze(pcap, imsi)
