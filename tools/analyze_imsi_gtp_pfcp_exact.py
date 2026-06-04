#!/usr/bin/env python3
"""Exact IMSI match in GTPv2-C and PFCP."""
import sys
from datetime import datetime, timezone
from scapy.all import rdpcap, IP, UDP

GTPN = {32: "Create Session Req", 33: "Create Session Resp", 34: "Modify Bearer Req",
        35: "Modify Bearer Resp", 36: "Delete Session Req", 37: "Delete Session Resp",
        170: "Create Bearer Req", 171: "Create Bearer Resp"}
PFCPN = {50: "Session Establishment Req", 51: "Session Establishment Resp",
         52: "Session Modification Req", 53: "Session Modification Resp",
         54: "Session Deletion Req", 55: "Session Deletion Resp"}
GTP_CAUSE = {16: "Request accepted", 72: "System failure", 73: "No resources",
             74: "Semantic errors in TFT", 78: "Missing/unknown APN", 103: "Conditional IE missing"}
PFCP_CAUSE = {1: "Request accepted", 64: "Request rejected", 75: "Mandatory IE missing",
              77: "Conditional IE missing"}


def imsi_tbcd(imsi):
    out = bytearray()
    for i in range(0, len(imsi), 2):
        d1 = int(imsi[i])
        d2 = int(imsi[i + 1]) if i + 1 < len(imsi) else 0xF
        out.append((d1 & 0xF) | ((d2 & 0xF) << 4))
    return bytes(out)


def tbcd_imsi(raw):
    digits = []
    for b in raw:
        lo, hi = b & 0x0F, (b >> 4) & 0x0F
        if lo != 0x0F:
            digits.append(str(lo))
        if hi != 0x0F:
            digits.append(str(hi))
    return "".join(digits)


def parse_gtpc_ies(payload, off):
    ies = {}
    while off + 4 <= len(payload):
        t = payload[off]
        ln = int.from_bytes(payload[off + 1 : off + 3], "big")
        if off + 4 + ln > len(payload):
            break
        val = payload[off + 4 : off + 4 + ln]
        if t == 1:
            ies["IMSI"] = tbcd_imsi(val[: min(ln, 8)])
        elif t == 2 and ln:
            ies["Cause"] = val[0]
        elif t == 71:
            ies["APN"] = val.decode("ascii", "replace")
        elif t == 87 and ln >= 5 and val[0] == 1:
            ies["PAA"] = ".".join(str(x) for x in val[1:5])
        off += 4 + ln
    return ies


def parse_gtpv2(data):
    if len(data) < 8 or (data[0] >> 5) != 2:
        return None
    fl, mt = data[0], data[1]
    ln = int.from_bytes(data[2:4], "big")
    if len(data) < 4 + ln:
        return None
    body = data[4 : 4 + ln]
    off = 0
    teid = None
    seq = None
    if fl & 0x08:
        teid = int.from_bytes(body[0:4], "big")
        seq = int.from_bytes(body[4:7], "big")
        off = 8
    else:
        seq = int.from_bytes(body[0:3], "big")
        off = 4
    return mt, teid, seq, parse_gtpc_ies(body, off)


def parse_pfcp_ies(payload, off):
    ies = {}
    while off + 5 <= len(payload):
        t = int.from_bytes(payload[off : off + 2], "big")
        ln = int.from_bytes(payload[off + 2 : off + 4], "big")
        if off + 4 + ln > len(payload):
            break
        val = payload[off + 4 : off + 4 + ln]
        if t == 1:
            ies["IMSI"] = tbcd_imsi(val[: min(ln, 8)])
        elif t == 19 and ln:
            ies["Cause"] = val[0]
        elif t == 60:
            ies["APN-DNN"] = val.decode("utf-8", "replace")
        off += 4 + ln
    return ies


def parse_pfcp(data):
    if len(data) < 4 or (data[0] >> 5) != 1:
        return None
    mt = data[1]
    ln = int.from_bytes(data[2:4], "big")
    if len(data) < 4 + ln:
        return None
    body = data[4 : 4 + ln]
    off = 16 if (data[0] & 0x01) else 4
    seq = int.from_bytes(body[0:3], "big") if len(body) >= 3 else None
    return mt, seq, parse_pfcp_ies(body, off)


def tsfmt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def analyze(pcap, imsi):
    need = imsi_tbcd(imsi)
    pkts = rdpcap(pcap)
    gtp, pfcp = [], []

    for p in pkts:
        ip = p.getlayer(IP)
        udp = p.getlayer(UDP)
        if not ip or not udp:
            continue
        data = bytes(udp.payload)
        if need not in data:
            continue
        ts = float(p.time)

        if udp.sport == 2123 or udp.dport == 2123:
            parsed = parse_gtpv2(data)
            if not parsed:
                continue
            mt, teid, seq, ies = parsed
            if not ies.get("IMSI", "").startswith(imsi[:14]):
                continue
            gtp.append((ts, ip.src, int(udp.sport), ip.dst, int(udp.dport), mt, seq, teid, ies))

        if udp.sport == 8805 or udp.dport == 8805:
            parsed = parse_pfcp(data)
            if not parsed:
                continue
            mt, seq, ies = parsed
            if not ies.get("IMSI", "").startswith(imsi[:14]):
                continue
            pfcp.append((ts, ip.src, int(udp.sport), ip.dst, int(udp.dport), mt, seq, ies))

    print(f"PCAP: {pcap}")
    print(f"IMSI: {imsi}  (TBCD {need.hex()})")
    print(f"GTPv2-C: {len(gtp)} messages   PFCP: {len(pfcp)} messages")
    print()

    for lst, names, causes in (
        (gtp, GTPN, GTP_CAUSE),
        (pfcp, PFCPN, PFCP_CAUSE),
    ):
        if not lst:
            print(f"No exact {('GTPv2-C' if lst is gtp else 'PFCP')} for this IMSI.")
            continue
        title = "GTPv2-C" if lst is gtp else "PFCP"
        print(f"=== {title} ===")
        for i, row in enumerate(sorted(lst)):
            ts, src, sport, dst, dport, mt, seq, *rest = row
            if lst is gtp:
                teid, ies = rest
                teid_s = f" teid={teid}"
            else:
                ies = rest[0]
                teid_s = ""
            c = ies.get("Cause")
            extra = f" cause={c} ({causes.get(c, '?')})" if c is not None else ""
            apn = ies.get("APN") or ies.get("APN-DNN")
            if apn:
                extra += f" apn={apn!r}"
            if "PAA" in ies:
                extra += f" ip={ies['PAA']}"
            print(
                f"{i+1:2d} {tsfmt(ts)} {src}:{sport} -> {dst}:{dport} "
                f"{names.get(mt, mt)} seq={seq}{teid_s}{extra}"
            )
        print()

    # Pair key procedures around attach window 14:32:47
    t0 = min(x[0] for x in gtp + pfcp) if gtp or pfcp else 0
    t1 = max(x[0] for x in gtp + pfcp) if gtp or pfcp else 0
    print(f"Activity span: {tsfmt(t0)} -> {tsfmt(t1)}")

    csr = [x for x in gtp if x[5] == 32]
    csresp = [x for x in gtp if x[5] == 33]
    print("\n=== GTP Create Session outcomes ===")
    for r in csr:
        ans = next((a for a in csresp if a[6] == r[6]), None)
        if ans:
            c = ans[8].get("Cause", "?")
            paa = ans[8].get("PAA", "none")
            print(f"  seq={r[6]}: {GTP_CAUSE.get(c, c)}  UE IP={paa}  ({tsfmt(r[0])})")
        else:
            print(f"  seq={r[6]}: no response  ({tsfmt(r[0])})")

    ser = [x for x in pfcp if x[5] == 50]
    serr = [x for x in pfcp if x[5] == 51]
    print("\n=== PFCP Session Establishment outcomes ===")
    for r in ser:
        ans = next((a for a in serr if a[6] == r[6]), None)
        if ans:
            c = ans[7].get("Cause", "?")
            print(f"  seq={r[6]}: {PFCP_CAUSE.get(c, c)}  ({tsfmt(r[0])})")
        else:
            print(f"  seq={r[6]}: no response  ({tsfmt(r[0])})")

    mbr = [x for x in gtp if x[5] == 34]
    mbresp = [x for x in gtp if x[5] == 35]
    if mbr:
        print("\n=== Modify Bearer ===")
        for r in mbr:
            ans = next((a for a in mbresp if a[6] == r[6]), None)
            c = ans[8].get("Cause", "no response") if ans else "no response"
            print(f"  seq={r[6]}: {GTP_CAUSE.get(c, c)}  ({tsfmt(r[0])})")

    dsr = [x for x in gtp if x[5] == 36]
    if dsr:
        print(f"\nDelete Session requests: {len(dsr)}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: analyze_imsi_gtp_pfcp_exact.py <capture.pcap> <imsi>", file=sys.stderr)
        sys.exit(2)
    analyze(sys.argv[1], sys.argv[2])
