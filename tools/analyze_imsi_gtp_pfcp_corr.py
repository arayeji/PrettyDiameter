#!/usr/bin/env python3
"""GTP/PFCP analysis for an IMSI: correlate responses by seq and PFCP by time."""
import sys
from datetime import datetime, timezone
from scapy.all import rdpcap, IP, UDP

GTPN = {
    32: "Create Session Req",
    33: "Create Session Resp",
    34: "Modify Bearer Req",
    35: "Modify Bearer Resp",
    36: "Delete Session Req",
    37: "Delete Session Resp",
}
PFCPN = {
    50: "Session Establishment Req",
    51: "Session Establishment Resp",
    52: "Session Modification Req",
    53: "Session Modification Resp",
    54: "Session Deletion Req",
    55: "Session Deletion Resp",
}
GTP_CAUSE = {
    16: "Request accepted",
    72: "System failure",
    73: "No resources",
    74: "Semantic errors in TFT",
    78: "Missing/unknown APN",
    103: "Conditional IE missing",
}
PFCP_CAUSE = {
    1: "Request accepted",
    64: "Request rejected",
    75: "Mandatory IE missing",
    77: "Conditional IE missing",
}


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
    pkts = rdpcap(pcap)
    gtp_all = []
    pfcp_all = []

    for p in pkts:
        ip = p.getlayer(IP)
        udp = p.getlayer(UDP)
        if not ip or not udp:
            continue
        data = bytes(udp.payload)
        ts = float(p.time)

        if udp.sport == 2123 or udp.dport == 2123:
            parsed = parse_gtpv2(data)
            if parsed:
                mt, teid, seq, ies = parsed
                gtp_all.append((ts, ip.src, int(udp.sport), ip.dst, int(udp.dport), mt, seq, teid, ies))

        if udp.sport == 8805 or udp.dport == 8805:
            parsed = parse_pfcp(data)
            if parsed:
                mt, seq, ies = parsed
                pfcp_all.append((ts, ip.src, int(udp.sport), ip.dst, int(udp.dport), mt, seq, ies))

    csr = [x for x in gtp_all if x[5] == 32 and x[8].get("IMSI", "").startswith(imsi[:14])]
    csr_seqs = {x[6] for x in csr}

    print(f"PCAP: {pcap}")
    print(f"IMSI: {imsi}")
    print(f"Create Session Requests with IMSI: {len(csr)}")
    print()

    print("=== GTPv2-C timeline (IMSI CSReq + matching responses / bearer ops) ===")
    for attempt, req in enumerate(sorted(csr), 1):
        t, src, sport, dst, dport, _, seq, _, ies = req
        apn = ies.get("APN", "")
        print(f"\n--- Attempt {attempt}: seq={seq} @ {tsfmt(t)} ---")
        print(f"  CSReq  {src}:{sport} -> {dst}:{dport}  apn={apn!r}")

        for row in sorted(gtp_all):
            rt, rsrc, rsport, rdst, rdport, rmt, rseq, _, ries = row
            if rseq != seq:
                continue
            if rmt == 33:
                c = ries.get("Cause", "?")
                paa = ries.get("PAA", "none")
                print(
                    f"  CSResp {rsrc}:{rsport} -> {rdst}:{rdport} @ {tsfmt(rt)}  "
                    f"cause={c} ({GTP_CAUSE.get(c, '?')})  UE IP={paa}"
                )

        # Modify Bearer often uses next seq; scan +1..+10
        for delta in range(1, 12):
            mseq = seq + delta
            mbr = [x for x in gtp_all if x[5] == 34 and x[6] == mseq]
            if not mbr:
                continue
            for row in mbr:
                _, msrc, msport, mdst, mdport, _, _, _, _ = row
                ans = next((a for a in gtp_all if a[5] == 35 and a[6] == mseq), None)
                c = ans[8].get("Cause", "no response") if ans else "no response"
                print(
                    f"  MBR/MBRsp seq={mseq} @ {tsfmt(row[0])}  "
                    f"{msrc}:{msport}->{mdst}:{mdport}  "
                    f"cause={c} ({GTP_CAUSE.get(c, c) if isinstance(c, int) else c})"
                )
            break

        # PGW leg: CSReq near same time without IMSI filter
        t0, t1 = t - 0.01, t + 0.01
        pgw_csr = [
            x
            for x in gtp_all
            if x[5] == 32
            and t0 <= x[0] <= t1
            and x[6] != seq
            and x[8].get("IMSI", "").startswith(imsi[:14])
        ]
        for row in pgw_csr:
            _, psrc, psport, pdst, pdport, _, pseq, _, pies = row
            ans = next((a for a in gtp_all if a[5] == 33 and a[6] == pseq), None)
            if ans:
                c = ans[8].get("Cause", "?")
                paa = ans[8].get("PAA", "none")
                print(
                    f"  PGW CSReq/Resp seq={pseq}  cause={c} ({GTP_CAUSE.get(c, '?')})  "
                    f"UE IP={paa}  ({psrc}->{pdst})"
                )

    print("\n=== PFCP (no IMSI in capture — time windows around each CSReq) ===")
    for attempt, req in enumerate(sorted(csr), 1):
        t = req[0]
        t0, t1 = t - 0.05, t + 0.35
        near = [x for x in pfcp_all if t0 <= x[0] <= t1]
        ser = [x for x in near if x[5] == 50]
        serr = [x for x in near if x[5] == 51]

        print(f"\n--- Attempt {attempt}: PFCP {tsfmt(t0)} .. {tsfmt(t1)} ---")
        print(f"  Total PFCP: {len(near)}  Session Establishment Req: {len(ser)}")

        flows = {}
        for row in near:
            key = (row[1], row[3])
            flows[key] = flows.get(key, 0) + 1
        if flows:
            print("  Flows:", ", ".join(f"{a}->{b} ({n})" for (a, b), n in sorted(flows.items())))

        for row in ser[:8]:
            rt, src, _, dst, _, _, pseq, ies = row
            ans = next((a for a in serr if a[6] == pseq), None)
            c = ans[7].get("Cause", "no response") if ans else "no response"
            extra = ""
            if ies.get("IMSI"):
                extra += f" imsi={ies['IMSI']}"
            if ies.get("APN-DNN"):
                extra += f" apn={ies['APN-DNN']!r}"
            print(
                f"  {tsfmt(rt)} {src}->{dst} SER seq={pseq} -> "
                f"{PFCP_CAUSE.get(c, c) if isinstance(c, int) else c}{extra}"
            )
        if len(ser) > 8:
            print(f"  ... +{len(ser) - 8} more SER")

    # Any PFCP with IMSI anywhere in pcap
    pfcp_imsi = [x for x in pfcp_all if x[7].get("IMSI", "").startswith(imsi[:14])]
    print(f"\n=== PFCP with IMSI IE anywhere in pcap: {len(pfcp_imsi)} ===")
    for row in pfcp_imsi[:10]:
        rt, src, _, dst, _, mt, pseq, ies = row
        print(f"  {tsfmt(rt)} {src}->{dst} {PFCPN.get(mt, mt)} seq={pseq} imsi={ies.get('IMSI')}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: analyze_imsi_gtp_pfcp_corr.py <capture.pcap> <imsi>", file=sys.stderr)
        sys.exit(2)
    analyze(sys.argv[1], sys.argv[2])
