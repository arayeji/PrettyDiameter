#!/usr/bin/env python3
"""Find GTPv2-C (2123) and PFCP (8805) messages for one IMSI in a pcap."""
import sys
from collections import defaultdict
from datetime import datetime, timezone
from scapy.all import rdpcap, IP, IPv6, UDP


GTPV2_MSG = {
    1: "Echo Req",
    2: "Echo Resp",
    32: "Create Session Req",
    33: "Create Session Resp",
    34: "Modify Bearer Req",
    35: "Modify Bearer Resp",
    36: "Delete Session Req",
    37: "Delete Session Resp",
    64: "Context Req",
    65: "Context Resp",
    70: "Change Notification Req",
    71: "Change Notification Resp",
    95: "Suspend Notification",
    96: "Suspend Ack",
    97: "Resume Notification",
    98: "Resume Ack",
    100: "Create Bearer Req",
    101: "Create Bearer Resp",
    102: "Update Bearer Req",
    103: "Update Bearer Resp",
    104: "Delete Bearer Req",
    105: "Delete Bearer Resp",
}

PFCP_MSG = {
    1: "Heartbeat Req",
    2: "Heartbeat Resp",
    50: "Session Establishment Req",
    51: "Session Establishment Resp",
    52: "Session Modification Req",
    53: "Session Modification Resp",
    54: "Session Deletion Req",
    55: "Session Deletion Resp",
    56: "Session Report Req",
    57: "Session Report Resp",
}

GTPV2_CAUSE = {
    16: "Request accepted",
    17: "Request accepted partially",
    64: "Context not found",
    72: "System failure",
    73: "No resources available",
    94: "Request rejected",
    103: "Conditional IE missing",
}

PFCP_CAUSE = {
    1: "Request accepted",
    64: "Request rejected",
    65: "Session context not found",
    75: "Mandatory IE missing",
    77: "Conditional IE missing",
}


def tsfmt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def imsi_to_tbcd(imsi: str) -> bytes:
    digits = imsi
    out = bytearray()
    for i in range(0, len(digits), 2):
        d1 = int(digits[i])
        d2 = int(digits[i + 1]) if i + 1 < len(digits) else 0xF
        out.append((d1 & 0x0F) | ((d2 & 0x0F) << 4))
    return bytes(out)


def tbcd_to_imsi(raw: bytes) -> str:
    digits = []
    for b in raw:
        lo = b & 0x0F
        hi = (b >> 4) & 0x0F
        if lo != 0x0F:
            digits.append(str(lo))
        if hi != 0x0F:
            digits.append(str(hi))
    return "".join(digits)


def parse_gtpc_ies(payload, off):
    ies = {}
    multi = defaultdict(list)
    while off + 4 <= len(payload):
        ie_type = payload[off]
        ie_len = int.from_bytes(payload[off + 1 : off + 3], "big")
        if off + 4 + ie_len > len(payload):
            break
        val = payload[off + 4 : off + 4 + ie_len]
        if ie_type == 1 and ie_len >= 4:
            ies["IMSI"] = tbcd_to_imsi(val[: min(ie_len, 8)])
        elif ie_type == 2 and ie_len >= 2:
            ies["Cause"] = val[0]
        elif ie_type == 71 and ie_len >= 1:
            ies["APN"] = val.decode("ascii", "replace")
        elif ie_type == 73 and ie_len >= 4:
            ies["EBI"] = val[0]
        elif ie_type == 80 and ie_len >= 5:
            ies["Bearer-EBI"] = val[0]
        elif ie_type == 87 and ie_len >= 9:
            ptype = val[0]
            if ptype == 1 and ie_len >= 5:
                ies["PAA"] = ".".join(str(x) for x in val[1:5])
        elif ie_type == 93 and ie_len >= 1:
            ies["Bearer-QoS"] = val.hex()
        multi[ie_type].append(val)
        off += 4 + ie_len
    return ies, multi


def parse_gtpv2(data):
    if len(data) < 8 or (data[0] >> 5) != 2:
        return None
    flags = data[0]
    msg_type = data[1]
    length = int.from_bytes(data[2:4], "big")
    if len(data) < 4 + length:
        return None
    body = data[4 : 4 + length]
    off = 0
    teid = None
    seq = None
    if flags & 0x08:
        if len(body) < 8:
            return None
        teid = int.from_bytes(body[0:4], "big")
        seq = int.from_bytes(body[4:7], "big")
        off = 8
    else:
        if len(body) < 4:
            return None
        seq = int.from_bytes(body[0:3], "big")
        off = 4
    ies, _ = parse_gtpc_ies(body, off)
    return {
        "msg_type": msg_type,
        "teid": teid,
        "seq": seq,
        "ies": ies,
    }


def parse_pfcp_ies(payload, off):
    ies = {}
    while off + 5 <= len(payload):
        ie_type = int.from_bytes(payload[off : off + 2], "big")
        ie_len = int.from_bytes(payload[off + 2 : off + 4], "big")
        if off + 4 + ie_len > len(payload):
            break
        val = payload[off + 4 : off + 4 + ie_len]
        if ie_type == 1 and ie_len >= 4:
            ies["IMSI"] = tbcd_to_imsi(val[: min(ie_len, 8)])
        elif ie_type == 19 and ie_len >= 1:
            ies["Cause"] = val[0]
        elif ie_type == 57 and ie_len >= 4:
            ies["F-SEID"] = val.hex()
        elif ie_type == 60 and ie_len >= 1:
            ies["APN-DNN"] = val.decode("utf-8", "replace")
        elif ie_type == 131 and ie_len >= 1:
            ies["PDN-Type"] = val[0]
        off += 4 + ie_len
    return ies


def parse_pfcp(data):
    if len(data) < 4:
        return None
    ver = data[0] >> 5
    if ver != 1:
        return None
    msg_type = data[1]
    length = int.from_bytes(data[2:4], "big")
    if len(data) < 4 + length:
        return None
    body = data[4 : 4 + length]
    off = 0
    seq = None
    seid = None
    if data[0] & 0x01:
        if len(body) < 16:
            return None
        seid = int.from_bytes(body[0:8], "big")
        seq = int.from_bytes(body[8:11], "big")
        off = 16
    else:
        if len(body) < 4:
            return None
        seq = int.from_bytes(body[0:3], "big")
        off = 4
    ies = parse_pfcp_ies(body, off)
    return {"msg_type": msg_type, "seq": seq, "seid": seid, "ies": ies}


def imsi_match(ies, imsi, tbcd):
    got = ies.get("IMSI", "")
    if got.startswith(imsi[:10]) or imsi.startswith(got[:10]):
        return True
    return False


def analyze(pcap, imsi):
    tbcd = imsi_to_tbcd(imsi)
    pkts = rdpcap(pcap)
    gtp_events = []
    pfcp_events = []

    for pkt in pkts:
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        udp = pkt.getlayer(UDP) if ip else None
        if not (ip and udp):
            continue
        data = bytes(udp.payload)
        ts = float(pkt.time)
        src, dst = ip.src, ip.dst
        sport, dport = int(udp.sport), int(udp.dport)

        if sport in (2123, 2152) or dport in (2123, 2152):
            if sport != 2123 and dport != 2123:
                continue
            g = parse_gtpv2(data)
            if not g:
                continue
            raw_hit = tbcd in data or imsi.encode() in data
            ie_hit = imsi_match(g["ies"], imsi, tbcd)
            if not (raw_hit or ie_hit):
                continue
            gtp_events.append(
                {
                    "ts": ts,
                    "src": src,
                    "dst": dst,
                    "sport": sport,
                    "dport": dport,
                    **g,
                }
            )

        if sport == 8805 or dport == 8805:
            p = parse_pfcp(data)
            if not p:
                continue
            raw_hit = tbcd in data or imsi.encode() in data
            ie_hit = imsi_match(p["ies"], imsi, tbcd)
            if not (raw_hit or ie_hit):
                continue
            pfcp_events.append(
                {
                    "ts": ts,
                    "src": src,
                    "dst": dst,
                    "sport": sport,
                    "dport": dport,
                    **p,
                }
            )

    gtp_events.sort(key=lambda x: x["ts"])
    pfcp_events.sort(key=lambda x: x["ts"])

    print(f"PCAP: {pcap}")
    print(f"IMSI: {imsi}")
    print(f"GTPv2-C events: {len(gtp_events)}  PFCP events: {len(pfcp_events)}")
    print()

    if gtp_events:
        print("=== GTPv2-C (UDP 2123) ===")
        for i, e in enumerate(gtp_events):
            name = GTPV2_MSG.get(e["msg_type"], f"type {e['msg_type']}")
            cause = e["ies"].get("Cause")
            cstr = ""
            if cause is not None:
                cstr = f" cause={cause} ({GTPV2_CAUSE.get(cause, '?')})"
            print(
                f"{i+1:2d} {tsfmt(e['ts'])} {e['src']}:{e['sport']} -> "
                f"{e['dst']}:{e['dport']} {name} seq={e['seq']} teid={e['teid']}{cstr}"
            )
            for k in ("IMSI", "APN", "PAA", "EBI", "Bearer-EBI"):
                if k in e["ies"]:
                    print(f"      {k}: {e['ies'][k]}")
    else:
        print("=== GTPv2-C: no messages for this IMSI ===")

    print()
    if pfcp_events:
        print("=== PFCP (UDP 8805) ===")
        for i, e in enumerate(pfcp_events):
            name = PFCP_MSG.get(e["msg_type"], f"type {e['msg_type']}")
            cause = e["ies"].get("Cause")
            cstr = ""
            if cause is not None:
                cstr = f" cause={cause} ({PFCP_CAUSE.get(cause, '?')})"
            print(
                f"{i+1:2d} {tsfmt(e['ts'])} {e['src']}:{e['sport']} -> "
                f"{e['dst']}:{e['dport']} {name} seq={e['seq']}{cstr}"
            )
            for k in ("IMSI", "APN-DNN", "PDN-Type", "F-SEID"):
                if k in e["ies"]:
                    print(f"      {k}: {e['ies'][k]}")
    else:
        print("=== PFCP: no messages for this IMSI ===")

    print("\n=== Summary ===")
    csr = [e for e in gtp_events if e["msg_type"] == 32]
    csresp = [e for e in gtp_events if e["msg_type"] == 33]
    mbr = [e for e in gtp_events if e["msg_type"] == 34]
    mbresp = [e for e in gtp_events if e["msg_type"] == 35]
    dsr = [e for e in gtp_events if e["msg_type"] == 36]
    pfcp_est = [e for e in pfcp_events if e["msg_type"] == 50]
    pfcp_est_r = [e for e in pfcp_events if e["msg_type"] == 51]

    if csr:
        for r in csr:
            ans = next((a for a in csresp if a["seq"] == r["seq"]), None)
            if ans:
                c = ans["ies"].get("Cause", "?")
                print(
                    f"Create Session seq={r['seq']}: "
                    f"{GTPV2_CAUSE.get(c, c)}; PAA={ans['ies'].get('PAA', 'n/a')}"
                )
            else:
                print(f"Create Session seq={r['seq']}: no response in capture")
    if mbr:
        for r in mbr:
            ans = next((a for a in mbresp if a["seq"] == r["seq"]), None)
            c = ans["ies"].get("Cause", "?") if ans else "no response"
            print(f"Modify Bearer seq={r['seq']}: {GTPV2_CAUSE.get(c, c)}")
    if dsr:
        print(f"Delete Session requests: {len(dsr)}")
    if pfcp_est:
        for r in pfcp_est:
            ans = next((a for a in pfcp_est_r if a["seq"] == r["seq"]), None)
            c = ans["ies"].get("Cause", "?") if ans else "no response"
            print(f"PFCP Session Establishment seq={r['seq']}: {PFCP_CAUSE.get(c, c)}")
    if not csr and not pfcp_est:
        print("No Create Session or PFCP Session Establishment found for this IMSI.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: analyze_imsi_gtp_pfcp.py <capture.pcap> <imsi>", file=sys.stderr)
        sys.exit(2)
    analyze(sys.argv[1], sys.argv[2])
