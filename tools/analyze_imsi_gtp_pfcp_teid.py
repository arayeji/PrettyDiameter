#!/usr/bin/env python3
"""Correlate PFCP to GTPv2 for an IMSI using F-TEID values from GTP messages."""
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
GTP_CAUSE = {16: "Request accepted", 74: "Semantic errors in TFT", 103: "Conditional IE missing"}
PFCP_CAUSE = {1: "Request accepted", 64: "Request rejected", 77: "Conditional IE missing"}
IFACE = {
    0: "S1U-eNB",
    1: "S1U-SGW",
    4: "S5-SGW-U",
    5: "S5-PGW-U",
    6: "S5-SGW-C",
    7: "S5-PGW-C",
    10: "S11-MME",
    11: "S11-SGW",
}


def tbcd_imsi(raw):
    digits = []
    for b in raw:
        lo, hi = b & 0x0F, (b >> 4) & 0x0F
        if lo != 0x0F:
            digits.append(str(lo))
        if hi != 0x0F:
            digits.append(str(hi))
    return "".join(digits)


def dec_fteid(val):
    if len(val) < 5:
        return None
    fl = val[0]
    teid = int.from_bytes(val[1:5], "big")
    iface = fl & 0x3F
    ip4 = ".".join(str(x) for x in val[5:9]) if (fl & 0x80) and len(val) >= 9 else None
    return iface, teid, ip4


def parse_gtp_ies(body, off):
    ies = []
    while off + 4 <= len(body):
        t = body[off]
        ln = int.from_bytes(body[off + 1 : off + 3], "big")
        inst = body[off + 3]
        if off + 4 + ln > len(body):
            break
        val = body[off + 4 : off + 4 + ln]
        if t == 93:
            sub = 0
            while sub + 4 <= len(val):
                st = val[sub]
                sl = int.from_bytes(val[sub + 1 : sub + 3], "big")
                sinst = val[sub + 3]
                if sub + 4 + sl > len(val):
                    break
                sval = val[sub + 4 : sub + 4 + sl]
                ies.append((st, sinst, sval))
                sub += 4 + sl
        else:
            ies.append((t, inst, val))
        off += 4 + ln
    return ies


def parse_gtp(data):
    if len(data) < 8 or (data[0] >> 5) != 2:
        return None
    fl, mt = data[0], data[1]
    ln = int.from_bytes(data[2:4], "big")
    if len(data) < 4 + ln:
        return None
    body = data[4 : 4 + ln]
    off = 0
    hdr_teid = None
    seq = None
    if fl & 0x08:
        hdr_teid = int.from_bytes(body[0:4], "big")
        seq = int.from_bytes(body[4:7], "big")
        off = 8
    else:
        seq = int.from_bytes(body[0:3], "big")
        off = 4
    ies = parse_gtp_ies(body, off)
    imsi = cause = None
    fteids = []
    for t, inst, val in ies:
        if t == 1:
            imsi = tbcd_imsi(val[: min(len(val), 8)])
        elif t == 2 and val:
            cause = val[0]
        elif t == 87:
            d = dec_fteid(val)
            if d:
                fteids.append((inst, d[0], d[1], d[2]))
    return mt, hdr_teid, seq, imsi, cause, fteids


def parse_pfcp(data):
    if len(data) < 4 or (data[0] >> 5) != 1:
        return None
    mt = data[1]
    ln = int.from_bytes(data[2:4], "big")
    if len(data) < 4 + ln:
        return None
    body = data[4 : 4 + ln]
    has_seid = bool(data[0] & 0x08)
    off = 12 if has_seid else 4
    seq = int.from_bytes(body[off : off + 3], "big") if len(body) >= off + 3 else None
    cause = None
    teids = []
    o = off + 4
    while o + 4 <= len(body):
        t = int.from_bytes(body[o : o + 2], "big")
        l = int.from_bytes(body[o + 2 : o + 4], "big")
        if o + 4 + l > len(body):
            break
        val = body[o + 4 : o + 4 + l]
        if t == 19 and l:
            cause = val[0]
        elif t == 21 and l >= 5:
            fl = val[0]
            teid = int.from_bytes(val[1:5], "big")
            ip4 = ".".join(str(x) for x in val[5:9]) if (fl & 0x80) and l >= 9 else None
            teids.append((teid, ip4, "F-TEID"))
        elif t == 95 and l >= 2:
            desc = val[0]
            if desc & 0x01 and l >= 6:
                teid = int.from_bytes(val[2:6], "big")
                ip4 = ".".join(str(x) for x in val[6:10]) if l >= 10 else None
                teids.append((teid, ip4, "Outer-Hdr"))
        o += 4 + l
    return mt, seq, cause, teids


def tsfmt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def teid_hex(t):
    return f"0x{t:x}"


def fteid_label(inst, iface, teid, ip4):
    return f"{IFACE.get(iface, f'iface{iface}')} teid={teid_hex(teid)} ip={ip4 or '-'}"


def collect_gtp(pkts):
    msgs = []
    for p in pkts:
        ip = p.getlayer(IP)
        udp = p.getlayer(UDP)
        if not ip or not udp or (udp.sport != 2123 and udp.dport != 2123):
            continue
        r = parse_gtp(bytes(udp.payload))
        if not r:
            continue
        mt, hdr_teid, seq, imsi, cause, fteids = r
        msgs.append(
            {
                "ts": float(p.time),
                "src": ip.src,
                "dst": ip.dst,
                "mt": mt,
                "seq": seq,
                "hdr_teid": hdr_teid,
                "imsi": imsi,
                "cause": cause,
                "fteids": fteids,
            }
        )
    return msgs


def collect_pfcp(pkts):
    msgs = []
    for p in pkts:
        ip = p.getlayer(IP)
        udp = p.getlayer(UDP)
        if not ip or not udp or (udp.sport != 8805 and udp.dport != 8805):
            continue
        data = bytes(udp.payload)
        r = parse_pfcp(data)
        if not r:
            continue
        mt, seq, cause, teids = r
        msgs.append(
            {
                "ts": float(p.time),
                "src": ip.src,
                "dst": ip.dst,
                "mt": mt,
                "seq": seq,
                "cause": cause,
                "teids": teids,
                "raw": data,
            }
        )
    return msgs


def find_by_seq(msgs, seq, mt=None):
    out = [m for m in msgs if m["seq"] == seq and (mt is None or m["mt"] == mt)]
    return out[0] if out else None


def find_mbr(msgs, after_ts, s11_teid):
    for m in sorted(msgs, key=lambda x: x["ts"]):
        if m["mt"] != 34 or m["ts"] < after_ts - 0.001 or m["ts"] > after_ts + 0.5:
            continue
        if m["hdr_teid"] == s11_teid:
            return m
    for m in sorted(msgs, key=lambda x: x["ts"]):
        if m["mt"] != 34 and m["mt"] != 35:
            continue
        if after_ts <= m["ts"] <= after_ts + 0.25:
            return m if m["mt"] == 34 else None
    return None


def find_pgw_csr(msgs, t0, imsi, s11_seq):
    for m in msgs:
        if m["mt"] != 32 or not (t0 - 0.01 <= m["ts"] <= t0 + 0.01):
            continue
        if m["seq"] == s11_seq:
            continue
        if m["imsi"] and m["imsi"].startswith(imsi[:14]):
            return m
    return None


def session_teids(s11_csr, s11_csresp, pgw_csr, pgw_csresp, mbr, mbrsp):
    teids = {}
    anchor = None

    def add(label, teid, ip4=None):
        if not teid:
            return
        teids[teid] = {"label": label, "ip": ip4}

    for msg in (s11_csr, pgw_csr):
        if not msg:
            continue
        for inst, iface, teid, ip4 in msg["fteids"]:
            add(fteid_label(inst, iface, teid, ip4), teid, ip4)
            if iface in (6, 11) and teid:
                anchor = teid

    for msg in (s11_csresp, pgw_csresp):
        if not msg:
            continue
        for inst, iface, teid, ip4 in msg["fteids"]:
            add(fteid_label(inst, iface, teid, ip4), teid, ip4)
            if iface in (1, 4, 5, 6, 11) and teid:
                anchor = anchor or teid

    for msg in (mbr, mbrsp):
        if not msg:
            continue
        for inst, iface, teid, ip4 in msg["fteids"]:
            add(fteid_label(inst, iface, teid, ip4), teid, ip4)

    return teids, anchor


def pfcp_for_teids(pfcp_msgs, teids, t0, t_end, teid_bytes=None):
    hits = []
    teid_bytes = teid_bytes or {t: t.to_bytes(4, "big") for t in teids}
    for m in pfcp_msgs:
        if m["ts"] < t0 - 0.05 or m["ts"] > t_end:
            continue
        matched = {t for t, _, _ in m["teids"] if t in teids}
        if not matched and m.get("raw"):
            for t, b in teid_bytes.items():
                if b in m["raw"]:
                    matched.add(t)
        if matched:
            hits.append({**m, "matched": sorted(matched)})
    return hits


def analyze(pcap, imsi):
    pkts = rdpcap(pcap)
    gtp = collect_gtp(pkts)
    pfcp = collect_pfcp(pkts)

    csreqs = [
        m
        for m in gtp
        if m["mt"] == 32
        and m["imsi"]
        and m["imsi"].startswith(imsi[:14])
        and m["sport"] == 2123
    ]

    print(f"PCAP: {pcap}")
    print(f"IMSI: {imsi}")
    print(f"S11 Create Session Requests: {len(csreqs)}")
    print()

    for n, csr in enumerate(sorted(csreqs, key=lambda x: x["ts"]), 1):
        seq = csr["seq"]
        csresp = find_by_seq(gtp, seq, 33)
        pgw_csr = find_pgw_csr(gtp, csr["ts"], imsi, seq)
        pgw_csresp = find_by_seq(gtp, pgw_csr["seq"], 33) if pgw_csr else None

        s11_teid = None
        if csresp:
            for inst, iface, teid, ip4 in csresp["fteids"]:
                if iface == 11:
                    s11_teid = teid
        mbr = find_mbr(gtp, csresp["ts"] if csresp else csr["ts"], s11_teid)
        mbrsp = find_by_seq(gtp, mbr["seq"], 35) if mbr else None

        teids, anchor = session_teids(csr, csresp, pgw_csr, pgw_csresp, mbr, mbrsp)
        t_end = (mbrsp or csresp or csr)["ts"] + 0.4

        print(f"{'=' * 72}")
        print(f"Attach attempt {n}: GTP seq={seq} @ {tsfmt(csr['ts'])}")
        print(f"{'=' * 72}")
        print("\nGTP TEIDs for this session:")
        for teid, info in sorted(teids.items()):
            print(f"  {teid_hex(teid):>12}  {info['label']}")
        if anchor:
            print(f"\nPFCP anchor TEID (SGW-C): {teid_hex(anchor)}")

        print("\nGTP procedure:")
        print(f"  {tsfmt(csr['ts'])} CSReq seq={seq} {csr['src']}->{csr['dst']}")
        if csresp:
            c = csresp["cause"]
            print(
                f"  {tsfmt(csresp['ts'])} CSResp seq={seq} cause={c} "
                f"({GTP_CAUSE.get(c, '?')}) {csresp['src']}->{csresp['dst']}"
            )
        if pgw_csr:
            print(
                f"  {tsfmt(pgw_csr['ts'])} PGW-leg CSReq seq={pgw_csr['seq']} "
                f"{pgw_csr['src']}->{pgw_csr['dst']}"
            )
        if pgw_csresp:
            c = pgw_csresp["cause"]
            print(
                f"  {tsfmt(pgw_csresp['ts'])} PGW-leg CSResp seq={pgw_csresp['seq']} "
                f"cause={c} ({GTP_CAUSE.get(c, '?')})"
            )
        if mbr:
            print(f"  {tsfmt(mbr['ts'])} MBR seq={mbr['seq']} {mbr['src']}->{mbr['dst']}")
        if mbrsp:
            c = mbrsp["cause"]
            print(
                f"  {tsfmt(mbrsp['ts'])} MBRsp seq={mbr['seq']} cause={c} "
                f"({GTP_CAUSE.get(c, '?')})"
            )

        pfcp_hits = pfcp_for_teids(pfcp, teids, csr["ts"], t_end)
        print(f"\nPFCP matched by GTP TEID ({len(pfcp_hits)} messages):")
        if not pfcp_hits:
            print("  (none)")
        else:
            for m in sorted(pfcp_hits, key=lambda x: x["ts"]):
                mt = m["mt"]
                c = m["cause"]
                cstr = f"cause={c} ({PFCP_CAUSE.get(c, '?')})" if c is not None else "cause=?"
                matched = ", ".join(
                    f"{teid_hex(t)} ({teids[t]['label'].split()[0]})" for t in sorted(m["matched"])
                )
                print(
                    f"  {tsfmt(m['ts'])} {PFCPN.get(mt, mt):28} "
                    f"{m['src']}->{m['dst']} pfcp_seq={m['seq']} {cstr}"
                )
                print(f"    matched TEIDs: {matched}")

        print("\nPFCP flow summary:")
        stages = []
        for m in sorted(pfcp_hits, key=lambda x: x["ts"]):
            mt = m["mt"]
            if mt == 50:
                stages.append(f"SER@{tsfmt(m['ts'])[-12:]}")
            elif mt == 51:
                stages.append(f"SERR ok@{tsfmt(m['ts'])[-12:]}")
            elif mt == 52:
                stages.append(f"SMR@{tsfmt(m['ts'])[-12:]}")
            elif mt == 53:
                stages.append(f"SMRsp@{tsfmt(m['ts'])[-12:]}")
            elif mt == 54:
                stages.append(f"SDR@{tsfmt(m['ts'])[-12:]}")
            elif mt == 55:
                stages.append(f"SDRsp@{tsfmt(m['ts'])[-12:]}")
        print("  " + " -> ".join(stages) if stages else "  (no PFCP matched)")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: analyze_imsi_gtp_pfcp_teid.py <capture.pcap> <imsi>", file=sys.stderr)
        sys.exit(2)
    analyze(sys.argv[1], sys.argv[2])
