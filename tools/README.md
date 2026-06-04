# Lab PCAP helpers (optional)

Python utilities for correlating Diameter, GTPv2-C, and PFCP in capture files. **Not required** to run PrettyDiameter.

Requires: `pip install scapy`

```bash
python tools/analyze_imsi_pcap.py capture.pcap 999011234567890
python tools/analyze_imsi_gtp_pfcp_teid.py capture.pcap 999011234567890
```

Do not commit PCAP files or subscriber identifiers into the repository.
