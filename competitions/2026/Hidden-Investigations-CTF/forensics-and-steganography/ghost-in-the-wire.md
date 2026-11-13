# Ghost in the Wire — Forensics & Network (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Network Traffic Analysis |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{1cmp_3xf1l_d3t3ct3d}` |
| **Vulnerability Class** | ICMP Echo Payload Protocol Covert Tunneling (CWE-506) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`ghost-in-the-wire` provides a packet capture `ghost_traffic.pcap`. The capture shows anomalous ICMP traffic between two internal hosts. An adversary utilized ICMP Echo Request (`Type 8`) payload fields as a covert data exfiltration channel.

---

## 2. Traffic Analysis & Extraction
Wireshark filtering:
```text
icmp.type == 8 && ip.src == 192.168.1.105
```
Each ICMP packet carried an abnormal 1-byte data segment appended to the standard echo header, transmitting sequential ASCII characters.

Using `scapy` to reconstruct the exfiltrated byte stream:
```python
from scapy.all import rdpcap, ICMP

packets = rdpcap("ghost_traffic.pcap")
payload = []
for p in packets:
    if p.haslayer(ICMP) and p[ICMP].type == 8:
        raw_data = bytes(p[ICMP].payload)
        if raw_data:
            payload.append(raw_data[-1:])

flag = b"".join(payload).decode()
print("Flag:", flag) # hiCTF{1cmp_3xf1l_d3t3ct3d}
```
