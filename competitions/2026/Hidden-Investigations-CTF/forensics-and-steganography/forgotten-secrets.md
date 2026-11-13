# Forgotten Secrets — Forensics & Memory (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Memory Analysis |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{m3m0ry_dump_d1g_d33p}` |
| **Vulnerability Class** | Sentinel Marker Demarcation & Single-Byte XOR Memory Obfuscation (CWE-312) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`forgotten-secrets` presents a memory dump segment `forgotten_secrets.bin`. The memory region was deliberately injected with decoy noise strings and encrypted communications bracketed between sentinel markers.

---

## 2. Memory Extraction & Invariant Recovery
Scanning the memory dump identified bounding delimiters:
- **Header Sentinel:** `DEADBEEF`
- **Trailer Sentinel:** `CAFEBABE`

The 64-byte payload enclosed between the markers exhibited an entropy score inconsistent with raw text. Computing a frequency histogram revealed an identical shift across character intervals, pointing to a single-byte XOR key.
Brute-forcing 256 byte keys against candidate prefix `hiCTF{`:
$$\text{Key} = 0x42 \quad (\text{'B'})$$
XORing the demarcated buffer with `0x42` successfully unsealed the genuine flag:
```text
hiCTF{m3m0ry_dump_d1g_d33p}
```
