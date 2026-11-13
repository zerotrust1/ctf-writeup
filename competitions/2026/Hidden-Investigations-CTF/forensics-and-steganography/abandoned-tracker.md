# Abandoned Tracker — Forensics & Wireless Signals (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Wireless Sensor Analysis |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{FoxgloveCoffee_Guest}` |
| **Vulnerability Class** | Spatio-Temporal Sensor Scoring & Signal Anomaly Elimination (CWE-312) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`abandoned-tracker` provides WiFi RSSI sensor logs (`scan_export.csv`) and access point configurations (`aps.conf`). The investigator must track the target device's physical movement path across several access points while filtering out spoofed high-power decoy transmitters.

---

## 2. Analysis & Spatial Scoring
The note states: *"loud just means close. close doesn't mean i went anywhere."*
Filtering by persistent movement velocity rather than raw signal strength (RSSI) eliminated high-power stationary beacons. Evaluating the candidate SSID corresponding to the true target route identified the guest network:
```text
hiCTF{FoxgloveCoffee_Guest}
```
