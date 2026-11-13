# Resurrection — Forensics & Disk Geometry (Hard)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Disk Analysis |
| **Difficulty** | Hard |
| **Flag** | `hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_n7f5_runl157_cl5_g30m37ry_7r4ns4c710n_n4n0_f1l371m3_3v7x_b1n4ry_xml_70k3n5_b17m4p_orph4n_v01d_r35urr3c710n}` |
| **Vulnerability Class** | Multi-Phase NTFS Structural Steganography Reconstruction (CWE-506) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`resurrection` supplies a raw forensic disk image `resurrection.raw`. The adversary shattered a 140-character covert transmission across five low-level NTFS structural layers:
1. **Phase 1 (`f!r5t`):** PE Header Timestamp Overlay
2. **Phase 2 (`53c0nd`):** NTFS Data Runlist Geometry
3. **Phase 3 (`th1jd`):** USN Transaction Journal FILETIME Nanosecond Deltas
4. **Phase 4 (`f01_1rth`):** EVTX Binary XML Token Stream
5. **Phase 5 (`51f7h`):** $Bitmap Orphan Cluster Void

---

## 2. Reassembly Workflow & Flag
Executing deep NTFS parsing across all five artifact tiers recovered the shattered fragments in sequence:
- **Phase 1:** `hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_`
- **Phase 2:** `n7f5_runl157_cl5_g30m37ry_`
- **Phase 3:** `7r4ns4c710n_n4n0_f1l371m3_`
- **Phase 4:** `3v7x_b1n4ry_xml_70k3n5_`
- **Phase 5:** `b17m4p_orph4n_v01d_r35urr3c710n}`

Complete flag:
```text
hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_n7f5_runl157_cl5_g30m37ry_7r4ns4c710n_n4n0_f1l371m3_3v7x_b1n4ry_xml_70k3n5_b17m4p_orph4n_v01d_r35urr3c710n}
```
