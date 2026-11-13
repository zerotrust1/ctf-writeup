# Broken Signals — Forensics (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics / File Format Analysis |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{h34d3r_r3p41r_m4st3r}` |
| **Vulnerability Class** | PNG Magic Header Corruption & Bitplane Slicing (CWE-436) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INPV-01 |

---

## 1. Executive Summary & Challenge Overview
`broken-signals` supplies a corrupted binary file `broken_signal.dat`. Standard image viewers and file identification tools (`file`, `binwalk`) fail to recognize the file due to deliberately nullified magic header bytes.

---

## 2. Forensic Reconstruction
Inspecting the file in a hex editor:
- Bytes `0x00..0x03` were zeroed out (`00 00 00 00`).
- Bytes `0x04..0x07` contained `0D 0A 1A 0A`.
- At offset `0x0C`, the string `IHDR` appeared.

This confirmed the file was a damaged **Portable Network Graphics (PNG)** image whose signature `89 50 4E 47` was wiped.
Restoring the magic header:
```python
with open("broken_signal.dat", "rb") as f:
    data = f.read()

repaired = b"\x89PNG\r\n\x1a\n" + data[8:]
with open("repaired.png", "wb") as f:
    f.write(repaired)
```
Opening `repaired.png` rendered the high-contrast transmission graphic displaying the flag:
```text
hiCTF{h34d3r_r3p41r_m4st3r}
```
