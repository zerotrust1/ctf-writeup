# Roof of Africa — Forensics & Steganography (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Steganography |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}` |
| **Vulnerability Class** | Steghide DCT Embedding with Elevation Passphrase (CWE-506) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`roof-of-africa` provides a high-resolution photograph of Mount Kilimanjaro (`kilimanjaro.jpg`). The challenge requires combining geographic OSINT and steganographic extraction to discover the secret flag embedded within the image's discrete cosine transform (DCT) coefficients.

---

## 2. Investigation & Solution Workflow
1. **Context Clue:** The challenge description references "the exact peak elevation of the Roof of Africa".
2. **OSINT Verification:** Mount Kilimanjaro (Uhuru Peak) has an official elevation of **5,895 meters** above sea level.
3. **Steghide Extraction:** Using `5895` as the passphrase against `kilimanjaro.jpg`:
   ```bash
   steghide extract -sf kilimanjaro.jpg -p "5895"
   ```
4. Successfully extracted `flag.txt`:
   ```text
   hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}
   ```
