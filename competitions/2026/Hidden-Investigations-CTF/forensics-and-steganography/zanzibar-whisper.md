# Zanzibar Whisper — Forensics & Steganography (Easy)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Steganography |
| **Difficulty** | Easy |
| **Flag** | `hiCTF{sp1c3_1sl4nd_s3cr3ts}` |
| **Vulnerability Class** | Steghide DCT Embedding with Null Passphrase (CWE-506) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`zanzibar-whisper` presents a scenic photograph of the historic Stone Town in Zanzibar (`zanzibar.jpg`). Steganographic data is embedded into the DCT matrix with an empty (null) passphrase.

---

## 2. Extraction & Solution
Running `steghide` with a blank passphrase (`-p ""`):
```bash
steghide extract -sf zanzibar.jpg -p ""
```
Extracts `secret.txt` containing the flag:
```text
hiCTF{sp1c3_1sl4nd_s3cr3ts}
```
