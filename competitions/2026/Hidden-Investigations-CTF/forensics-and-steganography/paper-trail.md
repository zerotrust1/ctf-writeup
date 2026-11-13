# Paper Trail — Forensics (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Document Analysis |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{pdf_str34m_0bj3ct_d3fl4t3_unc0v3r3d}` |
| **Vulnerability Class** | PDF Deflate Stream Object Carving & Hidden Annotation Layers (CWE-506) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`paper-trail` provides a redacted legal PDF document `chall.pdf`. Black redaction boxes cover critical sections of the evidence.

---

## 2. Forensic Analysis & Object Carving
Using `pdf-parser` and `qpdf --qdf --object-streams=disable`:
Inspecting stream object `12 0 obj` revealed that the text had not been rasterized or wiped; rather, a black rectangular vector polygon was drawn on top of the text layer (`/Rect [ ... ] /Subtype /Square`).
Extracting the raw FlateDecode compressed stream decompressed the underlying hidden text:
```text
hiCTF{pdf_str34m_0bj3ct_d3fl4t3_unc0v3r3d}
```
