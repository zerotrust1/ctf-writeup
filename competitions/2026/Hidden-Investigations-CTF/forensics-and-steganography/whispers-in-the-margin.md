# Whispers in the Margin — Forensics & Steganography (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Steganography |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{573g4n0gr4phy_!5_fun}` |
| **Vulnerability Class** | Zero-Width Whitespace Steganography & Steghide Extraction (CWE-506) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`whispers-in-the-margin` provides a Microsoft Word document (`memo.docx`) and an embedded graphic. The challenge hides data across both structural XML whitespace and carrier image steganography.

---

## 2. Investigation & Solution Workflow
1. Unzipping `memo.docx` reveals `word/document.xml`.
2. Inspecting the text revealed sequences of zero-width spaces (`\u200b` and `\u200c`) embedded in paragraph margins.
3. Decoding the binary bitstream (`\u200b` = 0, `\u200c` = 1) recovered the passphrase: `white_spaces_tell_tales`.
4. Applying this passphrase to extract the embedded image (`word/media/image1.jpeg`) via `steghide`:
   ```bash
   steghide extract -sf word/media/image1.jpeg -p "white_spaces_tell_tales"
   ```
5. Recovered `flag.txt`:
   ```text
   hiCTF{573g4n0gr4phy_!5_fun}
   ```
