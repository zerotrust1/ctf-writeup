# Echoes of a Forgotten Canvas — Forensics & Steganography (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Steganography |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{mu1t!14y3r3d_st3g0o_ju5t_l0v333}` |
| **Vulnerability Class** | Multi-Layered Steganography & Container Dimension Tampering (CWE-506) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`echoes-of-a-forgotten-canvas` provides an artistic image file `canvas.png`. The challenge conceals a multi-part flag across **four distinct, nested steganographic layers**:
1. PNG IHDR Height Truncation
2. EOF ZipCrypto Embedded Archive
3. Steghide DCT Graph-Theoretic Embedding
4. JPEG SOF0 Dimension Truncation

---

## 2. Forensic Investigation & Layer Unwinding

### Layer 1: PNG IHDR Height Restoration
Inspecting `canvas.png` with `pngcheck`:
```text
CRC error in IHDR chunk: calculated 0x48a1c902, expected 0x12b59f3a
```
The image height byte was deliberately modified to hide the bottom rows of pixels. Computing the correct height matching the expected CRC32:
$$\text{Calculated Height} = 1080 \quad (\text{stored as } 480)$$
Patching bytes `0x14..0x17` restored the hidden bottom banner, revealing the passphrase hint:
```text
"The dreamcatcher holds the key: dreamcatcher"
```

### Layer 2: Appended ZipCrypto Archive
Carving the file using `binwalk -e canvas.png` extracted a password-protected ZIP archive appended beyond the PNG `IEND` chunk.
Unlocking the archive with password `dreamcatcher` extracted `painting.jpg`.

### Layer 3: Steghide DCT Extraction
Running `steghide info painting.jpg` confirmed embedded data. Extracting with passphrase `dreamcatcher`:
```bash
steghide extract -sf painting.jpg -p "dreamcatcher"
```
Extracted an intermediate payload `hidden.jpg` and the first half of the flag:
```text
hiCTF{mu1t!14y3r3d_
```

### Layer 4: JPEG SOF0 Truncation
Analyzing `hidden.jpg` revealed that the SOF0 (Start of Frame) segment had its height marker set to `0x0080` (128 pixels), while the scan data contained entropy for 512 pixels. Patching the SOF0 height field to `0x0200` rendered the hidden text:
```text
st3g0o_ju5t_l0v333}
```

Combining the parts yields the complete flag:
```text
hiCTF{mu1t!14y3r3d_st3g0o_ju5t_l0v333}
```
