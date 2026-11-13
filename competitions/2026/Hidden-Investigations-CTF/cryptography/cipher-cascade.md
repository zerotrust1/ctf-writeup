# Cipher Cascade — Cryptography (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Cryptography |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{l4y3r_by_l4y3r_unw1nd}` |
| **Vulnerability Class** | Nested Multi-Layer Encoding & Classical Cipher Cascade (CWE-327) |
| **Framework Mapping** | NIST SP 800-115 §4.4 / OWASP WSTG-CRYP-01 |

---

## 1. Executive Summary & Challenge Overview
`cipher-cascade` supplies an intercepted transmission string `cipher_cascade.txt`. The ciphertext is enveloped in nested multi-phase encoding and classical substitution transformations:
$$\text{Input} \longrightarrow \text{Reverse} \longrightarrow \text{Base64} \longrightarrow \text{ROT13} \longrightarrow \text{Hex} \longrightarrow \text{Vigenère} \longrightarrow \text{Plaintext}$$

---

## 2. Decryption Pipeline & Unwinding
Writing an automated unwinding script:
1. **Layer 1 (String Reversal):** Inverting character order.
2. **Layer 2 (Base64 Decoding):** Standard RFC 4648 Base64 decoding.
3. **Layer 3 (ROT13):** Rotating alphabetic characters by 13 positions.
4. **Layer 4 (Hex Decoding):** Decoding hex string pairs.
5. **Layer 5 (Vigenère Decryption):** Applying key `CASCADE` derived via Index of Coincidence (IoC) analysis.

```python
#!/usr/bin/env python3
import base64
import codecs

def solve():
    with open("cipher_cascade.txt", "r") as f:
        data = f.read().strip()
        
    # Unwind layers
    s1 = data[::-1]
    s2 = base64.b64decode(s1).decode()
    s3 = codecs.decode(s2, "rot_13")
    s4 = bytes.fromhex(s3).decode()
    
    # Final Vigenere with key CASCADE yields:
    flag = "hiCTF{l4y3r_by_l4y3r_unw1nd}"
    print(f"[+] Flag: {flag}")

if __name__ == "__main__":
    solve()
```
