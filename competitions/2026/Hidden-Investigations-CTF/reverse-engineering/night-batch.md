# Night Batch — Reverse Engineering (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}` |
| **Vulnerability Class** | GnuCOBOL Packed Decimal Arithmetic Constraint & Keystream Recovery (CWE-327) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`night-batch` compiles **COBOL** source code into an x86-64 ELF binary using GnuCOBOL (`libcob`). The application simulates a legacy banking ledger that validates an 18-digit account clearance key. It validates the key using COBOL packed-decimal BCD arithmetic (`COMP-3`) before utilizing the key as an entropy seed for SHA-256 batch reconciliation.

---

## 2. Technical Analysis & Reversing COBOL in GnuCOBOL
Reverse engineering GnuCOBOL binaries involves tracking calls to `cob_decimal_alloc`, `cob_decimal_set_field`, and `cob_decimal_add`.

The 18-digit account number is stored as 9 bytes of packed decimal:
- Each byte stores two decimal digits (high and low nibbles), with the final nibble representing the sign (`C` or `F` for positive).
- The arithmetic constraints enforce:
  1. $\sum_{i=1}^{18} d_i \cdot w_i \equiv 0 \pmod{97}$ (Modulo 97 Checksum).
  2. Substring $d_1 \dots d_6 \times d_7 \dots d_{12} \equiv c_1 \pmod{10^9}$.
  3. Prefix matching against legacy routing code `481702`.

Modeling the packed decimal digits in Z3:
```python
import z3

s = z3.Solver()
digits = [z3.Int(f"d_{i}") for i in range(18)]
for d in digits:
    s.add(d >= 0, d <= 9)
...
```
Solving the constraint system yielded the unique 18-digit account clearance key:
```text
481702596318740925
```

Feeding this key to `./night-batch` decrypts the ledger report and outputs the flag:
```text
hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}
```
