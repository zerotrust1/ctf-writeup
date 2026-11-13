# Epsilon Drift — Reverse Engineering (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}` |
| **Vulnerability Class** | IEEE-754 Precision Drift & Signed Zero Invariant Violation (CWE-682) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`epsilon-drift` is an x86-64 ELF binary that validates a 32-byte calibration passkey structured as four 64-bit IEEE-754 double-precision floating-point numbers ($f_0, f_1, f_2, f_3$). The binary subjects each float to an iterative numerical integration algorithm with signed-zero branching conditions before checking their equality against precomputed hash targets.

---

## 2. Technical Analysis & Invariant Violation

### IEEE-754 Signed Zero & ULP Precision Drift
Inspection in IDA showed that the validation logic checks:
1. Float $f_0$ must satisfy:
   $$f_0 + 0.0 == -0.0 \quad \text{yet} \quad \text{copysign}(1.0, f_0) < 0$$
   This is the classic IEEE-754 **Negative Zero** (bit pattern `0x8000000000000000`).
2. Float $f_1$ undergoes 1,000,000 iterations of:
   $$x_{n+1} = (x_n + \epsilon) - \epsilon$$
   Due to floating-point rounding mode drift (Unit in the Last Place / 1-ULP drift), floating-point addition is non-associative:
   $$(a + b) - b \neq a$$
3. Float $f_2$ must evaluate to subnormal floating-point precision ($0 < |f_2| < 2^{-1022}$).
4. Float $f_3$ satisfies a specific trigonometric invariant:
   $$\sin(f_3) / f_3 \approx 1 - \frac{f_3^2}{6}$$

Evaluating these floating-point representations at the bit level recovers the exact 32-byte input vector, unlocking the binary and printing the flag:
```text
hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}
```

---

## 3. Solver Script (`solve.py`)
```python
#!/usr/bin/env python3
import struct

def solve():
    f0_bits = 0x8000000000000000 # Negative Zero -0.0
    f1_bits = 0x3ff0000000000001 # 1.0 + 1-ULP
    f2_bits = 0x0000000000000001 # Smallest positive subnormal double
    f3_bits = 0x3fd5555555555555 # 1/3 in double precision
    
    payload = struct.pack("<QQQQ", f0_bits, f1_bits, f2_bits, f3_bits)
    print(f"[+] Payload Hex: {payload.hex()}")
    print("[+] Flag: hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}")

if __name__ == "__main__":
    solve()
```
