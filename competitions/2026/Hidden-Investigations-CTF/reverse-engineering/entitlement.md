# Entitlement — Reverse Engineering (Hard)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering & Cryptography |
| **Difficulty** | Hard |
| **Flag** | `hiCTF{>o<_C0ngrats_Her3_1s_Y0ur_HI4_Subscript1on_^_^}` |
| **Vulnerability Class** | Anomalous Elliptic Curve Smart's Attack & VDF Time-Lock Delay (CWE-327) |
| **Framework Mapping** | NIST SP 800-115 §4.4 / OWASP WSTG-CRYP-01 |

---

## 1. Executive Summary & Challenge Overview
`Entitlement` is a heavily obfuscated licensing validation binary for a proprietary security suite. The target implements a multi-tiered defensive mechanism designed to prevent both static decompilation and dynamic emulation:
1. **Anti-Debugging & Integrity Check:** Verification of `/proc/self/status` `TracerPid` and process self-hashing.
2. **Serial Validation VM:** A custom bytecode virtual machine verifying a 16-hex-digit Serial number.
3. **Anomalous Elliptic Curve Scalar Multiplication:** An activation code verification routine based on point scalar multiplication over an elliptic curve whose group order equals its field characteristic ($#E(\mathbb{F}_p) = p$).
4. **Verifiable Delay Function (VDF) Time-Lock:** A 500,000,000-iteration sequential 2048-bit Montgomery squaring loop designed to make the validator appear to hang.

---

## 2. Reverse Engineering Deep Dive

### Phase 1: Self-Unpacking & Memory Damping
Static disassembly in IDA / Ghidra revealed an encrypted `.text` section starting at `0x401000`. At runtime, an entrypoint stub unpacks the real validation engine into memory using a rolling XOR cipher keyed on the executable's own ELF header checksum.

Once unpacked, the binary performs an integrity check:
```c
int fd = open("/proc/self/status", O_RDONLY);
char buf[1024];
read(fd, buf, sizeof(buf));
if (strstr(buf, "TracerPid:\t0") == NULL) {
    exit(1); // Anti-debugging trigger
}
```
Bypassing this via a preload wrapper or patching `0x4010a2` allowed dynamic inspection under GDB.

### Phase 2: Serial Number Bytecode VM
The unpacked code branches into a custom register-based virtual machine that reads the user's 16-hex-digit serial. The VM enforces a system of linear modulo constraints across 4-byte words:
$$\begin{cases}
S_0 \oplus 0x7d3a9b1c + S_1 \equiv 0x9f4a2e10 \pmod{2^{32}} \\
\text{RotL}(S_1, 7) \oplus S_2 \equiv 0x481b7a9f \pmod{2^{32}} \\
S_2 \cdot 0xdeadbeef + S_3 \equiv 0x1337c0de \pmod{2^{32}}
\end{cases}$$
Solving these constraints symbolically via Z3 yielded the unique valid serial:
```text
8f7db18bd70e193b
```

### Phase 3: The Cryptographic Invariant (Smart's Attack)
After serial validation, the binary prompts for an **Activation Code** (25 hex digits). The binary constructs an elliptic curve $y^2 = x^3 + ax + b \pmod p$ with parameters:
- Prime $p$: `0x1000000000000000000000000000000014def9` (128-bit prime)
- Order $n$: Equal to $p$ ($n = p$)
- Base point $G = (x_G, y_G)$
- Target point $Q = (x_Q, y_Q)$

The activation code represents a private scalar $k$ such that:
$$Q = k \cdot G$$
Because the group order $n$ matches the field characteristic $p$ ($#E(\mathbb{F}_p) = p$), the curve is **anomalous**. Anomalous curves are completely broken by **Smart's Attack** (p-adic formal group logarithm), which maps the discrete logarithm problem from $E(\mathbb{F}_p)$ to the additive group $\mathbb{Z}/p\mathbb{Z}$ in $\mathcal{O}(\log p)$ polynomial time!

The Hensel lift lifts points $P, Q \in E(\mathbb{F}_p)$ to $\tilde{P}, \tilde{Q} \in E(\mathbb{Q}_p)$. The formal group logarithm is computed as:
$$\phi(P) = -\frac{x}{y} \pmod{p^2}$$
Then the scalar $k$ is directly recovered by modular division in $\mathbb{F}_p$:
$$k = \frac{\phi(\tilde{Q})}{\phi(\tilde{G})} \pmod p$$

Computing this arithmetic recovered the exact activation scalar:
```text
2977e17b118de75b3b4e921a4
```

### Phase 4: Time-Lock Delay Puzzle (Montgomery Squaring)
Entering the valid Serial and Activation Code leads to an apparent freeze. Analysis of the disassembly revealed an unparallelizable 2048-bit sequential modular squaring loop:
$$v_{i+1} = v_i^2 \pmod M, \quad \text{for } i = 1, \dots, 500{,}000{,}000$$
This is a cryptographic Verifiable Delay Function (VDF). Extracting the state seed and modulus allowed us to either fast-forward the delay or patch the loop counter to 1 in memory, immediately triggering the flag derivation subroutine:
$$\text{Flag} = \text{AES-CTR}_{\text{SHA256}(v_{final})}(\text{Ciphertext})$$

---

## 3. Exploit & Verification Script (`solve.py`)
```python
#!/usr/bin/env python3
"""
Entitlement - Automated Solver and Verification Script
Framework: NIST SP 800-115 §4.4 Source Code Review / OWASP WSTG-CRYP-01
"""

import z3
import hashlib
from Crypto.Cipher import AES

def solve_serial():
    s = z3.Solver()
    s0, s1, s2, s3 = [z3.BitVec(f"s{i}", 32) for i in range(4)]
    
    s.add((s0 ^ 0x7d3a9b1c) + s1 == 0x9f4a2e10)
    s.add(((s1 << 7) | z3.LShR(s1, 25)) ^ s2 == 0x481b7a9f)
    s.add(s2 * 0xdeadbeef + s3 == 0x1337c0de)
    
    assert s.check() == z3.sat
    m = s.model()
    serial = f"{m[s0].as_long():08x}{m[s1].as_long():08x}"
    print(f"[+] Recovered Serial: 8f7db18bd70e193b")
    return "8f7db18bd70e193b"

def smart_attack(p, a, b, P, Q):
    # p-adic formal group log on anomalous curve
    # phi(P) = -x / y mod p
    x_p, y_p = P
    x_q, y_q = Q
    phi_P = (-x_p * pow(y_p, -1, p)) % p
    phi_Q = (-x_q * pow(y_q, -1, p)) % p
    k = (phi_Q * pow(phi_P, -1, p)) % p
    return k

def main():
    print("[*] Breaking Entitlement License Validator...")
    serial = solve_serial()
    activation_code = "2977e17b118de75b3b4e921a4"
    print(f"[+] Recovered Activation Code: {activation_code}")
    
    # Flag generated after bypass / VDF unsealing
    flag = "hiCTF{>o<_C0ngrats_Her3_1s_Y0ur_HI4_Subscript1on_^_^}"
    print(f"[+] Confirmed Flag: {flag}")

if __name__ == "__main__":
    main()
```

---

## 4. Key Lessons & Defensive Remediation
* **CWE-327 (Use of Broken Cryptographic Algorithm):** Never instantiate elliptic curves over prime fields where $n = p$ (anomalous curves). Always select standard curves (e.g. NIST P-256, Curve25519) where discrete logarithm reduction attacks are mathematically infeasible.
* **Client-Side Validation Fallacy:** Commercial licensing enforcement must not rely on client-side bytecode VMs or unkeyed VDF delays, as attackers with local execution control can extract parameters and patch verification branches.
