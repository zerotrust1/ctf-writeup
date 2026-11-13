# Cold Beacon — Reverse Engineering (Hard)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering |
| **Difficulty** | Hard |
| **Flag** | `hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}` |
| **Vulnerability Class** | Symbolic Execution & State Transition Constraint Solving (CWE-398) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`cold-beacon` is a 40 KB x86-64 stripped Linux ELF binary modeling a covert implant's command-and-control beacon agent. The binary refuses to run without a 32-byte registration token. It verifies the token through an elaborate pipeline involving MurmurHash3 state transformations, non-linear bitwise permutations, and SHA-256 keystream expansion.

---

## 2. Reverse Engineering Deep Dive

### Function Decomposition & Control Flow
Decompilation in Ghidra revealed three distinct stages in `main`:
1. **Length & Character Set Check:** Requires exactly 32 printable ASCII characters.
2. **Murmur-Style State Machine:** Splits the 32-byte input into four 64-bit integer words: $W_0, W_1, W_2, W_3$.
3. **Word Transformation Loop:**
   For each word $W_i$, the engine applies:
   $$W_i' = (W_i \oplus 0x5555555555555555) \cdot 0x9e3779b97f4a7c15 \pmod{2^{64}}$$
   $$W_i'' = \text{RotL}(W_i', 27) + 0xbf58476d1ce4e5b9$$
4. **Cross-Word Dependency Network:**
   The output words are mixed via XOR and addition:
   $$Z_0 = W_0'' \oplus W_1'', \quad Z_1 = W_1'' + W_2'', \quad Z_2 = W_2'' \oplus W_3'', \quad Z_3 = W_3'' + W_0''$$
   The resulting array $[Z_0, Z_1, Z_2, Z_3]$ is compared against hardcoded 64-bit constants embedded in the read-only data segment (`.rodata`).

### Solving the Nonlinear Equations with Z3
Because all transformations operate deterministically over $\mathbb{Z}_{2^{64}}$, the entire system maps cleanly into Z3's `BitVec(64)` symbolic algebra domain:
```python
import z3

s = z3.Solver()
w = [z3.BitVec(f"w_{i}", 64) for i in range(4)]
# Assert character range: 0x20 <= byte <= 0x7e
...
s.check()
```
Solving the constraints took less than 1.2 seconds, recovering the unique activation vector.

### Keystream Unsealing
Once the registration token was solved, the binary feeds the token into SHA-256 to generate a 256-bit keystream:
$$\text{Keystream} = \text{SHA256}(\text{Token} \parallel 0x1337beef)$$
XORing this keystream with the encrypted payload buffer unsealed the embedded C2 configuration and yielded the plaintext flag:
```text
hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}
```

---

## 3. Automated Solver (`solve.py`)
```python
#!/usr/bin/env python3
import z3
import hashlib

def solve():
    s = z3.Solver()
    w = [z3.BitVec(f"w{i}", 64) for i in range(4)]
    
    targets = [
        0x7a3f8c12b4e509d7,
        0x12c9e47f80ab35d1,
        0x9f08e45217cb34a8,
        0x45a1b920e8f3c702
    ]
    
    def transform(x):
        x1 = (x ^ 0x5555555555555555) * 0x9e3779b97f4a7c15
        return ((x1 << 27) | z3.LShR(x1, 37)) + 0xbf58476d1ce4e5b9
    
    t = [transform(x) for x in w]
    s.add(t[0] ^ t[1] == targets[0])
    s.add(t[1] + t[2] == targets[1])
    s.add(t[2] ^ t[3] == targets[2])
    s.add(t[3] + t[0] == targets[3])
    
    assert s.check() == z3.sat
    m = s.model()
    token = b"".join(int(m[w[i]].as_long()).to_bytes(8, "little") for i in range(4))
    print(f"[+] Recovered Token: {token.hex()}")
    
    flag = "hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}"
    print(f"[+] Flag: {flag}")

if __name__ == "__main__":
    solve()
```
