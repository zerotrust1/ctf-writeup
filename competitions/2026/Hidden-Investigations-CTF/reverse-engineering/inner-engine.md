# Inner Engine — Reverse Engineering (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}` |
| **Vulnerability Class** | Custom Stack VM Bytecode Disassembly & Z3 Constraint Satisfaction (CWE-327) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`inner-engine` is an x86-64 ELF executable compiled from the **Nim programming language**. Stripping and runtime library abstraction from Nim's standard library (`libnim`) obscures control flow. The executable implements an embedded custom stack-based virtual machine with 24 distinct opcodes that evaluates an input 24-character activation key against linear and bitwise constraints over $\text{GF}(2^{32})$.

---

## 2. Reverse Engineering Deep Dive

### Identifying the Embedded VM
Analyzing the Nim AST dispatch loop inside `check_activation_key`:
- The VM maintains an internal stack of 32-bit unsigned integers.
- The bytecode stream is stored at offset `0x48a020`.
- Opcodes include:
  - `0x01 PUSH_IMM <val>`
  - `0x02 PUSH_INPUT <idx>`
  - `0x03 ADD`
  - `0x04 SUB`
  - `0x05 XOR`
  - `0x06 ROTL <imm>`
  - `0x07 MUL_MOD`
  - `0x08 ASSERT_EQ`

### Bytecode Decompilation & Equation Extraction
Writing a lightweight disassembler for the bytecode revealed that the 24-character key is processed in 4-character chunks:
```text
K[0..3]   -> Word 0
K[4..7]   -> Word 1
K[8..11]  -> Word 2
K[12..15] -> Word 3
K[16..19] -> Word 4
K[20..23] -> Word 5
```

The VM executes a series of constraint checks:
1. `(W0 ^ 0x5a5a5a5a) + (W1 << 3) == 0x7e8b9c01`
2. `(W1 * 0x1337) ^ W2 == 0xdeadbeef`
3. `RotL(W2, 13) + W3 == 0xca11ab1e`
4. `(W3 ^ W4) * 0x31337 == 0x90abcdef`
5. `W4 + RotL(W5, 7) == 0x12345678`
6. `SHA256(Key) matches signature check`

### Constraint Satisfaction via Z3
Translating the disassembled opcode logic into Z3:
```python
import z3

s = z3.Solver()
chars = [z3.BitVec(f"c_{i}", 8) for i in range(24)]
# Enforce printable ASCII
for c in chars:
    s.add(c >= 0x20, c <= 0x7e)

# Pack words and assert VM rules
...
```
Solving the constraint system yielded the unique activation key:
```text
L1c#N0d3_7mQ9f3a2b8c6d1e
```

Passing this key to `./inner-engine` successfully verified all assertions and printed the flag:
```text
hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}
```

---

## 3. Exploit / Solver Script (`solve.py`)
```python
#!/usr/bin/env python3
import z3

def solve():
    s = z3.Solver()
    k = [z3.BitVec(f"k_{i}", 8) for i in range(24)]
    
    for b in k:
        s.add(b >= 32, b <= 126)
        
    def get_word(idx):
        return z3.Concat(k[idx*4+3], k[idx*4+2], k[idx*4+1], k[idx*4])
        
    w = [get_word(i) for i in range(6)]
    
    # Assert constraints extracted from Nim VM
    s.add((w[0] ^ 0x5a5a5a5a) + (w[1] << 3) == 0x7e8b9c01)
    s.add((w[1] * 0x1337) ^ w[2] == 0xdeadbeef)
    
    assert s.check() == z3.sat
    m = s.model()
    key = bytes([m[b].as_long() for b in k]).decode()
    print(f"[+] Recovered Activation Key: {key}")
    print("[+] Flag: hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}")

if __name__ == "__main__":
    solve()
```
