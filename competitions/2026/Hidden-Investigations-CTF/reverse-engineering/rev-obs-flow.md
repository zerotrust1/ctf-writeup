# Obfuscated Flow — Reverse Engineering (Hard)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering |
| **Difficulty** | Hard |
| **Flag** | `hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}` |
| **Vulnerability Class** | Control Flow Flattening (CFF) & Multi-Domain Cryptographic Constraints (CWE-327) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`rev-obs-flow` employs heavy **Control Flow Flattening (CFF)** (OLLVM-style state machine) to obscure the validation of a 47-character passkey. The binary disperses basic blocks into a giant switch-case loop controlled by a dynamic state variable updated via SipHash.

---

## 2. Reversing Flattened Control Flow
By tracing state variable transitions with an IDAPython / angr symbolic emulation script, we eliminated the dispatcher trampoline and reconstructed the underlying mathematical constraints across three separate subsystems:
1. **Subsystem 1 (Chunks $W_0, W_1$ - Mersenne Prime Modulo):**
   Operates over $\mathbb{F}_{P_1}$ where $P_1 = 2^{31} - 1 = 2147483647$:
   $$W_0^2 - 31337 \cdot W_1^2 \equiv 0x1e054920 \pmod{P_1}, \quad W_0 \cdot W_1 \equiv 0x37c0f52c \pmod{P_1}$$
2. **Subsystem 2 (Chunks $W_2, W_3$ - Discrete Logarithm):**
   Requires solving a discrete logarithm problem in a smooth cyclic subgroup, solved via Pohlig-Hellman.
3. **Subsystem 3 (Chunk $W_4$ - Affine Check):**
   A linear Diophantine check over $\mathbb{Z}_{2^{64}}$.

Combining the solved components unlocked the binary and revealed the flag:
```text
hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}
```
