# Last Execution — Reverse Engineering (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}` |
| **Vulnerability Class** | Custom Virtual Machine State Decryption & Loop Fast-Forward (CWE-327) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`last-execution` provides a disk image `last_execution.img` containing an executable VM core based on a custom architecture designated **EXE-9**. The virtual machine executes $10^{12}$ cycles of a rotating opcode ring to update its internal register file before dumping a seal buffer.

---

## 2. Technical Analysis & Loop Fast-Forwarding
Static analysis of the EXE-9 opcode interpreter revealed that the instruction stream forms a deterministic finite state machine with a cycle period $T = 65{,}536$.
Because the state transitions are linear over $\mathbb{Z}_{2^{32}}$:
$$\vec{S}_{k+1} = \mathbf{A} \vec{S}_k + \vec{B} \pmod{2^{32}}$$
We computed the matrix power $\mathbf{A}^{10^{12}} \pmod{2^{32}}$ in $\mathcal{O}(\log N)$ steps using binary exponentiation. This bypassed the trillion-cycle wait time and decrypted the flag buffer:
```text
hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}
```
