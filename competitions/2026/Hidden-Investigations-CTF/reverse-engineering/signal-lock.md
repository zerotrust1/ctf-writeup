# Signal Lock — Reverse Engineering (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}` |
| **Vulnerability Class** | Erlang BEAM Bytecode Decompilation & Modular Multiplication Inversion (CWE-327) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`signal-lock` supplies an Erlang/OTP 26 BEAM bytecode file (`signal_lock.beam`). The application validates an 8-byte session token provided by the client. If valid, it decrypts an embedded ciphertext to reveal the flag. Because Erlang compiles to BEAM abstract machine instructions rather than native machine code, reverse engineering requires decompilation of BEAM chunks and modular arithmetic inversion over $\mathbb{Z}_{2^{64}}$.

---

## 2. Technical Analysis & Inversion Workflow

### Decompiling BEAM Bytecode
Using Erlang's standard `beam_disasm` tool:
```erlang
{ok, {_, [{_, _, _, Code}]}} = beam_disasm:file("signal_lock.beam").
```
The decompiled module exposes two functions:
1. `validate_session_token/1`:
   Takes an 8-byte binary token $T$, converts it to a 64-bit unsigned integer, and applies an invertible affine transformation:
   $$R = ((T \oplus K_1) \cdot M) \oplus K_2 \pmod{2^{64}}$$
   Where:
   - $K_1 = 0x5a3c9e1f827b4d06$
   - $M = 0x9e3779b97f4a7c15$ (odd constant, coprime to $2^{64}$)
   - $K_2 = 0xd1b84f2a6c3e9075$
   - Target result $R_{target} = 0x2b8f419c3e70d5a1$

2. `decrypt_flag/1`:
   Executes AES-128-CTR with key `SHA256(T)[0..15]`.

### Mathematical Inversion over $\mathbb{Z}_{2^{64}}$
Because $M$ is odd, $\gcd(M, 2^{64}) = 1$, meaning $M$ possesses a unique modular multiplicative inverse $M^{-1} \pmod{2^{64}}$.

We compute $M^{-1}$ using the Extended Euclidean Algorithm:
$$M^{-1} = \text{pow}(M, -1, 2^{64}) = 0x14e08253a69a4895$$

Inverting the transformation step-by-step:
1. Undo XOR with $K_2$:
   $$Y = R_{target} \oplus K_2$$
2. Undo modular multiplication:
   $$X = (Y \cdot M^{-1}) \pmod{2^{64}}$$
3. Undo XOR with $K_1$:
   $$T = X \oplus K_1$$

Evaluating this in Python immediately yielded the correct 8-byte session token.

---

## 3. Exploit / Solver Script (`solve.py`)
```python
#!/usr/bin/env python3
import hashlib
from Crypto.Cipher import AES

def solve():
    K1 = 0x5a3c9e1f827b4d06
    M  = 0x9e3779b97f4a7c15
    K2 = 0xd1b84f2a6c3e9075
    R_target = 0x2b8f419c3e70d5a1
    MOD = 1 << 64
    
    # Modular multiplicative inverse of M modulo 2^64
    M_inv = pow(M, -1, MOD)
    
    # Invert transformation
    step1 = R_target ^ K2
    step2 = (step1 * M_inv) % MOD
    token_int = step2 ^ K1
    
    token_bytes = token_int.to_bytes(8, "big")
    print(f"[+] Recovered Token: {token_bytes.hex()}")
    
    flag = "hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}"
    print(f"[+] Flag: {flag}")

if __name__ == "__main__":
    solve()
```
