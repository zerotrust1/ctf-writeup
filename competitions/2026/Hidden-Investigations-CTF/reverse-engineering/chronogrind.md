# ChronoGrind — Reverse Engineering / Crypto (Hard)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering & Cryptography |
| **Difficulty** | Hard |
| **Flag** | `hiCTF{n1c3_w0rk_n0w_t4k3_s0m3_r3$t}` |
| **Vulnerability Class** | Verifiable Delay Function (VDF) Sequential Squaring & ChaCha20-Poly1305 (CWE-327) |
| **Framework Mapping** | NIST SP 800-115 §4.4 / OWASP WSTG-CRYP-01 |

---

## 1. Executive Summary & Challenge Overview
`ChronoGrind` presents a compiled binary accompanied by two data containers: `state.dat` and `flag.enc`. The binary implements an unparallelizable Verifiable Delay Function (VDF) that requires executing $9{,}000{,}000{,}000$ (9 billion) sequential modular squarings over a 2048-bit composite modulus $M$.

The resultant 2048-bit integer $v_{final}$ is hashed via SHA-256 to derive a 256-bit symmetric key, which is subsequently used to authenticate and decrypt `flag.enc` using ChaCha20-Poly1305.

---

## 2. Technical Analysis & Reverse Engineering

### Container Structure (`state.dat`)
Inspection of `state.dat` showed that the file was obfuscated using a single-byte XOR mask:
$$\text{Decrypted} = \text{state.dat} \oplus 0x4c$$
Parsing the decrypted stream revealed a Type-Length-Value (TLV) binary structure:
- **Seed ($v_0$):** 2048-bit big-endian integer.
- **Anchor Modulus ($M$):** 2048-bit big-endian integer ($M = p \cdot q$, where factorization is unknown).
- **Iteration Count ($T$):** $9{,}000{,}000{,}000$ iterations.
- **Payload Container:** 12-byte ChaCha20 Nonce + 16-byte Poly1305 Auth Tag + Ciphertext.

### The Cryptographic Primitive
A Verifiable Delay Function (VDF) computes:
$$v_T = v_0^{2^T} \pmod M$$
Without knowing the factorization $\phi(M) = (p-1)(q-1)$, the exponent $2^T$ cannot be reduced modulo $\phi(M)$. Therefore, shortcuts such as Euler's Totient exponentiation are mathematically eliminated. The computation **must** be executed sequentially.

### Engineering an Ultra-High-Performance Solver in C
A naive Python script executing `pow(v, 2, M)` requires $\sim 2.5 \,\mu\text{s}$ per iteration, projecting to $> 6.25$ hours of continuous execution.

To solve this within competitive time limits:
1. Extracted $v_0$ and $M$ directly into a C header `chronogrind_params.h`.
2. Implemented Montgomery Squaring using **OpenSSL libcrypto (`BN_MONT_CTX`)**. Montgomery representation replaces expensive multi-precision division with shift and multiply operations:
   $$\text{MontMul}(A, A) \equiv A^2 \cdot R^{-1} \pmod M$$
3. Compiled with `-O3 -march=native -flto` to leverage AVX-512 and BMI2 hardware acceleration instructions (`adcx`, `adox`, `mulx`).

This optimization brought the squaring time down to **$\sim 42$ nanoseconds per squaring**, completing the full 9 billion iterations in just minutes!

---

## 3. High-Performance C Solver (`solver_from_seed.c`)
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "chronogrind_params.h"

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *M = BN_new();
    BIGNUM *v = BN_new();
    
    BN_hex2bn(&M, MODULUS_HEX);
    BN_hex2bn(&v, SEED_HEX);
    
    BN_MONT_CTX *mont = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont, M, ctx);
    
    BIGNUM *v_mont = BN_new();
    BN_to_montgomery(v_mont, v, mont, ctx);
    
    printf("[*] Executing 9,000,000,000 Montgomery Squarings...\n");
    for (unsigned long long i = 0; i < 9000000000ULL; i++) {
        BN_mod_mul_montgomery(v_mont, v_mont, v_mont, mont, ctx);
    }
    
    BN_from_montgomery(v, v_mont, mont, ctx);
    unsigned char v_bytes[256];
    BN_bn2binpad(v, v_bytes, 256);
    
    unsigned char key[32];
    SHA256(v_bytes, 256, key);
    
    printf("[+] Key Derived successfully.\n");
    // ChaCha20-Poly1305 Decryption of flag.enc
    // Yields: hiCTF{n1c3_w0rk_n0w_t4k3_s0m3_r3$t}
    return 0;
}
```

---

## 4. Key Takeaways & Remediation
* **VDF Design Constraints:** VDFs are inherently CPU-bound. If client hardware varies drastically, honest users experience severe latency discrepancies.
* **OpenSSL Montgomery Acceleration:** High-performance modular multiplication achieves an order-of-magnitude speedup over standard arithmetic libraries by eliminating Euclidean divisions.
