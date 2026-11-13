# Dormant Signer — Blockchain / Smart Contract (Hard)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Blockchain & Cryptography |
| **Difficulty** | Hard |
| **Flag** | `layout_undead_borrowed_betrays` |
| **Vulnerability Class** | ECDSA Nonce Reuse on secp256k1 & Self-Destruct State Recovery (CWE-327) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`dormant-signer` simulates a private EVM blockchain where a privileged administrative account deployed and subsequently destroyed (`selfdestruct`) an escrow vault contract. The goal is to recover the destroyed contract's storage state and reconstruct the secret passphrase.

---

## 2. Vulnerability Analysis & Exploit Workflow

### ECDSA Nonce ($k$) Reuse
Auditing the transaction history in `chain/` revealed that Transaction #137 and Transaction #234 shared the exact same ECDSA $r$ value:
$$r = 0x5729d3f406b7d431b32719fe0b1ab50f67530f3da01fe55deb1c6ed5638a8c01$$
Because $r$ represents the $x$-coordinate of the ephemeral point $R = k \cdot G$, identical $r$ values on distinct messages $(m_1, m_2)$ prove that the **ephemeral nonce $k$ was reused**.

Recovering the private key $d$:
$$k = \frac{z_1 - z_2}{s_1 - s_2} \pmod n, \quad d = \frac{s_1 \cdot k - z_1}{r} \pmod n$$
Where $z_1, z_2$ are the transaction message hashes and $n$ is the secp256k1 curve order.

### State Reconstruction
Using the recovered signer key to trace destroyed contract `0xcac5bbcb8a4b57fca03f71a8eeb64be756d6327c`:
$$\text{escrow} = \text{final\_seal} \oplus \text{escrow\_mask} \oplus \text{running\_digest}$$
Evaluating the XOR chain reconstructed the plaintext passphrase:
```text
layout_undead_borrowed_betrays
```
