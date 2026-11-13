# 🛡️ CTF Writeup & Cybersecurity Research Archive

[![Author](https://img.shields.io/badge/Author-zerotrust1%20%2F%20rel7z-blue.svg)](https://github.com/zerotrust1)
[![Platform](https://img.shields.io/badge/Focus-CTF%20%7C%20Offensive%20%26%20Defensive-red.svg)](https://github.com/zerotrust1/ctf-writeup)
[![Standards](https://img.shields.io/badge/Standards-NIST%20SP%20800--115%20%7C%20OWASP%20WSTG-green.svg)](https://github.com/zerotrust1/ctf-writeup)

Welcome to my central technical archive documenting Capture The Flag (CTF) challenges, vulnerability research, exploit development, and forensic investigations. This repository serves as a transparent portfolio of solved challenges ranging from foundational exercises to complex international CTF competitions.

---

## 📂 Repository Organization

```text
ctf-writeup/
├── competitions/
│   └── 2026/
│       └── Hidden-Investigations-CTF/    # Full 26-Challenge Master Writeup Collection
│           ├── README.md                 # Complete Event Overview & Matrix
│           ├── reverse-engineering/      # Entitlement, ChronoGrind, Cold Beacon, etc.
│           ├── forensics-and-steganography/ # Echoes, Resurrection, Memory Liar, etc.
│           ├── cryptography/             # Cipher Cascade
│           ├── pwn/                      # Apex Engine
│           ├── misc/                     # Dormant Signer, LetMeOut
│           └── osint/                    # Shadow Identity
└── exercises/
    └── picoCTF/                          # Foundational exercises & warm-up challenges
        └── cookies/                      # Web Cookie Manipulation
```

---

## 🌟 Featured Major Competitions

### [Hidden Investigations CTF 2026 (hiCON / hiCTF)](./competitions/2026/Hidden-Investigations-CTF/README.md)
* **Status:** 26/26 Challenges Documented & Solved
* **Highlights:**
  * **Advanced Reversing:** Smart's p-adic attack on anomalous elliptic curves (`Entitlement`), OpenSSL AVX-512 Montgomery squaring for 9 Billion VDF cycles (`ChronoGrind`), Nim stack VM disassembly (`Inner Engine`), Erlang BEAM modular inverse (`Signal Lock`).
  * **Deep Forensics:** Kernel DKOM unlinked process detection (`Memory Liar`), 5-layer shattered NTFS geometry reconstruction (`Resurrection`), 4-layer nested steganography (`Echoes of a Forgotten Canvas`).
  * **Pwn & Concurrency:** Multi-threaded balance double-spend and TOCTOU file handle race (`Apex Engine`).
  * **Blockchain Security:** secp256k1 ECDSA nonce reuse private key recovery (`Dormant Signer`).

👉 **[Read the Full Hidden Investigations CTF 2026 Writeup Series](./competitions/2026/Hidden-Investigations-CTF/README.md)**

---

## 🔬 Core Methodologies & Tooling
* **Reverse Engineering:** IDA Pro, Ghidra, GDB-GEF, Z3 Theorem Prover, Angr, `beam_disasm`.
* **Binary Exploitation:** Pwntools, ROPgadget, OneGadget, Glibc heap arena inspection.
* **Forensics & Stego:** Volatility 3, Scapy, Steghide, Zsteg, Binwalk, QPDF, Exiftool.
* **Standards Adherence:** NIST SP 800-115, OWASP Web Security Testing Guide (WSTG v4.2/v5), CWE Top 25.

---

*Authored with precision by [zerotrust1](https://github.com/zerotrust1).*
