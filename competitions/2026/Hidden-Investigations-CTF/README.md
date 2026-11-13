# Hidden Investigations CTF 2026 (hiCON / hiCTF) — Master Writeup Collection

> **Official Comprehensive Writeup Archive & Technical Deconstructions**  
> **Event Date:** Late October – Early November 2026  
> **Host / Organizer:** Hidden Investigations (`hiddeninvestigations.net`)  
> **Methodology & Frameworks:** NIST SP 800-115 (§4.4 / §6.3), OWASP WSTG v4.2/v5, CWE Top 25

---

## 🏆 Event Overview & Performance Summary

**Hidden Investigations CTF 2026** was an international advanced cybersecurity competition focusing on deep reverse engineering, low-level binary exploitation, kernel and physical memory forensics, esoteric steganography, and advanced cryptography.

* **Total Challenges Solved:** 26 Challenges
* **Categories Covered:** Reverse Engineering, Forensics & Steganography, Binary Exploitation (Pwn), Cryptography, Smart Contracts / Blockchain, Misc (Sandbox Escapes), and OSINT / IMINT.
* **Key Technical Feats:**
  * Broke an anomalous elliptic curve licensing validator via **Smart's p-adic formal group logarithm attack** in O(log p) time (`Entitlement`).
  * Engineered a hardware-accelerated **AVX-512 / BMI2 Montgomery squaring engine in C** using OpenSSL to compute **9 Billion VDF modular squarings** (`ChronoGrind`).
  * Decompiled **Erlang OTP 26 BEAM bytecode** and calculated modular multiplicative inverses over integers modulo 2^64 (`Signal Lock`).
  * Reconstructed an unlinked Windows kernel rootkit process by bypassing **DKOM list unlinking** using pool tag allocation scanning (`Memory Liar`).
  * Reassembled a **5-tier shattered transmission** across raw NTFS geometry, USN transaction logs, and PE timestamp overlays (`Resurrection`).

---

## 📊 Complete Challenge Scoreboard & Matrix

| Category | Challenge Name | Difficulty | Vulnerability Archetype | Solved Flag |
| :--- | :--- | :---: | :--- | :--- |
| **Rev** | [Entitlement](./reverse-engineering/entitlement.md) | **Hard** | Anomalous Elliptic Curve Smart's Attack & VDF Time-Lock | `hiCTF{>o<_C0ngrats_Her3_1s_Y0ur_HI4_Subscript1on_^_^}` |
| **Rev** | [ChronoGrind](./reverse-engineering/chronogrind.md) | **Hard** | 9 Billion Modular Squaring VDF & ChaCha20-Poly1305 | <code>hiCTF{n1c3_w0rk_n0w_t4k3_s0m3_r3&#36;t}</code> |
| **Rev** | [Cold Beacon](./reverse-engineering/cold-beacon.md) | **Hard** | Z3 Symbolic Modeling & SHA-256 Keystream Decryption | `hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}` |
| **Rev** | [Obfuscated Flow](./reverse-engineering/rev-obs-flow.md) | **Hard** | Control Flow Flattening (CFF) & Pohlig-Hellman DLog | `hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}` |
| **Rev** | [Inner Engine](./reverse-engineering/inner-engine.md) | **Medium** | Nim Custom Stack VM Bytecode & Z3 Constraint Satisfaction | `hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}` |
| **Rev** | [Signal Lock](./reverse-engineering/signal-lock.md) | **Medium** | Erlang OTP 26 BEAM Decompilation & Modular Inverse over 2^64 | `hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}` |
| **Rev** | [Warden's Maze](./reverse-engineering/maze-breach.md) | **Medium** | Raycasting 8-bit Integer Truncation & Map Memory Corruption | `hiCTF{r4yc4st1ng_trunc4t10n_br34ch3d_th3_v4ult}` |
| **Rev** | [Epsilon Drift](./reverse-engineering/epsilon-drift.md) | **Medium** | IEEE-754 Precision Drift & Signed Zero Invariant | `hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}` |
| **Rev** | [Night Batch](./reverse-engineering/night-batch.md) | **Medium** | GnuCOBOL Packed Decimal (COMP-3) Constraint System | `hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}` |
| **Rev** | [Last Execution](./reverse-engineering/last-execution.md) | **Medium** | EXE-9 Virtual Processor Core Decryption & Loop Fast-Forward | `hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}` |
| **Forensics** | [Echoes of a Forgotten Canvas](./forensics-and-steganography/echoes-of-a-forgotten-canvas.md) | **Medium** | 4-Layer Nested Stego (PNG IHDR, ZipCrypto, Steghide, JPEG SOF0) | `hiCTF{mu1t!14y3r3d_st3g0o_ju5t_l0v333}` |
| **Forensics** | [Resurrection](./forensics-and-steganography/resurrection.md) | **Hard** | NTFS Volume Geometry Runlists & EVTX Binary XML Reassembly | `hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_...}` |
| **Forensics** | [Memory Liar](./forensics-and-steganography/memory-liar.md) | **Hard** | DKOM Unlinked Process EPROCESS Discrepancy & Pool Tag Scan | `hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}` |
| **Forensics** | [Forgotten Secrets](./forensics-and-steganography/forgotten-secrets.md) | **Medium** | Memory Dump Obfuscation via Sentinels & Single-Byte XOR | `hiCTF{m3m0ry_dump_d1g_d33p}` |
| **Forensics** | [Ghost in the Wire](./forensics-and-steganography/ghost-in-the-wire.md) | **Medium** | ICMP Echo Payload Protocol Covert Tunneling | `hiCTF{1cmp_3xf1l_d3t3ct3d}` |
| **Forensics** | [Broken Signals](./forensics-and-steganography/broken-signals.md) | **Medium** | PNG Magic Header Corruption & Image Bitplane Slicing | `hiCTF{h34d3r_r3p41r_m4st3r}` |
| **Forensics** | [Paper Trail](./forensics-and-steganography/paper-trail.md) | **Medium** | PDF Deflate Stream Object Carving & Hidden Vector Layers | `hiCTF{pdf_str34m_0bj3ct_d3fl4t3_unc0v3r3d}` |
| **Forensics** | [Abandoned Tracker](./forensics-and-steganography/abandoned-tracker.md) | **Medium** | WiFi Sensor Spatio-Temporal Trajectory Scoring | `hiCTF{FoxgloveCoffee_Guest}` |
| **Forensics** | [Roof of Africa](./forensics-and-steganography/roof-of-africa.md) | **Medium** | Steghide DCT Embedding with Elevation Passphrase (`5895`) | `hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}` |
| **Forensics** | [Zanzibar Whisper](./forensics-and-steganography/zanzibar-whisper.md) | **Easy** | Steghide DCT Embedding with Null Passphrase | `hiCTF{sp1c3_1sl4nd_s3cr3ts}` |
| **Forensics** | [Whispers in the Margin](./forensics-and-steganography/whispers-in-the-margin.md) | **Medium** | Zero-Width Margin Steganography & Word XML Carving | `hiCTF{573g4n0gr4phy_!5_fun}` |
| **Crypto** | [Cipher Cascade](./cryptography/cipher-cascade.md) | **Medium** | Multi-Layer Unwinding (Reverse, Base64, ROT13, Hex, Vigenère) | `hiCTF{l4y3r_by_l4y3r_unw1nd}` |
| **Pwn** | [Apex Engine](./pwn/apex-engine.md) | **Hard** | Concurrency Race Condition Double-Spend & TOCTOU File Streaming | `hiCTF{r4c3_c0nd1t10n_d0ubl3_sp3nd_v4ult_unl0ck3d}` |
| **Misc** | [Dormant Signer](./misc/dormant-signer.md) | **Hard** | secp256k1 ECDSA Nonce Reuse & EVM Self-Destruct State Recovery | `layout_undead_borrowed_betrays` |
| **Misc** | [LetMeOut](./misc/letmeout.md) | **Medium** | Jinja2 Sandbox Escape under 3-Letter Constraint & NFKC Normalization | `hiCTF{j1nj42_s4ndb0x_3sc4p3_nfkc_n0rm4l1z3}` |
| **OSINT** | [Shadow Identity](./osint/shadow-identity.md) | **Easy** | Swahili Coast Architectural IMINT & Facial OSINT | `jihan mohin dimack` |

---

## 🛠️ Verification & Engineering Standards

Every writeup in this repository adheres to strict defensive security analysis standards:
1. **Root Cause Analysis:** Explicit identification of the violated invariant (e.g. integer truncation, anomalous curve group structure, lack of transaction mutex locks).
2. **Reproducible Code:** Self-contained verification and exploit scripts (`solve.py`) ready for standalone execution.
3. **Defensive Guidance:** Clear architectural remediations mapped to OWASP and CWE classifications.
