# Memory Liar — Forensics & Windows Kernel Memory (Hard)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Forensics & Memory Analysis |
| **Difficulty** | Hard |
| **Flag** | `hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}` |
| **Vulnerability Class** | DKOM (Direct Kernel Object Manipulation) Unlinked Process EPROCESS Discrepancy (CWE-284) |
| **Framework Mapping** | NIST SP 800-115 §4.3 / OWASP WSTG-INFO-01 |

---

## 1. Executive Summary & Challenge Overview
`memory-liar` provides a physical memory dump (`memory.raw`). A kernel-mode rootkit concealed a malicious process by unlinking its `EPROCESS` block from the Windows `ActiveProcessLinks` doubly-linked list. Standard memory analysis tools (like Volatility's `windows.pslist`) fail to display the hidden process.

---

## 2. Forensic Analysis & Discrepancy Auditing
1. **Decoy Flag Trap:** An initial string search reveals a decoy flag in incident response triage logs at `0x355000`:
   `hiCTF{th1s_1s_4_f4k3_d3c0y_fl4g_f0r_n00bs_883a1c}` (Fake Flag!).
2. **Pool Tag Scanning (`windows.psscan`):**
   Scanning for `Proc` pool tag allocations bypassed the unlinked list and located an orphaned `EPROCESS` block named `ROOT9` at physical offset `0x35f000`.
3. **Decryption of Process Memory:**
   Inspecting `ROOT9`'s VAD tree extracted an encrypted memory segment. Applying a rolling XOR key derived from the process PID revealed the genuine flag:
   ```text
   hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}
   ```
