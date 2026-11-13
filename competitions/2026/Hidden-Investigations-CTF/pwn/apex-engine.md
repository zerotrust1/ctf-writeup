# Apex Engine — Binary Exploitation (Hard)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Binary Exploitation & Concurrency |
| **Difficulty** | Hard |
| **Flag** | `hiCTF{r4c3_c0nd1t10n_d0ubl3_sp3nd_v4ult_unl0ck3d}` |
| **Vulnerability Class** | Concurrency Race Condition Double-Spend & TOCTOU File Stream Race (CWE-362 / CWE-367) |
| **Framework Mapping** | NIST SP 800-115 §4.4 / OWASP WSTG-INPV-01 |

---

## 1. Executive Summary & Challenge Overview
`apex-engine` is a high-performance multithreaded financial ledger and document repository daemon written in C. The service contains two concurrent race condition primitives:
1. **Account Escrow Double-Spend Race:** Lack of synchronization locks around asynchronous account balance checks allows concurrent transfer threads to trigger balance underflow, enabling purchase of VIP access.
2. **Time-of-Check to Time-of-Use (TOCTOU) File Stream Race:** While an asynchronous worker thread prepares to stream a user document, an attacker can rewrite the internal file pointer to `/flag`.

---

## 2. Exploitation Architecture
1. **Balance Underflow:** Connect with 20 parallel threads sending transfer requests simultaneously. Due to the 10ms settlement sleep, multiple threads pass the `balance >= amount` check before debiting occurs. This underflows the account balance to a massive unsigned integer, permitting immediate purchase of VIP tier.
2. **TOCTOU Handle Swapping:** Request streaming of a benign file, then instantly issue an edit command modifying the file handle to `/flag` before the streaming worker reads the descriptor.
```python
#!/usr/bin/env python3
import socket
import threading

def race_thread(host, port):
    s = socket.create_connection((host, port))
    s.sendall(b"TRANSFER 100\n")
    s.close()

# Flag captured: hiCTF{r4c3_c0nd1t10n_d0ubl3_sp3nd_v4ult_unl0ck3d}
```
