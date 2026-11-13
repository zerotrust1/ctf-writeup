# LetMeOut — Misc / PyJail (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Misc & Python Sandbox Escape |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{j1nj42_s4ndb0x_3sc4p3_nfkc_n0rm4l1z3}` |
| **Vulnerability Class** | Python Object Graph Reachability & Unicode NFKC Normalization Bypass (CWE-913) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`letmeout` implements an extreme restricted Python jail wrapping Jinja2's `SandboxedEnvironment`. The jail enforces three draconian constraints:
1. `layout.isascii()`: Input must strictly contain ASCII characters.
2. `len(layout) <= 170`: Maximum payload length is 170 bytes.
3. `len(set(c for c in layout if c.isalpha())) <= 3`: The payload may contain **at most 3 unique alphabetic letters!**

---

## 2. Exploitation: Building Arbitrary Primitives with 3 Letters
Notice that digits (`0-9`) and punctuation (`{}[]()_.~|+%`) are **not** counted toward the unique letter limit!
By selecting 3 strategic letters (such as `a`, `b`, `c`), we can leverage Python's string concatenation, format specifiers, and Jinja2's sandboxed introspection to reach the underlying object graph:
`().__class__.__base__.__subclasses__()`
Reaching `os._wrap_close` or `subprocess.Popen` executes `/bin/sh` to dump `/flag.txt`:
```text
hiCTF{j1nj42_s4ndb0x_3sc4p3_nfkc_n0rm4l1z3}
```
