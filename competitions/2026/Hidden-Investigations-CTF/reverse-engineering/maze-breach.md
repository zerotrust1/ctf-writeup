# Warden's Maze (Maze Breach) — Reverse Engineering (Medium)

| Attribute | Details |
| :--- | :--- |
| **Event** | Hidden Investigations CTF 2026 (hiCON / hiCTF) |
| **Category** | Reverse Engineering & Binary Exploitation |
| **Difficulty** | Medium |
| **Flag** | `hiCTF{r4yc4st1ng_trunc4t10n_br34ch3d_th3_v4ult}` |
| **Vulnerability Class** | Signed Integer Truncation & Map Memory Corruption (CWE-197 / CWE-787) |
| **Framework Mapping** | NIST SP 800-115 §4.4 Source Code Review |

---

## 1. Executive Summary & Challenge Overview
`maze-breach` is a console-based maze exploration game compiled from **Rust**. The player must navigate a character through a $24 \times 24$ dungeon grid to reach a high-security inner vault containing the flag. The inner vault is entirely surrounded by solid barrier tiles (`0x80` solid walls) with zero valid passages. Winning legitimately through conventional navigation is mathematically impossible.

---

## 2. Reverse Engineering Deep Dive

### The Vulnerability: 8-bit Signed Integer Truncation in Raycasting
Decompiling the visibility engine (`sub_9680`) revealed a raycasting algorithm that illuminates walkable tiles in front of the player's line of sight.

The linear 2D map index calculation:
```rust
let linear_offset: i32 = dy * map_width + dx;
let truncated_offset: i8 = linear_offset as i8; // 8-bit signed cast!
let dest_index = player_index + (truncated_offset as i32);
```

When calculating visibility for a tile located at $dy = 6, dx = 0$ in a grid of width $24$:
$$\text{linear\_offset} = 6 \cdot 24 + 0 = 144$$
When cast to `i8`:
$$144 \equiv -112 \pmod{256}$$
Instead of indexing **forward** by $+144$ tiles, the calculation indexes **backward** by $-112$ tiles!

### Triggering Out-of-Bounds Memory Corruption
When the player stands at coordinate $(4, 14)$:
- `player_index` $= 14 \cdot 24 + 4 = 340$.
- Offset calculation: $340 - 112 = 228$.
- Grid index $228$ corresponds directly to coordinates $(x=12, y=9)$—the **north perimeter wall of the sealed vault!**

The visibility engine sets the tile state to walkable floor:
$$\text{grid}[228] = \text{grid}[228] \mid 0x40$$
This overwrites the impassable vault wall tile into an open, walkable doorway!

---

## 3. Exploit & Solution Navigation
The solution requires two navigation phases:
1. **Move to the Glitch Point $(4, 14)$:**
   Execute 25 moves: `saaaasssaassdsssdssssaaaa`. This triggers the raycasting loop, corrupting tile $(12, 9)$.
2. **Move through the Corrupted Wall into the Vault $(11, 11)$:**
   Execute 20 moves: `dwdddwwwawwdddddsssa` to enter through the breached wall and capture the prize.

```python
#!/usr/bin/env python3
import socket
import ssl
import re

PATH_TO_BREACH = "saaaasssaassdsssdssssaaaa"
PATH_INTO_VAULT = "dwdddwwwawwdddddsssa"
FULL_PATH = PATH_TO_BREACH + PATH_INTO_VAULT

def solve(host="maze-breach-3077060b609c.chall.hiddeninvestigations.net", port=1337):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock) as s:
            s.sendall(FULL_PATH.encode() + b"\n")
            resp = s.recv(4096).decode()
            print(resp)
            # Flag captured: hiCTF{r4yc4st1ng_trunc4t10n_br34ch3d_th3_v4ult}

if __name__ == "__main__":
    solve()
```
